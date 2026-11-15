"""Account disable/re-enable policy over the unchanged development reference issuer.

Only the HTTP issuer observes this policy. Already issued detached certificates
remain verifiable until expiry; this is not instant offline peer revocation.
"""
import json,os,re,secrets,sqlite3,stat,sys,threading,time,uuid
from contextlib import closing
from argon2 import PasswordHasher,extract_parameters
from argon2.low_level import Type
from argon2.exceptions import InvalidHashError,VerifyMismatchError,VerificationError
from pathlib import Path
from urllib.parse import quote,urlsplit
from .service import Service as ReferenceService,Failure,PATHS
from .mount import validate_base_path
from .app_asset_cache import RegisteredAppAssetCache
from . import jose
SCHEMA='CREATE TABLE IF NOT EXISTS account_policy (subject TEXT PRIMARY KEY, disabled INTEGER NOT NULL CHECK(disabled IN (0,1)), generation INTEGER NOT NULL CHECK(generation>=0))'
ACCOUNT_DB_TIMEOUT_SECONDS=2
# Reserve half of the eight HTTP workers for other requests during login bursts.
PASSWORD_ADMISSIONS=4
PASSWORD_WAIT_SECONDS=3
# Reverse-proxied issuer requests can share a loopback peer, including a whole classroom.
ISSUER_PEER_REQUESTS_PER_MINUTE=1200
def connection(path):return sqlite3.connect('file:'+quote(str(Path(path).absolute()),safe='/')+'?mode=rw',uri=True,timeout=ACCOUNT_DB_TIMEOUT_SECONDS)
def policy(db,subject):
 row=db.execute('SELECT disabled,generation FROM account_policy WHERE subject=?',(subject,)).fetchone()
 if row is None:raise ValueError('Account policy missing; recover private state')
 if type(row[0]) is not int or row[0] not in (0,1) or type(row[1]) is not int or row[1]<0:raise ValueError('Invalid account policy')
 return row
TRIGGER='CREATE TRIGGER account_policy_on_insert AFTER INSERT ON accounts BEGIN INSERT INTO account_policy VALUES(NEW.subject,0,0); END'
def setup_policy(db,migrate=False):
 marker=db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='account_policy_metadata'").fetchone()
 if marker:
  if db.execute('SELECT version FROM account_policy_metadata').fetchall()!=[(1,)]:raise ValueError('Invalid account policy metadata')
 else:
  accounts=db.execute('SELECT count(*) FROM accounts').fetchone()[0]
  existing=db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='account_policy'").fetchone()
  retained=db.execute('SELECT count(*) FROM account_policy').fetchone()[0] if existing else 0
  if (accounts or retained) and not migrate:raise ValueError('Explicit account policy migration required')
  db.execute(SCHEMA)
  db.execute('INSERT OR IGNORE INTO account_policy SELECT subject,0,0 FROM accounts')
  db.execute(TRIGGER)
  db.execute('CREATE TABLE account_policy_metadata (version INTEGER PRIMARY KEY CHECK(version=1))');db.execute('INSERT INTO account_policy_metadata VALUES(1)')
 trigger=db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='account_policy_on_insert'").fetchone()
 if not trigger or trigger[0]!=TRIGGER:raise ValueError('Account policy creation trigger missing or changed')
 if db.execute('SELECT count(*) FROM accounts LEFT JOIN account_policy USING(subject) WHERE account_policy.subject IS NULL').fetchone()[0]:raise ValueError('Account policy rows missing; restore private state')
 for subject,disabled,generation in db.execute('SELECT subject,disabled,generation FROM account_policy'):
  if type(disabled) is not int or disabled not in (0,1) or type(generation) is not int or generation<0:raise ValueError('Invalid persisted account policy')

STORED_HASH_PATTERN=re.compile(r'\$argon2id\$v=19\$m=[1-9][0-9]{0,5},t=[1-9][0-9]?,p=[1-9][0-9]?\$[A-Za-z0-9+/]{1,86}\$[A-Za-z0-9+/]{1,86}')
def validate_stored_hash(encoded):
 # Envelope validation is not password verification. Use the maintained Argon2
 # parser after bounding text and fixing a unique, canonical parameter layout.
 if not isinstance(encoded,str) or len(encoded)>512 or not STORED_HASH_PATTERN.fullmatch(encoded):raise Failure(500,'Stored password policy unavailable')
 try:parameters=extract_parameters(encoded)
 except (InvalidHashError,ValueError,TypeError):raise Failure(500,'Stored password policy unavailable') from None
 if parameters.type!=Type.ID or parameters.version!=19 or not (1<=parameters.parallelism<=4 and 8*parameters.parallelism<=parameters.memory_cost<=65536 and 1<=parameters.time_cost<=3 and 8<=parameters.salt_len<=64 and 4<=parameters.hash_len<=64):raise Failure(500,'Stored password policy unavailable')

class Service(ReferenceService):
 def __init__(self,config,clock=time.time,turn_policy=None,base_path='',maintenance_file=None):
  # Retained keys and login records are one identity state. Never recreate an
  # empty account registry alongside an existing signing key, or vice versa.
  state=Path(config.state_dir)
  files=[state/'issuer.pem',state/'accounts.sqlite3']
  if any(p.exists() or p.is_symlink() for p in files):
   info=state.lstat()
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Owned private retained issuer directory required')
   for file in files:
    try:info=file.lstat()
    except FileNotFoundError:raise ValueError('Retained issuer identity state incomplete; recover it without reinitializing') from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise ValueError('Owned private retained issuer key/database required')
  self.base_path=validate_base_path(base_path)
  self.desktop_epoch=str(uuid.uuid4())
  self.maintenance_file=Path(maintenance_file) if maintenance_file is not None else None
  self.turn_policy=turn_policy
  super().__init__(config,clock)
  self.app_asset_cache=RegisteredAppAssetCache(self.public_root)
  self.password_admissions=threading.BoundedSemaphore(PASSWORD_ADMISSIONS)
  with closing(connection(self.db)) as db:
   db.execute('BEGIN IMMEDIATE');setup_policy(db)
   db.execute('CREATE TABLE IF NOT EXISTS registered_sessions (token_digest TEXT PRIMARY KEY, record TEXT NOT NULL, deadline INTEGER NOT NULL)')
   db.execute('DELETE FROM registered_sessions WHERE deadline<=?',(self.now(),))
   rows=db.execute('SELECT token_digest,record,deadline FROM registered_sessions').fetchall()
   if len(rows)>self.c.max_sessions:raise ValueError('Persisted session capacity exceeded')
   for digest,raw,deadline in rows:
    if not isinstance(digest,str) or not re.fullmatch('[A-Za-z0-9_-]{43}',digest) or not isinstance(raw,str) or len(raw)>4096:raise ValueError('Invalid persisted session')
    session=json.loads(raw)
    # Accept records written by the first deployment, whose ICE extension
    # attached this optional, non-authoritative transport preference.
    if isinstance(session,dict) and '_ice_preference' in session:
     if session.pop('_ice_preference') not in ('relay','all'):raise ValueError('Invalid persisted session preference')
    if not isinstance(session,dict) or set(session)!={'sub','sid','name','kind','key','deadline','_account_generation'} or session['kind']!='registered' or type(deadline) is not int or session['deadline']!=deadline or type(session['_account_generation']) is not int or session['_account_generation']<0:raise ValueError('Invalid persisted session')
    if not all(isinstance(session[k],str) and 1<=len(session[k])<=128 for k in ('sub','sid','name')):raise ValueError('Invalid persisted session')
    if jose.public_jwk(jose.load_public(session['key']))!=session['key']:raise ValueError('Invalid persisted session key')
    self.sessions[digest]=session
   db.commit()
 def throttle(self,bucket,*,limit=None):
  # The proxy can make many real clients share this transport address. Keep a
  # bounded aggregate ceiling alongside the separate per-username limit.
  if limit is None and bucket.startswith('ip:'):limit=ISSUER_PEER_REQUESTS_PER_MINUTE
  return super().throttle(bucket,limit=limit)
 def account(self,data):
  # Keep the reference validation/hash policy, with one bounded transactional
  # account/policy write path instead of its ten-second SQLite fallback.
  if not isinstance(data,dict) or set(data) not in ({'username','password'},{'username','password','operation'}):raise Failure(400,'Username and password required')
  operation=data.get('operation','legacy')
  if 'operation' in data and operation not in ('register','signin'):raise Failure(400,'Choose register or signin')
  username,password=data['username'],data['password']
  if not isinstance(username,str) or not isinstance(password,str):raise Failure(400,'Invalid account input')
  username=username.strip().lower()
  if not re.fullmatch('[a-z][a-z0-9]{2,27}',username) or username in {'admin','root','owner','system'}:raise Failure(400,'Choose 3–28 letters or numbers, starting with a letter; that name may be reserved')
  # Existing accounts may have passwords from the earlier 128-character
  # policy; keep those sign-ins working while limiting new passwords to 32.
  maximum=128 if operation=='signin' else 32
  if not valid_password(password,maximum=maximum):raise Failure(400,'Password must be 4–'+str(maximum)+' characters without control characters')
  self.throttle('username:'+username)
  if not self.password_admissions.acquire(blocking=False):raise Failure(429,'Password service busy; try again shortly')
  if not self.hash_slots.acquire(timeout=PASSWORD_WAIT_SECONDS):
   self.password_admissions.release()
   raise Failure(429,'Password service busy; try again shortly')
  try:
   with closing(connection(self.db)) as db:
    try:db.execute('BEGIN IMMEDIATE')
    except sqlite3.OperationalError as error:
     # This marker is safe for a registration retry only when SQLite confirms
     # that no transaction was entered and no account write was attempted.
     if getattr(error,'sqlite_errorcode',0)&255 in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED) and not db.in_transaction:raise Failure(429,'Account admission busy; try again shortly') from None
     raise
    row=db.execute('SELECT subject,password_hash FROM accounts WHERE username=?',(username,)).fetchone()
    if row:
     if operation=='register':raise Failure(400,'Username unavailable; choose another name or sign in')
     try:disabled,generation=policy(db,row[0])
     except ValueError:raise Failure(500,'Account policy unavailable')
     if disabled:raise Failure(401,'Unable to sign in')
     validate_stored_hash(row[1])
     try:self.passwords.verify(row[1],password)
     except (VerifyMismatchError,VerificationError):raise Failure(401,'Unable to sign in')
     subject=row[0]
     if self.passwords.check_needs_rehash(row[1]):db.execute('UPDATE accounts SET password_hash=? WHERE username=?',(self.passwords.hash(password),username))
    else:
     if operation=='signin':
      # Keep missing-name attempts inside the existing bounded Argon2 slots;
      # signing in must never implicitly register a mistyped username.
      self.passwords.hash(password)
      raise Failure(401,'Unable to sign in')
     subject='user:'+str(uuid.uuid4())
     db.execute('INSERT INTO accounts VALUES (?,?,?,?)',(username,subject,self.passwords.hash(password),self.now()))
     disabled,generation=policy(db,subject)
    db.commit()
   return subject,username,generation
  except sqlite3.OperationalError as error:
   if getattr(error,'sqlite_errorcode',0)&255 in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):raise Failure(429,'Account database busy; retry later') from None
   raise
  finally:
   self.hash_slots.release()
   self.password_admissions.release()
 def issue(self,session):
  if session['kind']!='registered':return self._signed_issue(session)
  # The read transaction holds the issuance decision through signing. An admin
  # disable committing afterward cannot retroactively revoke that certificate.
  with closing(connection(self.db)) as db:
   db.execute('BEGIN')
   account=db.execute('SELECT username FROM accounts WHERE subject=?',(session['sub'],)).fetchone()
   if account is None or account[0]!=session['name']:raise Failure(401,'Account no longer available')
   try:disabled,generation=policy(db,session['sub'])
   except ValueError:raise Failure(500,'Account policy unavailable')
   if type(session.get('_account_generation')) is not int:raise Failure(500,'Session generation unavailable')
   if disabled or session['_account_generation']!=generation:raise Failure(401,'Session revoked or account unavailable')
   session['_account_generation']=generation
   return self._signed_issue(session)
 def config(self):
  reference=super().config()
  # Account discovery is independent of guest engines and peer transports.
  # Keep the identity wire format while advertising only this service's API.
  config={'protocol':reference['protocol'],'identity':reference['identity']}
  config['identity']['apiBase']=self.base_path+'/api/v1'
  config['accounts']={'actions':['register','signin']}
  config['desktopLifecycle']={'version':'codi-desktop-lifecycle/1','statusPath':self.base_path+'/api/v1/desktop-status'}
  return config
 def desktop_status(self):
  notice=None
  if self.maintenance_file is not None:
   path=self.maintenance_file
   for parent in [path.parent,*path.parent.parents]:
    info=parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Protected maintenance directory required')
   try:fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
   except FileNotFoundError:pass
   else:
    try:
     info=os.fstat(fd)
     if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o644 or info.st_nlink!=1 or info.st_size>4096:raise ValueError('Protected bounded maintenance notice required')
     raw=os.read(fd,4097)
    finally:os.close(fd)
    value=json.loads(raw)
    if set(value)!={'version','id','phase','deadline','expiresAt','message'} or value['version']!='codi-maintenance-notice/1' or not re.fullmatch(r'[a-f0-9]{32}',value['id']) or value['phase'] not in ('scheduled','active','cancelled'):raise ValueError('Invalid maintenance notice')
    if any(type(value[k]) is not int for k in ['deadline','expiresAt']) or not value['deadline']<=value['expiresAt']<=value['deadline']+86400 or not isinstance(value['message'],str) or not 1<=len(value['message'])<=500:raise ValueError('Invalid maintenance deadline/message')
    if value['expiresAt']>self.now():notice=value
  return {'version':'codi-desktop-status/1','epoch':self.desktop_epoch,'serverTime':self.now(),'maintenance':notice}
 def static(self,path,start):
  # The reference dispatcher admits only GET here (HeadSupport preserves GET
  # headers for HEAD). All path/Host/authorization/error behavior stays there.
  def asset_headers(status,headers,exc_info=None):
   headers=self.app_asset_cache.response_headers(path,status,headers)
   return start(status,headers) if exc_info is None else start(status,headers,exc_info)
  return super().static(path,asset_headers)
 def __call__(self,env,start):
  if env.get('PATH_INFO')=='/assets/desktop/offline-worker.js':
   def worker_headers(status,headers,exc_info=None):return start(status,[*headers,('Service-Worker-Allowed',self.base_path+'/')],exc_info)
   return super().__call__(env,worker_headers)
  if env.get('PATH_INFO')!='/api/v1/desktop-status':return super().__call__(env,start)
  if env.get('HTTP_HOST')!=urlsplit(self.c.origin).netloc:return self.json_response(start,403,{'error':'Unexpected Host'})
  if env.get('REQUEST_METHOD')!='GET':return self.json_response(start,405,{'error':'GET required'})
  try:return self.json_response(start,200,self.desktop_status())
  except Exception:return self.json_response(start,500,{'error':'Desktop status unavailable'})
 def challenge(self,data):
  if not self.base_path:return super().challenge(data)
  if not isinstance(data,dict) or set(data)!={'key','path'} or not isinstance(data['path'],str) or data['path'] not in {self.base_path+p for p in PATHS}:raise Failure(400,'Invalid challenge request')
  # The existing validator and bounded challenge store remain authoritative.
  # Hold its RLock through replacing the path with the full external binding.
  with self.lock:
   result=super().challenge({**data,'path':data['path'][len(self.base_path):]})
   self.challenges[result['nonce']]['path']=data['path']
   return result
 def consume_proof(self,envelope,path):
  return super().consume_proof(envelope,self.base_path+path)
 def _signed_issue(self,session):
  result=super().issue(session)
  if self.turn_policy is not None:result['rtc']=self.turn_policy.issue(result['expires_at'],self.clock)
  return result
 def enter(self,data,key,path):
  if path.endswith('/anonymous'):
   if data:raise Failure(400,'Anonymous identities are assigned by the server')
   sub='anon:'+str(uuid.uuid4());name='anon-'+secrets.token_hex(6);kind='anonymous'
  else:sub,name,generation=self.account(data);kind='registered'
  session={'sub':sub,'sid':str(uuid.uuid4()),'name':name,'kind':kind,'key':key,'deadline':self.now()+self.c.session_seconds}
  if kind=='registered':session['_account_generation']=generation
  with self.lock:
   self.cleanup()
   if len(self.sessions)>=self.c.max_sessions:raise Failure(429,'Session capacity reached')
   # A rejected issuance must not consume an unreachable RAM session slot.
   result=self.issue(session);token=secrets.token_urlsafe(32);digest=jose.digest(token)
   if kind=='registered':
    with closing(connection(self.db)) as db:
     db.execute('BEGIN IMMEDIATE');db.execute('DELETE FROM registered_sessions WHERE deadline<=?',(self.now(),))
     # Issuance extensions may attach transient data (such as ICE preference).
     # Persist only the stable authentication binding, not extension state.
     record={k:session[k] for k in ('sub','sid','name','kind','key','deadline','_account_generation')}
     db.execute('INSERT INTO registered_sessions VALUES (?,?,?)',(digest,json.dumps(record,separators=(',',':')),session['deadline']));db.commit()
   self.sessions[digest]=session
  result['session_token']=token;return result
 def continue_session(self,data,key,proof,path,authorization):
  if data or not authorization.startswith('Codi '):raise Failure(401,'Session authentication required')
  token=authorization[5:]
  if len(token)>128:raise Failure(401,'Invalid session')
  digest=jose.digest(token)
  with self.lock:
   self.cleanup();session=self.sessions.get(digest)
   if session is None or session['sid']!=proof.get('iss') or jose.thumbprint(session['key'])!=jose.thumbprint(key):raise Failure(401,'Invalid session binding')
   if session['kind']=='registered':
    with closing(connection(self.db)) as db:
     db.execute('BEGIN IMMEDIATE' if path.endswith('/logout') else 'BEGIN')
     row=db.execute('SELECT 1 FROM registered_sessions WHERE token_digest=? AND deadline>?',(digest,self.now())).fetchone()
     if row is None:raise Failure(401,'Session revoked')
     if path.endswith('/logout'):db.execute('DELETE FROM registered_sessions WHERE token_digest=?',(digest,));db.commit()
   if path.endswith('/logout'):
    del self.sessions[digest];return {'logged_out':True}
   return self.issue(session)

def private_database(state):
 state=Path(state).absolute();db_path=state/'accounts.sqlite3'
 for path,is_directory,mode in ((state,True,0o700),(db_path,False,0o600)):
  info=path.lstat()
  if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=mode or not (stat.S_ISDIR(info.st_mode) if is_directory else stat.S_ISREG(info.st_mode)):raise ValueError('Owned private issuer state required')
 return db_path

def migrate_policy(state):
 db_path=private_database(state)
 with closing(connection(db_path)) as db:
  db.execute('BEGIN IMMEDIATE');setup_policy(db,migrate=True);db.commit()
  return {'migrated':True,'accounts':db.execute('SELECT count(*) FROM accounts').fetchone()[0]}

def set_disabled(state,username,disabled):
 db_path=private_database(state)
 name=username.strip().lower()
 if not re.fullmatch('[a-z][a-z0-9_-]{2,31}',name) or type(disabled) is not bool:raise ValueError('Invalid account policy input')
 with closing(connection(db_path)) as db:
  db.execute('BEGIN IMMEDIATE');setup_policy(db)
  row=db.execute('SELECT subject FROM accounts WHERE username=?',(name,)).fetchone()
  if row is None:raise ValueError('Unknown account; no account created')
  subject=row[0];prior,generation=policy(db,subject)
  if prior!=int(disabled):generation+=1
  db.execute('INSERT INTO account_policy VALUES (?,?,?) ON CONFLICT(subject) DO UPDATE SET disabled=excluded.disabled,generation=excluded.generation',(subject,int(disabled),generation));db.commit()
 return {'subject':subject,'disabled':disabled,'generation':generation}


def valid_password(password,*,maximum=32):
 if not isinstance(password,str) or not 4<=len(password)<=maximum:return False
 try:password.encode('utf-8')
 except UnicodeEncodeError:return False
 return not any(ord(c)<32 or 127<=ord(c)<=159 for c in password)

def reset_password(state,username,password):
 """Local state-owner operation: replace the secret and revoke HTTP sessions."""
 db_path=private_database(state);name=username.strip().lower()
 if not re.fullmatch('[a-z][a-z0-9_-]{2,31}',name):raise ValueError('Invalid account name')
 if not valid_password(password):raise ValueError('Password must be 4–32 characters without control characters')
 with closing(connection(db_path)) as db:
  db.execute('BEGIN IMMEDIATE');setup_policy(db)
  row=db.execute('SELECT subject FROM accounts WHERE username=?',(name,)).fetchone()
  if row is None:raise ValueError('Unknown account; no account created')
  subject=row[0];disabled,generation=policy(db,subject)
  encoded=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1,hash_len=32,salt_len=16,type=Type.ID).hash(password)
  validate_stored_hash(encoded)
  db.execute('UPDATE accounts SET password_hash=? WHERE subject=?',(encoded,subject))
  db.execute('UPDATE account_policy SET generation=? WHERE subject=?',(generation+1,subject));db.commit()
 return {'subject':subject,'disabled':bool(disabled),'generation':generation+1,'passwordChanged':True}
