"""Small WSGI identity authority, intentionally NOT a host resource broker.

Anonymous sessions and credentials live only in RAM. Registered account password
hashes and the issuer key are persistent. No messages, guest state, or peer
signaling are accepted. Deployment hardening is a separate, mandatory gate.
"""
from dataclasses import dataclass
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from . import jose
CERT_TYPE='codi-identity+jwt'
PROOF_TYPE='codi-request+jws'
PATHS={'/api/v1/anonymous','/api/v1/auth','/api/v1/renew','/api/v1/logout'}
@dataclass
class Config:
    state_dir: Path
    web_root: Path
    origin: str='http://127.0.0.1:8098'
    audience: str='codiserver-peers-v1'
    certificate_seconds: int=900
    session_seconds: int=28800
    max_sessions: int=2048
    max_challenges: int=1024
    rate_per_minute: int=60
    authority_class: str='development'
class Failure(Exception):
    def __init__(self,status,message): self.status=status;self.message=message

class Service:
    def __init__(self,config: Config,clock=time.time):
        self.c=config;self.clock=clock;self.lock=threading.RLock()
        self.challenges={};self.sessions={};self.rates={}
        self.public_root=Path(config.web_root).resolve();self.state_root=Path(config.state_dir).resolve()
        if self.state_root.is_relative_to(self.public_root) or self.public_root.is_relative_to(self.state_root):
            raise ValueError('State and public files must be disjoint directory trees')
        u=urlsplit(config.origin)
        if u.path or u.query or u.fragment or not u.netloc:raise ValueError('Origin must be scheme + authority only')
        if u.scheme!='https' and not (u.scheme=='http' and u.hostname in ('127.0.0.1','localhost','[::1]','::1')):
            raise ValueError('Plain HTTP is only allowed on loopback')
        if config.authority_class!='development':
            raise ValueError('This reference build is development-only; complete S04 before introducing an official deployment entry point')
        if not 1<=config.certificate_seconds<=900:raise ValueError('Certificate TTL must be 1..900 seconds')
        if not (self.public_root/'index.html').is_file():raise ValueError('Explicit web public/ directory required')
        self.state_root.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(self.state_root,0o700)
        key_path=self.state_root/'issuer.pem'
        if key_path.exists():
            if key_path.is_symlink() or key_path.stat().st_mode & 0o077:raise ValueError('Issuer key must be a private regular file (0600)')
            self.key=serialization.load_pem_private_key(key_path.read_bytes(),password=None)
            if not isinstance(self.key,ec.EllipticCurvePrivateKey) or not isinstance(self.key.curve,ec.SECP256R1):raise ValueError('Wrong issuer key type')
        else:
            self.key=ec.generate_private_key(ec.SECP256R1())
            raw=self.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            fd=os.open(key_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as out:out.write(raw)
        self.jwk=jose.public_jwk(self.key);self.kid=jose.thumbprint(self.jwk)[:24]
        self.db=self.state_root/'accounts.sqlite3'
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('CREATE TABLE IF NOT EXISTS accounts (username TEXT PRIMARY KEY, subject TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created INTEGER NOT NULL)')
            db.commit()
        os.chmod(self.db,0o600)
        self.passwords=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1,hash_len=32,salt_len=16)
        self.hash_slots=threading.BoundedSemaphore(2)
    def now(self):return int(self.clock())
    def cleanup(self):
        t=self.now()
        self.challenges={k:v for k,v in self.challenges.items() if v['expires']>t}
        self.sessions={k:v for k,v in self.sessions.items() if v['deadline']>t}
        self.rates={k:v for k,v in self.rates.items() if v[0]+60>t}
    def throttle(self,bucket,*,limit=None):
        with self.lock:
            self.cleanup();t=self.now()
            if bucket not in self.rates and len(self.rates)>=4096:raise Failure(429,'Capacity reached; retry later')
            start,count=self.rates.get(bucket,(t,0));self.rates[bucket]=(start,count+1)
            if count>=(self.c.rate_per_minute if limit is None else limit):raise Failure(429,'Too many requests; retry later')
    def challenge(self,data):
        if set(data)!={'key','path'} or data['path'] not in PATHS:raise Failure(400,'Invalid challenge request')
        key=jose.public_jwk(jose.load_public(data['key']))
        with self.lock:
            self.cleanup()
            if len(self.challenges)>=self.c.max_challenges:raise Failure(429,'Challenge capacity reached')
            nonce=secrets.token_urlsafe(32)
            self.challenges[nonce]={'key':key,'path':data['path'],'expires':self.now()+60}
        return {'nonce':nonce,'expires_at':self.now()+60}
    def consume_proof(self,envelope,path):
        if set(envelope)!={'request','proof'} or not isinstance(envelope['request'],str):raise Failure(400,'Invalid request envelope')
        p=jose.inspect(envelope['proof'],PROOF_TYPE)[1]
        nonce=p.get('nonce')
        if not isinstance(nonce,str):raise Failure(401,'Invalid authentication proof')
        # One-use even on failure; a malicious invalid proof cannot consume an
        # unrelated challenge without first guessing its 256-bit nonce.
        with self.lock:
            self.cleanup();ch=self.challenges.pop(nonce,None)
        if ch is None:raise Failure(401,'Expired or already used challenge')
        p=jose.verify(envelope['proof'],ch['key'],PROOF_TYPE)
        t=self.now()
        if any(type(p.get(k)) is not int for k in ('iat','exp')):raise Failure(401,'Invalid proof time')
        if not (p['iat']<=t+30 and p['exp']>t and 0<p['exp']-p['iat']<=60):raise Failure(401,'Expired proof')
        if p.get('v')!=1 or p.get('aud')!=self.c.origin or p.get('method')!='POST' or p.get('path')!=path or ch['path']!=path:
            raise Failure(401,'Wrong proof context')
        if p.get('request_sha256')!=jose.digest(envelope['request']):raise Failure(401,'Request body changed')
        data=jose.loads(envelope['request'])
        if not isinstance(data,dict):raise Failure(400,'Request data must be an object')
        return data,ch['key'],p
    def account(self,data):
        if set(data)!={'username','password'}:raise Failure(400,'Username and password required')
        username,password=data['username'],data['password']
        if not isinstance(username,str) or not isinstance(password,str):raise Failure(400,'Invalid account input')
        username=username.strip().lower()
        if not re.fullmatch('[a-z][a-z0-9_-]{2,31}',username) or username in {'admin','root','owner','system'}:
            raise Failure(400,'Choose 3–32 ASCII letters, digits, _ or -, starting with a letter; that name may be reserved')
        if not 15<=len(password)<=128 or len(password.encode('utf-8'))>512:raise Failure(400,'Password must be 15–128 characters')
        self.throttle('username:'+username)
        if not self.hash_slots.acquire(blocking=False):raise Failure(429,'Password service busy')
        try:
            # BEGIN IMMEDIATE serializes first registration. Never overwrite an
            # existing account after an incorrect password or concurrent signup.
            with closing(sqlite3.connect(self.db,timeout=10)) as db:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT subject,password_hash FROM accounts WHERE username=?',(username,)).fetchone()
                if row:
                    try:self.passwords.verify(row[1],password)
                    except (VerifyMismatchError,VerificationError):raise Failure(401,'Unable to sign in')
                    subject=row[0]
                    if self.passwords.check_needs_rehash(row[1]):db.execute('UPDATE accounts SET password_hash=? WHERE username=?',(self.passwords.hash(password),username))
                else:
                    subject='user:'+str(uuid.uuid4())
                    db.execute('INSERT INTO accounts VALUES (?,?,?,?)',(username,subject,self.passwords.hash(password),self.now()))
                db.commit()
            return subject,username
        finally:self.hash_slots.release()
    def issue(self,s):
        t=self.now();exp=min(t+self.c.certificate_seconds,s['deadline'])
        claims={'v':1,'iss':self.c.origin,'aud':self.c.audience,'sub':s['sub'],'sid':s['sid'],
            'kind':s['kind'],'name':s['name'],'cnf':{'jwk':s['key']},'iat':t,'nbf':t,'exp':exp,'jti':str(uuid.uuid4())}
        identity={k:s[k] for k in ('sid','sub','name','kind','key')}
        identity['certificate']=jose.sign(claims,self.key,CERT_TYPE,self.kid)
        return {'identity':identity,'validated_at':t,'expires_at':exp}
    def enter(self,data,key,path):
        if path.endswith('/anonymous'):
            if data:raise Failure(400,'Anonymous identities are assigned by the server')
            sub='anon:'+str(uuid.uuid4());name='anon-'+secrets.token_hex(6);kind='anonymous'
        else:sub,name=self.account(data);kind='registered'
        s={'sub':sub,'sid':str(uuid.uuid4()),'name':name,'kind':kind,'key':key,'deadline':self.now()+self.c.session_seconds}
        token=secrets.token_urlsafe(32)
        with self.lock:
            self.cleanup()
            if len(self.sessions)>=self.c.max_sessions:raise Failure(429,'Session capacity reached')
            self.sessions[jose.digest(token)]=s
        result=self.issue(s);result['session_token']=token
        return result
    def continue_session(self,data,key,proof,path,authorization):
        if data or not authorization.startswith('Codi '):raise Failure(401,'Session authentication required')
        token=authorization[5:]
        if len(token)>128:raise Failure(401,'Invalid session')
        with self.lock:
            self.cleanup();s=self.sessions.get(jose.digest(token))
            if s is None or s['sid']!=proof.get('iss') or jose.thumbprint(s['key'])!=jose.thumbprint(key):raise Failure(401,'Invalid session binding')
            if path.endswith('/logout'):
                del self.sessions[jose.digest(token)];return {'logged_out':True}
            return self.issue(s)
    def config(self):
        return {'protocol':'codi-peer/1','identity':{'mode':'server','apiBase':'/api/v1','issuer':self.c.origin,
            'audience':self.c.audience,'authorityClass':self.c.authority_class,'authorityKeys':[{'kid':self.kid,'jwk':self.jwk}]},
            'rtc':{'iceServers':[]},'vm':{'manifest':'/vm/manifest.json'}}
    def json_response(self,start,status,data):
        return self.respond(start,status,jose.dumps(data).encode(),'application/json')
    def respond(self,start,status,body,content_type):
        names={200:'OK',400:'Bad Request',401:'Unauthorized',403:'Forbidden',404:'Not Found',405:'Method Not Allowed',413:'Payload Too Large',415:'Unsupported Media Type',429:'Too Many Requests',500:'Internal Server Error'}
        start(f'{status} {names[status]}',[('Content-Type',content_type),('Content-Length',str(len(body))),
            ('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),('Referrer-Policy','no-referrer'),
            ('Cross-Origin-Opener-Policy','same-origin'),('Cross-Origin-Embedder-Policy','require-corp'),
            ('Content-Security-Policy',"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'")])
        return [body]
    def static(self,path,start):
        if '..' in path.split('/') or '\\' in path or '\x00' in path:raise Failure(403,'Invalid path')
        rel=path.lstrip('/') or 'index.html';target=self.public_root/rel
        # Reject symlinks at every component, not only those pointing outside.
        cursor=self.public_root
        for part in Path(rel).parts:
            cursor=cursor/part
            if cursor.is_symlink():raise Failure(403,'Symlink assets are not served')
        target=target.resolve()
        if not target.is_relative_to(self.public_root) or not target.is_file():raise Failure(404,'Not found')
        # Only explicit public root. The dev server does not implement Range;
        # production Caddy serves huge assets and ranges, never this function.
        if target.stat().st_size>64*1024*1024:raise Failure(413,'Use sharded assets or the planned static production server')
        typ='text/javascript' if target.suffix=='.mjs' else mimetypes.guess_type(target.name)[0] or 'application/octet-stream'
        return self.respond(start,200,target.read_bytes(),typ)
    def __call__(self,env,start):
        try:
            method=env.get('REQUEST_METHOD','GET');path=env.get('PATH_INFO','/')
            if env.get('HTTP_HOST')!=urlsplit(self.c.origin).netloc:raise Failure(403,'Unexpected Host')
            if method=='GET':
                if path=='/healthz':return self.json_response(start,200,{'status':'ok','scope':'identity-reference-only'})
                if path=='/config.json':return self.json_response(start,200,self.config())
                if path=='/.well-known/codi-issuer.json':return self.json_response(start,200,{'issuer':self.c.origin,'keys':self.config()['identity']['authorityKeys']})
                if path.startswith('/api/'):raise Failure(405,'POST required')
                return self.static(path,start)
            if method!='POST':raise Failure(405,'Method not allowed')
            if path!='/api/v1/challenge' and path not in PATHS:raise Failure(404,'Not found')
            if env.get('HTTP_ORIGIN')!=self.c.origin:raise Failure(403,'Unexpected Origin')
            if env.get('CONTENT_TYPE','').split(';')[0].strip()!='application/json':raise Failure(415,'JSON required')
            if env.get('HTTP_TRANSFER_ENCODING'):raise Failure(400,'Unsupported transfer encoding')
            try:length=int(env.get('CONTENT_LENGTH',''))
            except ValueError:raise Failure(400,'Content-Length required')
            if not 0<length<=65536:raise Failure(413,'Request too large')
            self.throttle('ip:'+env.get('REMOTE_ADDR','unknown'))
            raw=env['wsgi.input'].read(length)
            if len(raw)!=length:raise Failure(400,'Truncated request')
            data=jose.loads(raw)
            if not isinstance(data,dict):raise Failure(400,'Object request required')
            if path=='/api/v1/challenge':result=self.challenge(data)
            else:
                body,key,proof=self.consume_proof(data,path)
                if path in {'/api/v1/anonymous','/api/v1/auth'}:result=self.enter(body,key,path)
                else:result=self.continue_session(body,key,proof,path,env.get('HTTP_AUTHORIZATION',''))
            return self.json_response(start,200,result)
        except Failure as e:return self.json_response(start,e.status,{'error':e.message})
        except (jose.Invalid,ValueError,TypeError,KeyError,UnicodeError):return self.json_response(start,400,{'error':'Invalid request'})
        except Exception:return self.json_response(start,500,{'error':'Internal service error'})
