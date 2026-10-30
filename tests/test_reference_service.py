import io, json, tempfile, unittest, sqlite3, os, threading
from contextlib import closing
from pathlib import Path
from dataclasses import replace
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.asymmetric import ec
from codiauth.service import Config,Service,CERT_TYPE,PROOF_TYPE
from codiauth import jose
PASSWORD='correct horse battery staple'

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        web=self.root/'public';web.mkdir();(web/'index.html').write_text('test shell')
        self.t=2000000000
        self.config=Config(self.root/'state',web,rate_per_minute=1000)
        self.s=Service(self.config,clock=lambda:self.t)
        self.key=ec.generate_private_key(ec.SECP256R1());self.jwk=jose.public_jwk(self.key)
    def tearDown(self):self.temp.cleanup()
    def call(self,path,body=None,method='POST',headers=None,raw=None):
        data=raw if raw is not None else (jose.dumps(body or {}).encode() if method=='POST' else b'')
        env={'REQUEST_METHOD':method,'PATH_INFO':path,'HTTP_HOST':urlsplit(self.config.origin).netloc,
             'HTTP_ORIGIN':self.config.origin,'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(data)),
             'wsgi.input':io.BytesIO(data),'REMOTE_ADDR':'127.0.0.1'}
        env.update(headers or {});out={}
        def start(status,hs):out.update(status=int(status.split()[0]),headers=dict(hs))
        raw=b''.join(self.s(env,start));
        out['body']=json.loads(raw) if out['headers']['Content-Type']=='application/json' else raw
        return out
    def envelope(self,path,data,key=None,public=None,subject='local-test'):
        key=key or self.key;public=public or jose.public_jwk(key)
        c=self.call('/api/v1/challenge',{'key':public,'path':path});self.assertEqual(c['status'],200,c)
        request=jose.dumps(data);proof={'v':1,'nonce':c['body']['nonce'],'iss':subject,'aud':self.config.origin,
          'method':'POST','path':path,'iat':self.t,'exp':self.t+60,'request_sha256':jose.digest(request)}
        return {'request':request,'proof':jose.sign(proof,key,PROOF_TYPE)}
    def enter(self,name=None,key=None):
        path='/api/v1/auth' if name else '/api/v1/anonymous';data={'username':name,'password':PASSWORD} if name else {}
        r=self.call(path,self.envelope(path,data,key));self.assertEqual(r['status'],200,r);return r['body']
    def session_request(self,path,session,key=None):
        e=self.envelope(path,{},key=key,subject=session['identity']['sid'])
        return self.call(path,e,headers={'HTTP_AUTHORIZATION':'Codi '+session['session_token']})
    def test_anon_certificate_is_real_es256(self):
        r=self.enter();c=jose.verify(r['identity']['certificate'],self.s.jwk,CERT_TYPE)
        self.assertEqual(c['kind'],'anonymous');self.assertEqual(c['cnf']['jwk'],self.jwk);self.assertEqual(c['exp']-c['iat'],900)
    def test_anon_random_identity_each_entry(self):
        a,b=self.enter(),self.enter();self.assertNotEqual(a['identity']['sub'],b['identity']['sub']);self.assertNotEqual(a['identity']['name'],b['identity']['name'])
    def test_anon_no_durable_account(self):
        self.enter()
        with closing(sqlite3.connect(self.s.db)) as db:self.assertEqual(db.execute('SELECT count(*) FROM accounts').fetchone()[0],0)
    def test_anon_cannot_choose_official_name(self):
        path='/api/v1/anonymous';self.assertEqual(self.call(path,self.envelope(path,{'name':'owner'}))['status'],400)
    def test_signup_then_login_stable_subject_fresh_session(self):
        a,b=self.enter('alice'),self.enter('ALICE');self.assertEqual(a['identity']['sub'],b['identity']['sub']);self.assertNotEqual(a['identity']['sid'],b['identity']['sid'])
    def test_password_is_argon2id_only(self):
        self.enter('alice')
        with closing(sqlite3.connect(self.s.db)) as db:h=db.execute('SELECT password_hash FROM accounts').fetchone()[0]
        self.assertTrue(h.startswith('$argon2id$'));self.assertNotIn(PASSWORD,self.s.db.read_bytes().decode('latin1'))
    def test_wrong_password_never_replaces_account(self):
        a=self.enter('alice');path='/api/v1/auth'
        bad=self.call(path,self.envelope(path,{'username':'alice','password':'wrong password but long'}));self.assertEqual(bad['status'],401)
        self.assertEqual(a['identity']['sub'],self.enter('alice')['identity']['sub'])
    def test_reserved_names_cannot_be_auto_owner(self):
        for name in ('owner','admin','root','system'):
            path='/api/v1/auth';self.assertEqual(self.call(path,self.envelope(path,{'username':name,'password':PASSWORD}))['status'],400)
    def test_short_password_rejected(self):
        path='/api/v1/auth';self.assertEqual(self.call(path,self.envelope(path,{'username':'alice','password':'short'}))['status'],400)
    def test_unicode_username_rejected(self):
        path='/api/v1/auth';self.assertEqual(self.call(path,self.envelope(path,{'username':'аlice','password':PASSWORD}))['status'],400)
    def test_proof_replay_rejected(self):
        e=self.envelope('/api/v1/anonymous',{});self.assertEqual(self.call('/api/v1/anonymous',e)['status'],200);self.assertEqual(self.call('/api/v1/anonymous',e)['status'],401)
    def test_body_tampering_rejected(self):
        e=self.envelope('/api/v1/anonymous',{});e['request']='{"name":"forged"}';self.assertEqual(self.call('/api/v1/anonymous',e)['status'],401)
    def test_wrong_route_rejected(self):
        e=self.envelope('/api/v1/anonymous',{});self.assertEqual(self.call('/api/v1/auth',e)['status'],401)
    def test_expired_challenge_rejected(self):
        e=self.envelope('/api/v1/anonymous',{});self.t+=61;self.assertEqual(self.call('/api/v1/anonymous',e)['status'],401)
    def test_wrong_signing_key_rejected(self):
        other=ec.generate_private_key(ec.SECP256R1());e=self.envelope('/api/v1/anonymous',{},key=other,public=self.jwk)
        self.assertEqual(self.call('/api/v1/anonymous',e)['status'],400)
    def test_jws_type_confusion_rejected(self):
        e=self.envelope('/api/v1/anonymous',{});p=jose.inspect(e['proof'],PROOF_TYPE)[1];e['proof']=jose.sign(p,self.key,CERT_TYPE)
        self.assertEqual(self.call('/api/v1/anonymous',e)['status'],400)
    def test_none_algorithm_rejected(self):
        e=self.envelope('/api/v1/anonymous',{});parts=e['proof'].split('.');parts[0]=jose.b64(b'{"alg":"none","typ":"codi-request+jws"}');e['proof']='.'.join(parts)
        self.assertEqual(self.call('/api/v1/anonymous',e)['status'],400)
    def test_cross_origin_rejected(self):
        self.assertEqual(self.call('/api/v1/challenge',{},headers={'HTTP_ORIGIN':'https://evil.invalid'})['status'],403)
    def test_missing_origin_rejected(self):
        self.assertEqual(self.call('/api/v1/challenge',{},headers={'HTTP_ORIGIN':''})['status'],403)
    def test_host_header_rejected(self):
        self.assertEqual(self.call('/healthz',method='GET',headers={'HTTP_HOST':'evil.invalid'})['status'],403)
    def test_oversize_request_rejected(self):
        self.assertEqual(self.call('/api/v1/challenge',{},headers={'CONTENT_LENGTH':'65537'})['status'],413)
    def test_form_post_rejected(self):
        self.assertEqual(self.call('/api/v1/challenge',{},headers={'CONTENT_TYPE':'text/plain'})['status'],415)
    def test_duplicate_json_keys_rejected(self):
        self.assertEqual(self.call('/api/v1/challenge',raw=b'{"key":1,"key":2}')['status'],400)
    def test_unknown_api_and_host_file_endpoint_absent(self):
        for path in ('/api/v1/files','/api/v1/shell','/api/v1/jobs','/api/v1/signal','/api/v1/messages'):
            self.assertEqual(self.call(path,{})['status'],404)
    def test_static_root_only(self):
        self.assertEqual(self.call('/../state/issuer.pem',method='GET')['status'],403)
        self.assertEqual(self.call('/issuer.pem',method='GET')['status'],404)
        self.assertEqual(self.call('/',method='GET')['body'],b'test shell')
    def test_static_symlink_rejected(self):
        (self.config.web_root/'secret').symlink_to(self.s.db);self.assertEqual(self.call('/secret',method='GET')['status'],403)
    def test_overlapping_data_and_public_rejected(self):
        with self.assertRaises(ValueError):Service(replace(self.config,state_dir=self.config.web_root/'state'))
    def test_config_is_development_authority(self):
        r=self.call('/config.json',method='GET');self.assertEqual(r['body']['identity']['mode'],'server');self.assertEqual(r['body']['identity']['authorityClass'],'development')
    def test_no_ambient_cookie_or_cors(self):
        r=self.call('/healthz',method='GET');self.assertNotIn('Set-Cookie',r['headers']);self.assertNotIn('Access-Control-Allow-Origin',r['headers'])
    def test_keybound_renewal(self):
        a=self.enter();self.t+=10;r=self.session_request('/api/v1/renew',a);self.assertEqual(r['status'],200)
        self.assertEqual(r['body']['identity']['sid'],a['identity']['sid']);self.assertEqual(r['body']['validated_at'],self.t)
    def test_stolen_token_without_private_key_rejected(self):
        a=self.enter();other=ec.generate_private_key(ec.SECP256R1());self.assertEqual(self.session_request('/api/v1/renew',a,other)['status'],401)
    def test_cross_tab_tokens_do_not_replace_each_other(self):
        a,b=self.enter(),self.enter();self.assertEqual(self.session_request('/api/v1/renew',a)['status'],200);self.assertEqual(self.session_request('/api/v1/renew',b)['status'],200)
    def test_logout_removes_only_current_server_session(self):
        a,b=self.enter(),self.enter();self.assertEqual(self.session_request('/api/v1/logout',a)['status'],200)
        self.assertEqual(self.session_request('/api/v1/renew',a)['status'],401);self.assertEqual(self.session_request('/api/v1/renew',b)['status'],200)
    def test_logout_does_not_magic_revoke_offline_certificate(self):
        a=self.enter();self.session_request('/api/v1/logout',a);c=jose.verify(a['identity']['certificate'],self.s.jwk,CERT_TYPE);self.assertGreater(c['exp'],self.t)
    def test_expired_absolute_session_cannot_renew(self):
        a=self.enter();self.t+=self.config.session_seconds+1;self.assertEqual(self.session_request('/api/v1/renew',a)['status'],401)
    def test_restart_retains_accounts_not_sessions(self):
        a=self.enter('alice');kid=self.s.kid;self.s=Service(self.config,clock=lambda:self.t)
        self.assertEqual(self.s.kid,kid);self.assertEqual(self.session_request('/api/v1/renew',a)['status'],401)
        self.assertEqual(self.enter('alice')['identity']['sub'],a['identity']['sub'])
    def test_rate_limit(self):
        self.s.c.rate_per_minute=2
        for _ in range(2):self.assertEqual(self.call('/api/v1/challenge',{'key':self.jwk,'path':'/api/v1/anonymous'})['status'],200)
        self.assertEqual(self.call('/api/v1/challenge',{'key':self.jwk,'path':'/api/v1/anonymous'})['status'],429)
    def test_capacity_limits(self):
        self.s.c.max_challenges=1
        self.assertEqual(self.call('/api/v1/challenge',{'key':self.jwk,'path':'/api/v1/anonymous'})['status'],200)
        self.assertEqual(self.call('/api/v1/challenge',{'key':self.jwk,'path':'/api/v1/anonymous'})['status'],429)
    def test_secrets_permissions(self):
        self.assertEqual((self.s.state_root/'issuer.pem').stat().st_mode&0o777,0o600)
        self.assertEqual(self.s.state_root.stat().st_mode&0o777,0o700)
    def test_public_http_refused(self):
        with self.assertRaises(ValueError):Service(replace(self.config,origin='http://example.invalid'))
    def test_official_deployment_refused_by_reference_entry(self):
        with self.assertRaises(ValueError):Service(replace(self.config,authority_class='official'))
    def test_concurrent_signup_does_not_overwrite(self):
        data=[{'username':'alice','password':PASSWORD},{'username':'alice','password':'a different sufficiently long password'}]
        results=[]
        def work(d):
            try:results.append(('ok',self.s.account(d)))
            except Exception as e:results.append(('error',getattr(e,'status',None)))
        ts=[threading.Thread(target=work,args=(d,)) for d in data]
        for t in ts:t.start()
        for t in ts:t.join()
        self.assertEqual(sum(r[0]=='ok' for r in results),1)
        self.assertEqual(sum(r==('error',401) for r in results),1)
if __name__=='__main__':unittest.main(verbosity=2)
