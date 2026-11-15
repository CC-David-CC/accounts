"""Optional issuer middleware confirming live sessions for the file gateway.

No filesystem permissions are assigned here. Normal login/renew/logout routes
remain in the existing issuer. No reference PATHS/global validators are changed.
The native launcher enables this explicitly; it is off by default.
"""
import secrets
from urllib.parse import urlsplit
from . import jose
from .service import Failure
from webos_runtime.file_protocol import AUTHORIZE, CHALLENGE, CONFIRMATION_TYPE, LIFETIME, gateway_context as context, canonical_digest as digest

class FileAuthority:
    def __init__(self, issuer, application=None):
        self.issuer = issuer
        self.application = issuer if application is None else application
        self.audience, _ = context(issuer.c.origin, issuer.base_path)

    def session_bucket(self, authorization):
        """Identify a live in-memory session for admission, never for access.

        The eventual authorization still verifies the one-use signature,
        persisted session, account generation and requested operation.
        Unknown tokens cannot choose another account's rate bucket.
        """
        if not isinstance(authorization,str) or not authorization.startswith('Codi '):
            return None
        token=authorization[5:]
        if not token or len(token)>128:return None
        issuer=self.issuer
        with issuer.lock:
            issuer.cleanup()
            session=issuer.sessions.get(jose.digest(token))
            if not session or session.get('kind')!='registered' or session.get('deadline',0)<=issuer.now():return None
            return session['sub']

    def challenge(self, data):
        issuer = self.issuer
        if not isinstance(data, dict) or set(data) != {'key','path'} or data['path'] != issuer.base_path + AUTHORIZE:
            raise Failure(400, 'Invalid gateway authorization challenge')
        key = jose.public_jwk(jose.load_public(data['key']))
        with issuer.lock:
            issuer.cleanup()
            if len(issuer.challenges) >= issuer.c.max_challenges:
                raise Failure(429, 'Challenge capacity reached')
            nonce = secrets.token_urlsafe(32)
            issuer.challenges[nonce] = {'key':key,'path':data['path'],'expires':issuer.now()+60}
        return {'nonce':nonce,'expires_at':issuer.now()+60}

    def authorize(self, data, key, proof, authorization):
        if not isinstance(data, dict) or set(data) != {'nonce','request_sha256'} or not isinstance(data['nonce'], str) or len(data['nonce']) != 43 or len(jose.unb64(data['nonce'])) != 32:
            raise Failure(400, 'Gateway nonce and request digest required')
        digest(data['request_sha256'])
        issuer = self.issuer
        with issuer.lock:
            # Reuse the actual token/key/SID, expiry, disabled-account and
            # password-generation checks. A detached certificate is insufficient.
            checked = issuer.continue_session({}, key, proof, '/api/v1/renew', authorization)
            identity = checked['identity']
            if identity['kind'] != 'registered':
                raise Failure(403, 'Registered account required for personal storage')
            session = issuer.sessions[jose.digest(authorization[5:])]
            now = issuer.now();expiry = min(now + LIFETIME, checked['expires_at'], session['deadline'])
            if expiry <= now:
                raise Failure(401, 'Session expired')
            claims = {'v':1,'iss':issuer.c.origin,'aud':self.audience,'sub':identity['sub'],
                      'sid':identity['sid'],'kind':identity['kind'],'cnf':{'jwk':identity['key']},
                      'iat':now,'exp':expiry,'jti':secrets.token_urlsafe(32),
                      'nonce':data['nonce'],'request_sha256':data['request_sha256'],
                      'session_deadline':session['deadline']}
            return {'confirmation':jose.sign(claims, issuer.key, CONFIRMATION_TYPE, issuer.kid),'expires_at':expiry}

    def __call__(self, env, start):
        issuer = self.issuer;path = env.get('PATH_INFO','/')
        if path not in (CHALLENGE, AUTHORIZE):
            return self.application(env, start)
        try:
            if env.get('HTTP_HOST') != urlsplit(issuer.c.origin).netloc or env.get('HTTP_ORIGIN') != issuer.c.origin:
                raise Failure(403, 'Unexpected gateway authorization origin')
            if env.get('REQUEST_METHOD') != 'POST':
                raise Failure(405, 'POST required')
            if env.get('CONTENT_TYPE','').split(';')[0].strip() != 'application/json':
                raise Failure(415, 'JSON required')
            if env.get('HTTP_TRANSFER_ENCODING'):
                raise Failure(400, 'Unsupported transfer encoding')
            length = env.get('CONTENT_LENGTH','')
            if not length.isascii() or not length.isdecimal() or len(length) > 5 or not 0 < int(length) <= 16384:
                raise Failure(413, 'Bounded gateway authorization request required')
            # A secret, live registered session selects an account budget;
            # it is admission only, not permission to issue a file grant.
            # Legacy/no-token callers retain a bounded transport budget.
            # A second server-wide cap bounds aggregate work from valid users.
            phase='challenge' if path==CHALLENGE else 'authorize'
            subject=self.session_bucket(env.get('HTTP_AUTHORIZATION',''))
            issuer.throttle(('file-'+phase+'-account:'+subject) if subject else ('file-'+phase+'-legacy:'+env.get('REMOTE_ADDR','unknown')))
            issuer.throttle('file-'+phase+'-global',limit=20*issuer.c.rate_per_minute)
            raw = env['wsgi.input'].read(int(length))
            if len(raw) != int(length):
                raise Failure(400, 'Truncated request')
            envelope = jose.loads(raw)
            if not isinstance(envelope, dict):
                raise Failure(400, 'Object request required')
            if path == CHALLENGE:
                result = self.challenge(envelope)
            else:
                body, key, proof = issuer.consume_proof(envelope, AUTHORIZE)
                result = self.authorize(body, key, proof, env.get('HTTP_AUTHORIZATION',''))
            return issuer.json_response(start, 200, result)
        except Failure as error:
            return issuer.json_response(start, error.status, {'error':error.message})
        except (ValueError, TypeError, KeyError, UnicodeError):
            return issuer.json_response(start, 400, {'error':'Invalid gateway authorization request'})
        except Exception:
            return issuer.json_response(start, 500, {'error':'Gateway authorization unavailable'})
