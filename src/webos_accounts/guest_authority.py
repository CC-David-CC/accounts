"""Issue a short-lived network grant for an explicitly authorized account."""

import re
import secrets
from urllib.parse import urlsplit

from . import jose
from .service import Failure


CHALLENGE = '/api/v1/guest-network/challenge'
AUTHORIZE = '/api/v1/guest-network/authorize'
GRANT_TYPE = 'codi-guest-network-identity+jwt'
LIFETIME = 30


def connection_identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value) or len(jose.unb64(value)) != 32:
        raise Failure(400, 'A canonical guest connection identifier is required')
    return value


class GuestAuthority:
    """Optional Accounts middleware using the installed guest policy and live session verifier."""

    def __init__(self, issuer, *, policy_sha256, allowed_until, application=None):
        if not isinstance(policy_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', policy_sha256) or not callable(allowed_until):
            raise ValueError('A pinned guest policy and account eligibility check are required')
        self.issuer = issuer
        self.application = issuer if application is None else application
        self.policy_sha256 = policy_sha256
        self.allowed_until = allowed_until
        self.authorize_path = issuer.base_path + AUTHORIZE
        self.audience = issuer.c.origin + issuer.base_path + '/guest-network'

    def challenge(self, data):
        issuer = self.issuer
        if set(data) != {'key', 'path'} or data['path'] != self.authorize_path:
            raise Failure(400, 'Invalid guest-network authorization challenge')
        key = jose.public_jwk(jose.load_public(data['key']))
        with issuer.lock:
            issuer.cleanup()
            if len(issuer.challenges) >= issuer.c.max_challenges:
                raise Failure(429, 'Challenge capacity reached')
            nonce = secrets.token_urlsafe(32)
            expires = issuer.now() + 60
            issuer.challenges[nonce] = {'key': key, 'path': self.authorize_path, 'expires': expires}
        return {'nonce': nonce, 'expires_at': expires}

    def authorize(self, data, key, proof, authorization):
        if set(data) != {'nonce', 'connection_id', 'policy_sha256'}:
            raise Failure(400, 'Exact guest wire authorization context required')
        nonce = connection_identifier(data['nonce'])
        connection = connection_identifier(data['connection_id'])
        if data['policy_sha256'] != self.policy_sha256:
            raise Failure(403, 'Guest egress policy changed')
        issuer = self.issuer
        with issuer.lock:
            checked = issuer.continue_session({}, key, proof, '/api/v1/renew', authorization)
            identity = checked['identity']
            now = issuer.now()
            allowed = self.allowed_until(identity['sub'], now) if identity['kind'] == 'registered' else None
            if type(allowed) is not int or allowed <= now:
                raise Failure(403, 'Guest networking is unavailable to this account')
            session = issuer.sessions[jose.digest(authorization[5:])]
            expiry = min(now + LIFETIME, allowed, checked['expires_at'], session['deadline'])
            if expiry <= now:
                raise Failure(401, 'Session expired')
            claims = {
                'v': 1, 'iss': issuer.c.origin, 'aud': self.audience, 'sub': identity['sub'],
                'sid': identity['sid'], 'kind': 'registered', 'cnf': {'jwk': identity['key']},
                'iat': now, 'exp': expiry, 'jti': secrets.token_urlsafe(32),
                'nonce': nonce, 'connection_id': connection, 'policy_sha256': self.policy_sha256,
                'session_deadline': session['deadline'],
            }
            return {'grant': jose.sign(claims, issuer.key, GRANT_TYPE, issuer.kid), 'expires_at': expiry}

    def __call__(self, env, start):
        issuer = self.issuer
        path = env.get('PATH_INFO', '/')
        if path not in (CHALLENGE, AUTHORIZE):
            return self.application(env, start)
        try:
            if env.get('HTTP_HOST') != urlsplit(issuer.c.origin).netloc or env.get('HTTP_ORIGIN') != issuer.c.origin:
                raise Failure(403, 'Unexpected guest authorization origin')
            if env.get('REQUEST_METHOD') != 'POST':
                raise Failure(405, 'POST required')
            if env.get('CONTENT_TYPE', '').split(';')[0].strip() != 'application/json':
                raise Failure(415, 'JSON required')
            if env.get('QUERY_STRING') or env.get('HTTP_TRANSFER_ENCODING') or env.get('HTTP_CONTENT_ENCODING'):
                raise Failure(400, 'Unexpected query or encoding')
            length = env.get('CONTENT_LENGTH', '')
            if not length.isascii() or not length.isdecimal() or len(length) > 5 or not 0 < int(length) <= 16384:
                raise Failure(413, 'Bounded guest authorization request required')
            phase = 'challenge' if path == CHALLENGE else 'authorize'
            issuer.throttle('guest-' + phase + '-ip:' + env.get('REMOTE_ADDR', 'unknown'))
            issuer.throttle('guest-' + phase + '-global', limit=10 * issuer.c.rate_per_minute)
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
                result = self.authorize(body, key, proof, env.get('HTTP_AUTHORIZATION', ''))
            return issuer.json_response(start, 200, result)
        except Failure as error:
            return issuer.json_response(start, error.status, {'error': error.message})
        except (ValueError, TypeError, KeyError):
            return issuer.json_response(start, 400, {'error': 'Invalid guest-network authorization request'})
