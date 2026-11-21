import io
import secrets
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ec

from webos_accounts import AccountsService, Config, jose
from webos_accounts.guest_authority import AUTHORIZE, CHALLENGE, GRANT_TYPE, STATUS, GuestAuthority
from webos_accounts.service import PROOF_TYPE


class GuestAuthorityTest(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        root = Path(directory)
        public = root / 'public'
        public.mkdir()
        (public / 'index.html').write_text('Synthetic account issuer fixture')
        self.now = 2000000000
        self.issuer = AccountsService(Config(root / 'state', public), base_path='/preview', clock=lambda: self.now)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public = jose.public_jwk(self.key)
        self.policy = 'a' * 64
        self.grants = {}
        self.transport = GuestAuthority(
            self.issuer, policy_sha256=self.policy, allowed_until=lambda subject, now: self.grants.get(subject),
        )

    def enter(self, name=None):
        if name is None:
            return self.issuer.enter({}, self.public, '/api/v1/anonymous')
        data = {'operation': 'register', 'username': name, 'password': secrets.token_urlsafe(18)}
        return self.issuer.enter(data, self.public, '/api/v1/auth')

    def request(self, path, data, **headers):
        body = jose.dumps(data).encode()
        origin = self.issuer.c.origin
        env = {
            'REQUEST_METHOD': 'POST', 'PATH_INFO': path, 'HTTP_HOST': urlsplit(origin).netloc,
            'HTTP_ORIGIN': origin, 'CONTENT_TYPE': 'application/json', 'CONTENT_LENGTH': str(len(body)),
            'REMOTE_ADDR': '127.0.0.1', 'wsgi.input': io.BytesIO(body), **headers,
        }
        result = {}

        def start(status, fields):
            result['status'] = int(status.split()[0])
            self.assertEqual(dict(fields)['Cache-Control'], 'no-store')

        value = jose.loads(b''.join(self.transport(env, start)))
        return result['status'], value

    def envelope(self, session, data, key=None, endpoint=AUTHORIZE):
        key = key or self.key
        path = self.issuer.base_path + endpoint
        status, challenge = self.request(CHALLENGE, {'path': path, 'key': jose.public_jwk(key)})
        self.assertEqual(status, 200)
        body = jose.dumps(data)
        proof = {
            'v': 1, 'nonce': challenge['nonce'], 'iss': session['identity']['sid'],
            'aud': self.issuer.c.origin, 'method': 'POST', 'path': path, 'iat': self.now,
            'exp': self.now + 60, 'request_sha256': jose.digest(body),
        }
        return {'request': body, 'proof': jose.sign(proof, key, PROOF_TYPE)}

    def wire(self, session, *, policy=None, key=None):
        data = {'nonce': secrets.token_urlsafe(32), 'connection_id': secrets.token_urlsafe(32),
                'policy_sha256': self.policy if policy is None else policy}
        proof = self.envelope(session, data, key)
        auth = 'Codi ' + session['session_token']
        return data, proof, auth, self.request(AUTHORIZE, proof, HTTP_AUTHORIZATION=auth)

    def test_grant_binds_the_live_account_connection_and_policy(self):
        session = self.enter('ownerfixture')
        identity = session['identity']
        self.grants[identity['sub']] = self.now + 900
        data, proof, auth, (status, reply) = self.wire(session)
        self.assertEqual(status, 200)
        claims = jose.verify(reply['grant'], self.issuer.jwk, GRANT_TYPE)
        self.assertEqual(claims['sub'], identity['sub'])
        self.assertEqual(claims['sid'], identity['sid'])
        self.assertEqual(claims['cnf']['jwk'], self.public)
        self.assertEqual(claims['aud'], self.issuer.c.origin + '/preview/guest-network')
        self.assertEqual(claims['exp'], self.now + 30)
        self.assertEqual({k: claims[k] for k in data}, data)
        self.assertEqual(self.request(AUTHORIZE, proof, HTTP_AUTHORIZATION=auth)[0], 401)

    def test_test_account_expiry_and_exclusion_of_other_accounts(self):
        dedicated = self.enter('networkfixture')
        ordinary = self.enter('ordinaryfixture')
        anonymous = self.enter()
        self.grants[dedicated['identity']['sub']] = self.now + 8
        self.grants[anonymous['identity']['sub']] = self.now + 8
        _, _, _, (status, reply) = self.wire(dedicated)
        self.assertEqual(status, 200)
        self.assertEqual(reply['expires_at'], self.now + 8)
        self.assertEqual(self.wire(ordinary)[-1][0], 403)
        self.assertEqual(self.wire(anonymous)[-1][0], 403)
        self.now += 8
        self.assertEqual(self.wire(dedicated)[-1][0], 403)

    def test_mismatched_policy_key_origin_and_logged_out_session(self):
        owner = self.enter('ownerfixture')
        identity = owner['identity']
        self.grants[identity['sub']] = self.now + 900
        self.assertEqual(self.wire(owner, policy='b' * 64)[-1][0], 403)
        alien = ec.generate_private_key(ec.SECP256R1())
        self.assertEqual(self.wire(owner, key=alien)[-1][0], 401)
        wrong_origin = self.request(
            CHALLENGE, {'path': self.issuer.base_path + AUTHORIZE, 'key': self.public}, HTTP_ORIGIN='https://other.invalid',
        )
        self.assertEqual(wrong_origin[0], 403)
        self.issuer.continue_session({}, self.public, {'iss': identity['sid']}, '/api/v1/logout',
                                     'Codi ' + owner['session_token'])
        self.assertEqual(self.wire(owner)[-1][0], 401)

    def test_status_binds_a_live_session_and_creates_no_wire_grant(self):
        dedicated = self.enter('networkfixture')
        ordinary = self.enter('ordinaryfixture')
        anonymous = self.enter()
        self.grants[dedicated['identity']['sub']] = self.now + 15
        self.grants[anonymous['identity']['sub']] = self.now + 15
        data = {'policy_sha256': self.policy}

        def check(session):
            proof = self.envelope(session, data, endpoint=STATUS)
            return self.request(STATUS, proof, HTTP_AUTHORIZATION='Codi ' + session['session_token'])

        self.assertEqual(check(dedicated), (200, {'policy_sha256': self.policy, 'expires_at': self.now + 15}))
        self.assertEqual(check(ordinary)[0], 403)
        self.assertEqual(check(anonymous)[0], 403)
        wrong_path = self.envelope(dedicated, data, endpoint=STATUS)
        self.assertEqual(self.request(AUTHORIZE, wrong_path,
                       HTTP_AUTHORIZATION='Codi ' + dedicated['session_token'])[0], 401)
        self.now += 15
        self.assertEqual(check(dedicated)[0], 403)


if __name__ == '__main__':
    unittest.main()
