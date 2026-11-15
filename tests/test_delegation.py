"""Actual signed owner/agent proofs and synthetic account state; no real users."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import secrets
import tempfile
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric import ec
from webos_accounts import AccountsService, Config, Failure, jose
from webos_accounts.delegation import Delegations, CREATE, LIST, REVOKE, AUTHORIZE, CONSUME, GRANT_TYPE
from webos_accounts.policy_service import set_disabled, reset_password
from webos_accounts.service import PROOF_TYPE


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='webos-delegation-test-'); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name); public = root / 'public'; public.mkdir(mode=0o700); (public / 'index.html').write_text('<title>Synthetic</title>')
        self.time = 1800000000
        self.issuer = AccountsService(Config(root / 'state', public, origin='http://127.0.0.1:18993'), clock=lambda: self.time)
        self.owner_key = ec.generate_private_key(ec.SECP256R1()); self.agent_key = ec.generate_private_key(ec.SECP256R1())
        self.username = 'test' + secrets.token_hex(6)
        self.password = secrets.token_urlsafe(16)
        self.owner = self.issuer.enter({'operation': 'register', 'username': self.username, 'password': self.password}, jose.public_jwk(self.owner_key), '/api/v1/auth')
        self.owner_auth = 'Codi ' + self.owner['session_token']; self.sid = self.owner['identity']['sid']
        self.core = Delegations(self.issuer)
        self.instance = str(uuid.uuid4()); self.view = 'view:' + self.instance
        self.scope = {'desktopId': str(uuid.uuid4()), 'sessionId': self.sid, 'instanceId': self.instance,
                      'resources': [self.view, 'Documents/allowed.txt'], 'commands': ['view.inspect', 'inspect', 'replace']}

    def envelope(self, path, data, key, sid, provider=None):
        challenge = (provider or self.core).challenge({'key': jose.public_jwk(key), 'path': self.issuer.base_path + path})
        raw = jose.dumps(data)
        proof = {'v': 1, 'iss': sid, 'aud': self.issuer.c.origin, 'method': 'POST', 'path': self.issuer.base_path + path,
                 'nonce': challenge['nonce'], 'request_sha256': jose.digest(raw), 'iat': self.time, 'exp': self.time + 60}
        return {'request': raw, 'proof': jose.sign(proof, key, PROOF_TYPE)}

    def call(self, path, data, *, key=None, sid=None, authorization=None):
        envelope = self.envelope(path, data, key or self.owner_key, sid or self.sid)
        return self.core.dispatch(path, envelope, self.owner_auth if authorization is None else authorization)

    def create(self, seconds=300):
        return self.call(CREATE, {'agent_key': jose.public_jwk(self.agent_key), 'scope': self.scope, 'seconds': seconds})

    def intent(self, *, command='replace', text='synthetic edit'):
        return jose.dumps({'method': 'application.execute', 'target': {'desktopId': self.scope['desktopId'], 'sessionId': self.sid,
            'instanceId': self.instance, 'resourceId': self.view}, 'resources': [self.view, 'Documents/allowed.txt'],
            'request': {'instanceId': self.instance, 'sessionId': self.sid, 'documentId': 'synthetic-document', 'operation': command, 'args': {'text': text}}})

    def authorize(self, credential, intent):
        return self.call(AUTHORIZE, {'intent': intent}, key=self.agent_key, sid=credential['id'], authorization='Agent ' + credential['agent_token'])

    def consume(self, grant, intent):
        return self.call(CONSUME, {'confirmation': grant['confirmation'], 'intent': intent})

    def test_real_agent_proof_grant_and_one_use_owner_consumption(self):
        credential = self.create(); intent = self.intent(); grant = self.authorize(credential, intent)
        claims = jose.verify(grant['confirmation'], self.issuer.jwk, GRANT_TYPE)
        self.assertEqual(claims['sub'], self.owner['identity']['sub']); self.assertEqual(claims['sid'], self.sid)
        self.assertEqual(claims['cnf']['jwk'], jose.public_jwk(self.agent_key))
        result = self.consume(grant, intent)
        self.assertEqual(result['actor']['kind'], 'agent'); self.assertEqual(result['actor']['id'], credential['id'])
        self.assertEqual(result['intent']['request']['args']['text'], 'synthetic edit')
        with self.assertRaises(Failure): self.consume(grant, intent)

    def test_scope_and_operation_bytes_cannot_be_changed(self):
        credential = self.create()
        for mutate in [lambda v: v['target'].update(instanceId=str(uuid.uuid4())),
                       lambda v: v['target'].update(sessionId=str(uuid.uuid4())),
                       lambda v: v.update(resources=[self.view, 'Documents/forbidden.txt']),
                       lambda v: v['request'].update(operation='delete')]:
            value = jose.loads(self.intent()); mutate(value)
            with self.assertRaises(Failure): self.authorize(credential, jose.dumps(value))
        intent = self.intent(); grant = self.authorize(credential, intent)
        with self.assertRaises(Failure): self.consume(grant, self.intent(text='different bytes'))
        self.assertEqual(self.consume(grant, intent)['actor']['id'], credential['id'])

    def test_agent_key_and_credential_do_not_impersonate_owner(self):
        credential = self.create(); other = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(Failure):
            self.call(AUTHORIZE, {'intent': self.intent()}, key=other, sid=credential['id'], authorization='Agent ' + credential['agent_token'])
        with self.assertRaises(Failure):
            self.call(LIST, {}, key=self.agent_key, sid=credential['id'], authorization='Codi ' + credential['agent_token'])
        with self.assertRaises(Failure):
            self.call(AUTHORIZE, {'intent': self.intent()}, key=self.agent_key, sid=self.sid, authorization='Agent ' + credential['agent_token'])
        with self.assertRaises(Failure):
            self.call(LIST, {}, key=self.agent_key, sid=self.sid)
        with self.assertRaises(Failure):
            self.call(AUTHORIZE, {'intent': self.intent()}, key=self.agent_key, sid=credential['id'], authorization='Agent ' + credential['id'])

    def test_inspection_omits_authentication_credentials_and_owns_scope_copy(self):
        credential = self.create(); self.scope['commands'].append('delete')
        public = self.call(LIST, {})['delegations']; self.assertEqual(len(public), 1)
        self.assertFalse(credential['agent_token'] in jose.dumps(public))
        for field in ('agent_token', 'owner_digest', 'confirmation', 'key'):
            self.assertNotIn(field, public[0])
        self.assertNotIn('delete', public[0]['scope']['commands'])
        with self.assertRaises(Failure): self.authorize(credential, self.intent(command='delete'))

    def test_revocation_and_owner_logout_invalidate_pending_grants(self):
        credential = self.create(); intent = self.intent(); grant = self.authorize(credential, intent)
        self.call(REVOKE, {'id': credential['id']})
        with self.assertRaises(Failure): self.consume(grant, intent)
        with self.assertRaises(Failure): self.authorize(credential, intent)
        credential = self.create(); grant = self.authorize(credential, intent)
        envelope = self.envelope('/api/v1/logout', {}, self.owner_key, self.sid, provider=self.issuer)
        data, key, proof = self.issuer.consume_proof(envelope, '/api/v1/logout')
        self.issuer.continue_session(data, key, proof, '/api/v1/logout', self.owner_auth)
        with self.assertRaises(Failure): self.authorize(credential, intent)
        self.assertFalse(self.core.grants)

    def assert_owner_revoked(self, action):
        credential = self.create(); intent = self.intent(); grant = self.authorize(credential, intent)
        if action == 'disable': set_disabled(self.issuer.c.state_dir, self.username, True)
        elif action == 'password': reset_password(self.issuer.c.state_dir, self.username, secrets.token_urlsafe(16))
        else:
            from webos_accounts.policy_service import connection
            with connection(self.issuer.db) as db: db.execute('DELETE FROM registered_sessions'); db.commit()
        with self.assertRaises(Failure): self.authorize(credential, intent)
        with self.assertRaises(Failure): self.consume(grant, intent)

    def test_disabled_account_is_checked(self):
        self.assert_owner_revoked('disable')

    def test_password_generation_is_checked(self):
        self.assert_owner_revoked('password')

    def test_persisted_session_revocation_is_checked(self):
        self.assert_owner_revoked('session')

    def test_expiry_replay_and_restart_are_refused(self):
        credential = self.create(seconds=2); intent = self.intent(); grant = self.authorize(credential, intent)
        self.time += 2
        with self.assertRaises(Failure): self.authorize(credential, intent)
        with self.assertRaises(Failure): self.consume(grant, intent)
        credential = self.create(); envelope = self.envelope(AUTHORIZE, {'intent': intent}, self.agent_key, credential['id'])
        self.core.dispatch(AUTHORIZE, envelope, 'Agent ' + credential['agent_token'])
        with self.assertRaises(Failure): self.core.dispatch(AUTHORIZE, envelope, 'Agent ' + credential['agent_token'])
        self.core = Delegations(self.issuer)
        with self.assertRaises(Failure): self.authorize(credential, intent)

    def test_same_account_different_session_cannot_consume_another_desktop_grant(self):
        credential = self.create(); intent = self.intent(); grant = self.authorize(credential, intent)
        second_key = ec.generate_private_key(ec.SECP256R1())
        # A new session for the existing subject, using the actual retained policy.
        second = self.issuer.enter({'operation': 'signin', 'username': self.username, 'password': self.password}, jose.public_jwk(second_key), '/api/v1/auth')
        with self.assertRaises(Failure):
            self.call(CONSUME, {'confirmation': grant['confirmation'], 'intent': intent}, key=second_key, sid=second['identity']['sid'], authorization='Codi ' + second['session_token'])
        self.assertEqual(self.consume(grant, intent)['actor']['id'], credential['id'])

    def test_another_account_cannot_inspect_or_revoke_the_owners_delegation(self):
        credential = self.create(); other_key = ec.generate_private_key(ec.SECP256R1())
        other = self.issuer.enter({'operation': 'register', 'username': 'test' + secrets.token_hex(6), 'password': secrets.token_urlsafe(16)}, jose.public_jwk(other_key), '/api/v1/auth')
        options = {'key': other_key, 'sid': other['identity']['sid'], 'authorization': 'Codi ' + other['session_token']}
        self.assertEqual(self.call(LIST, {}, **options)['delegations'], [])
        with self.assertRaises(Failure): self.call(REVOKE, {'id': credential['id']}, **options)
        self.assertEqual(self.consume(self.authorize(credential, self.intent()), self.intent())['actor']['id'], credential['id'])

    def test_concurrent_consumers_cannot_dispatch_the_same_grant_twice(self):
        credential = self.create(); intent = self.intent(); grant = self.authorize(credential, intent)
        envelopes = [self.envelope(CONSUME, {'confirmation': grant['confirmation'], 'intent': intent}, self.owner_key, self.sid) for _ in range(2)]
        def consume(envelope):
            try: self.core.dispatch(CONSUME, envelope, self.owner_auth); return True
            except Failure: return False
        with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(consume, envelopes))
        self.assertEqual(results.count(True), 1); self.assertEqual(results.count(False), 1)

    def test_protocol_separation_and_capacity_limits(self):
        self.core = Delegations(self.issuer, capacity=1, grant_capacity=1)
        credential = self.create()
        with self.assertRaises(Failure): self.create()
        grant = self.authorize(credential, self.intent())
        with self.assertRaises(Failure): self.authorize(credential, self.intent())
        from webos_runtime.file_protocol import CONFIRMATION_TYPE
        with self.assertRaises(jose.Invalid): jose.verify(grant['confirmation'], self.issuer.jwk, CONFIRMATION_TYPE)

    def test_owner_scope_is_exact_and_anonymous_credentials_cannot_delegate(self):
        original = dict(self.scope); self.scope['sessionId'] = str(uuid.uuid4())
        with self.assertRaises(Failure): self.create()
        self.scope = original
        for seconds in (True, 0, 901):
            with self.assertRaises(Failure): self.create(seconds=seconds)
        anonymous_key = ec.generate_private_key(ec.SECP256R1())
        anonymous = self.issuer.enter({}, jose.public_jwk(anonymous_key), '/api/v1/anonymous')
        with self.assertRaises(Failure):
            self.call(CREATE, {'agent_key': jose.public_jwk(self.agent_key), 'scope': self.scope, 'seconds': 60},
                key=anonymous_key, sid=anonymous['identity']['sid'], authorization='Codi ' + anonymous['session_token'])

    def test_resource_strings_have_no_wildcard_semantics(self):
        self.scope['resources'] = [self.view, 'Documents/*']; credential = self.create()
        with self.assertRaises(Failure): self.authorize(credential, self.intent())

    def test_returned_scope_cannot_widen_the_internal_grant(self):
        credential = self.create(); credential['scope']['commands'].append('delete')
        credential['scope']['resources'].append('Documents/forbidden.txt')
        with self.assertRaises(Failure): self.authorize(credential, self.intent(command='delete'))
        self.assertNotIn('delete', self.call(LIST, {})['delegations'][0]['scope']['commands'])

    def test_duplicate_fields_nonfinite_values_and_ambiguous_commands_are_rejected(self):
        credential = self.create()
        intent = self.intent()
        bad = [intent.replace('"method":', '"method":"application.inspect","method":', 1),
               intent.replace('"synthetic edit"', '1e999'),
               intent.replace('"synthetic edit"', '9007199254740993')]
        value = jose.loads(intent); value['request']['command'] = 'delete'; bad.append(jose.dumps(value))
        for raw in bad:
            with self.assertRaises(Failure): self.authorize(credential, raw)


if __name__ == '__main__':
    unittest.main()
