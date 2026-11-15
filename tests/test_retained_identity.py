"""Real synthetic account-state regressions; no production account data is used."""
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest

from webos_accounts import AccountsService, Config, Failure


class RetainedIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix='webos-account-test-')
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.public = self.root / 'public'
        self.public.mkdir(mode=0o700)
        (self.public / 'index.html').write_text('<!doctype html><title>Isolated test host</title>')
        self.config = Config(self.root / 'identity', self.public, origin='http://127.0.0.1:18993')

    def test_account_subject_password_hash_and_signing_key_survive_restart(self):
        first = AccountsService(self.config)
        name = 'test' + secrets.token_hex(6)
        password = secrets.token_urlsafe(16)
        subject, canonical, generation = first.account({'operation': 'register', 'username': name, 'password': password})
        key_before = (self.config.state_dir / 'issuer.pem').read_bytes()
        with sqlite3.connect(first.db) as db:
            hash_before = db.execute('SELECT password_hash FROM accounts WHERE username=?', (name,)).fetchone()[0]
        resumed = AccountsService(self.config)
        self.assertEqual(resumed.account({'operation': 'signin', 'username': name, 'password': password}),
                         (subject, canonical, generation))
        self.assertEqual(resumed.kid, first.kid)
        self.assertEqual((self.config.state_dir / 'issuer.pem').read_bytes(), key_before)
        with sqlite3.connect(resumed.db) as db:
            self.assertEqual(db.execute('SELECT subject,password_hash FROM accounts WHERE username=?', (name,)).fetchone(),
                             (subject, hash_before))

    def test_signin_of_unknown_name_does_not_create_an_account(self):
        service = AccountsService(self.config)
        with self.assertRaises(Failure) as result:
            service.account({'operation': 'signin', 'username': 'test' + secrets.token_hex(6),
                             'password': secrets.token_urlsafe(16)})
        self.assertEqual(result.exception.status, 401)
        with sqlite3.connect(service.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM accounts').fetchone()[0], 0)

    def test_incomplete_retained_identity_is_refused_without_reinitializing(self):
        AccountsService(self.config)
        # Model an incomplete restored identity in a second, disposable directory.
        partial = self.root / 'partial'
        partial.mkdir(mode=0o700)
        key = partial / 'issuer.pem'
        key.write_bytes((self.config.state_dir / 'issuer.pem').read_bytes())
        key.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'identity state incomplete'):
            AccountsService(Config(partial, self.public, origin=self.config.origin))
        self.assertFalse((partial / 'accounts.sqlite3').exists())
        self.assertEqual(key.read_bytes(), (self.config.state_dir / 'issuer.pem').read_bytes())

    def test_discovery_has_no_guest_dependency_or_authentication_secret(self):
        service = AccountsService(self.config)
        config = service.config()
        self.assertNotIn('vm', config)
        self.assertNotIn('rtc', config)
        self.assertEqual(config['accounts']['actions'], ['register', 'signin'])
        encoded = json.dumps(config)
        for forbidden in ('PRIVATE KEY', 'password_hash', 'session_token'):
            self.assertNotIn(forbidden, encoded)


if __name__ == '__main__':
    unittest.main()
