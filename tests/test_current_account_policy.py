"""Current public policy checks, separate from frozen identity-core regressions."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from webos_accounts import AccountsService, Config, Failure
from webos_accounts.policy_service import ISSUER_PEER_REQUESTS_PER_MINUTE
from webos_accounts.service import Service as ReferenceService
import test_reference_service as reference_tests


class CurrentAccountPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        root = Path(self.fixture.name)
        public = root / 'public'
        public.mkdir()
        (public / 'index.html').write_text('synthetic policy fixture')
        self.config = Config(root / 'state', public)
        self.service = AccountsService(self.config)

    def test_current_registration_bounds_and_legacy_long_password_signin(self):
        self.service.account({'operation': 'register', 'username': 'shortfixture', 'password': 'four'})
        for password in ['abc', 'x' * 33]:
            with self.assertRaises(Failure) as caught:
                self.service.account({'operation': 'register', 'username': 'invalidfixture', 'password': password})
            self.assertEqual(caught.exception.status, 400)
        legacy = ReferenceService(self.config)
        subject, _ = legacy.account({'username': 'legacyfixture', 'password': 'x' * 40})
        retained, _, _ = self.service.account({'operation': 'signin', 'username': 'legacyfixture', 'password': 'x' * 40})
        self.assertEqual(retained, subject)

    def test_concurrent_registration_has_one_durable_winner(self):
        second = AccountsService(self.config)
        def register(pair):
            service, password = pair
            try:
                subject, _, _ = service.account({'operation': 'register', 'username': 'racefixture', 'password': password})
                return ('created', subject, password)
            except Failure as failure:
                return ('refused', failure.status, None)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(register, [(self.service, 'first-fixture-password'), (second, 'second-fixture-password')]))
        winners = [result for result in results if result[0] == 'created']
        self.assertEqual(len(winners), 1)
        self.assertEqual([result[1] for result in results if result[0] == 'refused'], [400])
        with closing(sqlite3.connect(self.service.db)) as db:
            rows = db.execute('SELECT subject,password_hash FROM accounts WHERE username=?', ('racefixture',)).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], winners[0][1])
        self.assertTrue(self.service.passwords.verify(rows[0][1], winners[0][2]))

    def test_peer_budget_and_account_budget_remain_independently_bounded(self):
        self.service.c.rate_per_minute = 2
        for _ in range(2):
            self.service.throttle('username:fixture')
        with self.assertRaises(Failure) as caught:
            self.service.throttle('username:fixture')
        self.assertEqual(caught.exception.status, 429)
        for _ in range(ISSUER_PEER_REQUESTS_PER_MINUTE):
            self.service.throttle('ip:127.0.0.1')
        with self.assertRaises(Failure) as caught:
            self.service.throttle('ip:127.0.0.1')
        self.assertEqual(caught.exception.status, 429)

    def test_registered_session_survives_restart_and_logout_remains_final(self):
        # Reuse the original wire fixture against the public service without
        # inheriting its historical policy expectations as new policy tests.
        fixture = reference_tests.ServiceTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.s = AccountsService(fixture.config, clock=lambda: fixture.t)
        session = fixture.enter('retainedfixture')
        fixture.s = AccountsService(fixture.config, clock=lambda: fixture.t)
        self.assertEqual(fixture.session_request('/api/v1/renew', session)['status'], 200)
        self.assertEqual(fixture.session_request('/api/v1/logout', session)['status'], 200)
        fixture.s = AccountsService(fixture.config, clock=lambda: fixture.t)
        self.assertEqual(fixture.session_request('/api/v1/renew', session)['status'], 401)
