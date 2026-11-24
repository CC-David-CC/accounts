import base64
import json
import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from webos_accounts import AccountsService, Config
from webos_accounts.management import (
    AccountManagement,
    ManagementError,
    migrate,
    transaction,
)


class AccountManagementTests(unittest.TestCase):
    def setUp(self):
        private = tempfile.TemporaryDirectory()
        self.addCleanup(private.cleanup)
        root = Path(private.name)
        for directory in ("identity", "public"):
            (root / directory).mkdir(mode=0o700)
        (root / "public" / "index.html").write_text("Fixture")
        self.issuer = AccountsService(Config(root / "identity", root / "public"))
        self.service = AccountManagement(self.issuer)
        self.password = secrets.token_urlsafe(18)
        self.admin = self.register("initialperson")
        self.member = self.register("ordinaryperson")
        migrate(self.issuer.db, self.admin.sub)
        self.mod = self.register("otherperson")
        with transaction(self.issuer.db) as db:
            db.execute(
                "INSERT INTO am_membership VALUES(?,'moderator')", (self.mod.sub,)
            )

    def register(self, username):
        subject, _, generation = self.issuer.account(
            {"username": username, "password": self.password, "operation": "register"}
        )
        p = SimpleNamespace(
            kind="registered",
            sub=subject,
            sid=secrets.token_hex(16),
            deadline=self.issuer.now() + 3600,
        )
        record = {
            "sub": subject,
            "sid": p.sid,
            "name": username,
            "kind": p.kind,
            "_account_generation": generation,
        }
        with transaction(self.issuer.db) as db:
            db.execute(
                "INSERT INTO registered_sessions VALUES(?,?,?)",
                (secrets.token_hex(24), json.dumps(record), p.deadline),
            )
        return p

    def req(self, principal, op, **fields):
        return self.service.dispatch(
            principal, dict(resource="account-management", operation=op, **fields)
        )

    def test_permissions_defaults_and_repeat_migration(self):
        for user in (self.member, self.mod):
            state = self.req(self.admin, "inspect", target=user.sub)
            self.assertEqual(state["requestedMail"], ["mailbox", "receive_external"])
        self.assertNotIn("users.read", self.req(self.member, "self")["permissions"])
        self.assertEqual(self.req(self.mod, "self")["permissions"], ["users.read"])
        for actor in (self.member, self.mod):
            with self.assertRaises(ManagementError):
                self.req(
                    actor,
                    "mail",
                    setting="send_external",
                    enabled=True,
                    target=self.member.sub,
                )
        self.req(
            self.admin,
            "mail",
            setting="receive_external",
            enabled=False,
            target=self.member.sub,
        )
        migrate(self.issuer.db, self.admin.sub)
        self.assertEqual(
            self.req(self.admin, "inspect", target=self.member.sub)["requestedMail"],
            ["mailbox"],
        )

    def test_single_use_reset_session_revocation_and_avatar(self):
        avatar = base64.b64encode(bytes(64 * 64 * 4)).decode()
        self.req(self.member, "avatar", rgba=avatar)
        self.assertEqual(self.req(self.member, "self")["avatar"], avatar)
        self.assertIsNone(self.req(self.mod, "self")["avatar"])
        with self.assertRaises(ManagementError):
            self.req(self.mod, "issue-reset", target=self.member.sub)
        code = self.req(self.admin, "issue-reset", target=self.member.sub)["code"]
        self.service.redeem(code, "different password")
        with self.assertRaises(ManagementError):
            self.service.redeem(code, "second password")
        with self.assertRaises(ManagementError):
            self.req(self.member, "self")
        self.assertEqual(
            self.issuer.account(
                {
                    "username": "ordinaryperson",
                    "password": "different password",
                    "operation": "signin",
                }
            )[0],
            self.member.sub,
        )

    def test_own_password_and_reserved_registration(self):
        with self.assertRaises(ManagementError):
            self.req(
                self.member,
                "password",
                current="incorrect",
                password="safe new password",
            )
        self.req(
            self.member, "password", current=self.password, password="safe new password"
        )
        with self.assertRaises(ManagementError):
            self.req(self.member, "self")
        import sqlite3

        with self.assertRaises(sqlite3.IntegrityError):
            self.register("wallet")
