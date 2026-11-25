"""Subject-keyed personal settings and delegated administration for WebOS."""

import argparse
import base64
import binascii
import hashlib
import re
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path

from argon2.exceptions import VerifyMismatchError

from .policy_service import (
    PASSWORD_WAIT_SECONDS,
    private_database,
    valid_password,
    validate_stored_hash,
)
from .service import Failure

MAIL = ("mailbox", "send_local", "receive_external", "send_external")
PERMISSIONS = (
    "users.read",
    "users.suspend",
    "users.reset",
    "mail.manage",
    "retention.manage",
)
RESERVED = [
    "admin",
    "administrator",
    "root",
    "owner",
    "system",
    "sysadmin",
    "test",
    "mail",
    "mailops",
    "mail-ops",
    "postmaster",
    "abuse",
    "dmarc",
    "noreply",
    "no-reply",
    "mailerdaemon",
    "support",
    "help",
    "security",
    "billing",
    "accounts",
    "wallet",
    "webmaster",
]
SCHEMA = (
    "CREATE TABLE am_role (name TEXT PRIMARY KEY NOT NULL)",
    "CREATE TABLE am_permission (name TEXT PRIMARY KEY NOT NULL)",
    "CREATE TABLE am_role_permission (role TEXT REFERENCES am_role, permission TEXT REFERENCES am_permission, PRIMARY KEY(role,permission)) WITHOUT ROWID",
    "CREATE TABLE am_membership (subject TEXT REFERENCES accounts(subject) ON DELETE CASCADE, role TEXT REFERENCES am_role, PRIMARY KEY(subject,role)) WITHOUT ROWID",
    "CREATE TABLE am_retained (subject TEXT PRIMARY KEY NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE)",
    "CREATE TABLE am_avatar (subject TEXT PRIMARY KEY NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE, rgba BLOB NOT NULL CHECK(length(rgba)=16384))",
    "CREATE TABLE am_retiring (subject TEXT PRIMARY KEY NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE)",
    "CREATE TABLE am_mail_binding (subject TEXT PRIMARY KEY NOT NULL REFERENCES accounts(subject) ON DELETE RESTRICT, account_id TEXT NOT NULL UNIQUE)",
    "CREATE TABLE am_mail_setting (name TEXT PRIMARY KEY NOT NULL)",
    "CREATE TABLE am_requested_mail (subject TEXT REFERENCES accounts(subject) ON DELETE CASCADE, setting TEXT REFERENCES am_mail_setting, PRIMARY KEY(subject,setting)) WITHOUT ROWID",
    "CREATE TABLE am_reserved (name TEXT PRIMARY KEY NOT NULL COLLATE NOCASE)",
    "CREATE TABLE am_reset_code (subject TEXT PRIMARY KEY NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE, digest BLOB NOT NULL UNIQUE, expires INTEGER NOT NULL, generation INTEGER NOT NULL)",
    "CREATE TABLE am_audit (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, target TEXT, operation TEXT NOT NULL, outcome TEXT NOT NULL)",
    "CREATE TABLE am_version (version INTEGER PRIMARY KEY CHECK(version=1))",
    """CREATE TRIGGER am_receive_defaults AFTER INSERT ON accounts
       BEGIN INSERT INTO am_requested_mail VALUES(NEW.subject,'mailbox');
             INSERT INTO am_requested_mail VALUES(NEW.subject,'receive_external'); END""",
    """CREATE TRIGGER am_reserve_name BEFORE INSERT ON accounts
       WHEN EXISTS (SELECT 1 FROM am_reserved WHERE name=NEW.username)
       BEGIN SELECT RAISE(ABORT,'reserved WebOS username'); END""",
)
MAIL_PROJECTION_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS am_mail_projected "
    "(subject TEXT PRIMARY KEY NOT NULL REFERENCES am_mail_binding(subject) ON DELETE CASCADE)",
    "CREATE TABLE IF NOT EXISTS am_applied_mail "
    "(subject TEXT NOT NULL REFERENCES am_mail_projected(subject) ON DELETE CASCADE, "
    "setting TEXT NOT NULL REFERENCES am_mail_setting(name), PRIMARY KEY(subject,setting)) WITHOUT ROWID",
)
MAIL_PROJECTION_TABLES = {"am_mail_projected", "am_applied_mail"}

TABLES = {
    statement.split()[2] for statement in SCHEMA if statement.startswith("CREATE TABLE")
}


class ManagementError(ValueError):
    pass


@contextmanager
def transaction(path, write=True):
    with closing(
        sqlite3.connect(
            Path(path).resolve(strict=True).as_uri() + "?mode=rw", uri=True, timeout=3
        )
    ) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        with db:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db


def migrate_mail_projection(db):
    """Add readback tables without changing existing requested grants."""
    for statement in MAIL_PROJECTION_SCHEMA:
        db.execute(statement)


def audit(db, actor, target, action, outcome="ok"):
    db.execute(
        "INSERT INTO am_audit(at,actor,target,operation,outcome) VALUES(?,?,?,?,?)",
        (int(time.time()), actor, target, action, outcome),
    )


def migrate(path, owner, retained=(), pilots=()):
    """Bootstrap by verified subject. Re-running never reinstates a revoked grant."""
    with transaction(path) as db:
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='am_version'").fetchone():
            if not db.execute("SELECT 1 FROM am_version WHERE version=1").fetchone():
                raise ManagementError("Unknown management schema")
            return
        for subject in {owner, *retained, *pilots}:
            if not db.execute(
                "SELECT 1 FROM accounts JOIN account_policy USING(subject) WHERE subject=? AND disabled=0",
                (subject,),
            ).fetchone():
                raise ManagementError(
                    "Verify each existing bootstrap subject before migration"
                )
        for statement in SCHEMA:
            db.execute(statement)
        db.execute("INSERT INTO am_version VALUES(1)")
        db.executemany(
            "INSERT INTO am_role VALUES(?)", [("administrator",), ("moderator",)]
        )
        db.executemany(
            "INSERT INTO am_permission VALUES(?)", [(p,) for p in PERMISSIONS]
        )
        db.executemany(
            "INSERT INTO am_role_permission VALUES('administrator',?)",
            [(p,) for p in PERMISSIONS],
        )
        db.execute("INSERT INTO am_role_permission VALUES('moderator','users.read')")
        db.executemany(
            "INSERT INTO am_membership VALUES(?,?)",
            [(owner, "administrator"), (owner, "moderator")],
        )
        db.executemany(
            "INSERT INTO am_retained VALUES(?)", [(s,) for s in {owner, *retained}]
        )
        db.executemany("INSERT INTO am_mail_setting VALUES(?)", [(s,) for s in MAIL])
        db.execute(
            "INSERT INTO am_requested_mail SELECT subject, name FROM accounts CROSS JOIN am_mail_setting WHERE name IN ('mailbox','receive_external')"
        )
        db.executemany(
            "INSERT OR IGNORE INTO am_requested_mail VALUES(?,?)",
            [(sub, setting) for sub in set(pilots) for setting in MAIL],
        )
        db.executemany(
            "INSERT INTO am_reserved VALUES(?)", [(name,) for name in RESERVED]
        )
        audit(db, "operator", owner, "bootstrap")


def permissions(db, subject):
    return {
        r[0]
        for r in db.execute(
            """SELECT DISTINCT permission FROM am_membership
            JOIN am_role_permission USING(role) WHERE subject=?""",
            (subject,),
        )
    }


def account(db, subject):
    row = db.execute(
        "SELECT username, subject, disabled, generation FROM accounts JOIN account_policy USING(subject) WHERE subject=?",
        (subject,),
    ).fetchone()
    if row is None:
        raise ManagementError("Account is unavailable")
    return row


def change_password(db, subject, encoded):
    validate_stored_hash(encoded)
    db.execute(
        "UPDATE accounts SET password_hash=? WHERE subject=?", (encoded, subject)
    )
    revoke_sessions(db, subject)


def revoke_sessions(db, subject):
    db.execute(
        "UPDATE account_policy SET generation=generation+1 WHERE subject=?", (subject,)
    )
    db.execute(
        "DELETE FROM registered_sessions WHERE json_extract(record,'$.sub')=?",
        (subject,),
    )
    db.execute("DELETE FROM am_reset_code WHERE subject=?", (subject,))


def require_password(value):
    if not valid_password(value):
        raise ManagementError("Use 4–32 characters without control characters")


class AccountManagement:
    def __init__(self, issuer, chat=None, mail=None):
        self.issuer = issuer
        self.path = issuer.db
        self.chat = chat
        self.mail = mail

    @contextmanager
    def password_slot(self):
        if not self.issuer.password_admissions.acquire(blocking=False):
            raise ManagementError("Password service busy. Try again shortly.")
        try:
            if not self.issuer.hash_slots.acquire(timeout=PASSWORD_WAIT_SECONDS):
                raise ManagementError("Password service busy. Try again shortly.")
            try:
                yield
            finally:
                self.issuer.hash_slots.release()
        finally:
            self.issuer.password_admissions.release()

    def authorize(self, db, principal):
        if principal.kind != "registered" or principal.deadline <= self.issuer.now():
            raise ManagementError("Sign in to use Account Management")
        row = db.execute(
            """SELECT 1 FROM registered_sessions s JOIN accounts a ON a.subject=?
            JOIN account_policy p ON p.subject=a.subject WHERE s.deadline>?
            AND json_extract(s.record,'$.sub')=a.subject AND json_extract(s.record,'$.name')=a.username
            AND json_extract(s.record,'$.sid')=? AND json_extract(s.record,'$.kind')='registered'
            AND json_extract(s.record,'$._account_generation')=p.generation AND p.disabled=0""",
            (principal.sub, self.issuer.now(), principal.sid),
        ).fetchone()
        if row is None:
            raise ManagementError("Session ended. Sign in again.")

    def self_view(self, db, subject):
        user = account(db, subject)
        avatar = db.execute(
            "SELECT rgba FROM am_avatar WHERE subject=?", (subject,)
        ).fetchone()
        name = user["username"]
        if self.chat:
            with self.chat.connection() as chatdb:
                person = chatdb.execute(
                    "SELECT display_name FROM people WHERE subject=?", (subject,)
                ).fetchone()
                if person:
                    name = person[0]
        return {
            "subject": subject,
            "username": user["username"],
            "displayName": name,
            "canEditName": bool(self.chat),
            "avatar": base64.b64encode(avatar[0]).decode() if avatar else None,
            "permissions": sorted(permissions(db, subject)),
        }

    def target_view(self, db, target):
        user = account(db, target)
        value = {
            "subject": target,
            "username": user["username"],
            "suspended": bool(user["disabled"]),
            "retained": bool(
                db.execute(
                    "SELECT 1 FROM am_retained WHERE subject=?", (target,)
                ).fetchone()
            ),
            "requestedMail": [
                r[0]
                for r in db.execute(
                    "SELECT setting FROM am_requested_mail WHERE subject=? ORDER BY setting",
                    (target,),
                )
            ],
        }

        if self.mail:
            value.update(self.mail.view(db, target))
        return value

    def dispatch(self, principal, req):
        op = req.get("operation")
        fields = {
            "self": (),
            "display-name": ("name",),
            "avatar": ("rgba",),
            "password": ("current", "password"),
            "search": ("query",),
            "inspect": ("target",),
            "suspend": ("target", "enabled"),
            "retention": ("target", "enabled"),
            "mail": ("target", "setting", "enabled"),
            "issue-reset": ("target",),
        }
        if (
            not isinstance(op, str)
            or op not in fields
            or set(req) != {"resource", "operation", *fields[op]}
        ):
            raise ManagementError("Unknown account operation")
        target = req.get("target", principal.sub)
        if not isinstance(target, str) or len(target) > 80:
            raise ManagementError("Invalid account")
        # Chat is already the canonical display name store and checks this same live session.
        if op == "display-name":
            with transaction(self.path, False) as db:
                self.authorize(db, principal)
            if not self.chat:
                raise ManagementError("Shared profile is unavailable")
            self.chat.dispatch(
                principal,
                {"resource": "chat", "operation": "display-name", "name": req["name"]},
            )
            return {"saved": True}
        if op == "password":
            try:
                self.issuer.throttle("change-password:" + principal.sub, limit=8)
            except Failure:
                raise ManagementError(
                    "Too many password changes. Try again later."
                ) from None
        denied = None
        with (
            self.password_slot() if op == "password" else nullcontext(),
            transaction(self.path, op not in ("self", "search", "inspect")) as db,
        ):
            self.authorize(db, principal)
            needed = {
                "search": "users.read",
                "inspect": "users.read",
                "suspend": "users.suspend",
                "issue-reset": "users.reset",
                "retention": "retention.manage",
                "mail": "mail.manage",
            }.get(op)
            if needed and needed not in permissions(db, principal.sub):
                denied = "Permission denied"
            elif (
                "target" in req
                and op not in ("inspect",)
                and permissions(db, target)
                and target != principal.sub
            ):
                denied = "Privileged targets require a local operator"
            elif (
                op in ("suspend", "issue-reset", "mail", "retention")
                and db.execute(
                    "SELECT 1 FROM am_retiring WHERE subject=?", (target,)
                ).fetchone()
            ):
                denied = "Account cleanup is in progress"
            elif op in ("suspend", "issue-reset") and target == principal.sub:
                denied = "Use personal password controls for your own account"
            elif (
                op == "retention"
                and req["enabled"] is False
                and permissions(db, target)
            ):
                denied = "Privileged accounts must be retained"
            if denied:
                audit(db, principal.sub, target, op, "denied")
            elif op == "self":
                return self.self_view(db, principal.sub)
            elif op == "search":
                query = req["query"]
                if not isinstance(query, str) or not 1 <= len(query.strip()) <= 28:
                    raise ManagementError("Enter part of a username")
                rows = db.execute(
                    "SELECT username,subject FROM accounts WHERE instr(username,?)>0 ORDER BY username LIMIT 30",
                    (query.strip().lower(),),
                )
                return {"users": [dict(row) for row in rows]}
            elif op == "inspect":
                return self.target_view(db, target)
            elif op == "avatar":
                value = req["rgba"]
                if value is None:
                    db.execute("DELETE FROM am_avatar WHERE subject=?", (target,))
                else:
                    if not isinstance(value, str) or len(value) != 21848:
                        raise ManagementError("Invalid 64 × 64 avatar")
                    try:
                        pixels = base64.b64decode(value, validate=True)
                    except (ValueError, binascii.Error):
                        raise ManagementError("Invalid avatar") from None
                    if len(pixels) != 16384:
                        raise ManagementError("Invalid avatar size")
                    db.execute(
                        "INSERT INTO am_avatar VALUES(?,?) ON CONFLICT(subject) DO UPDATE SET rgba=excluded.rgba",
                        (target, pixels),
                    )
                audit(db, principal.sub, target, op)
                return {"saved": True}
            elif op == "password":
                require_password(req["password"])
                if not valid_password(req["current"], maximum=128):
                    raise ManagementError("Current password is incorrect")
                encoded = db.execute(
                    "SELECT password_hash FROM accounts WHERE subject=?", (target,)
                ).fetchone()[0]
                validate_stored_hash(encoded)
                try:
                    self.issuer.passwords.verify(encoded, req["current"])
                except VerifyMismatchError:
                    raise ManagementError("Current password is incorrect") from None
                change_password(db, target, self.issuer.passwords.hash(req["password"]))
                audit(db, principal.sub, target, op)
                return {"signInAgain": True}
            else:
                user = account(db, target)
                if op == "issue-reset":
                    if user["disabled"]:
                        raise ManagementError("Restore sign-in before issuing a reset")
                    token = secrets.token_urlsafe(32)
                    expiry = self.issuer.now() + 900
                    db.execute(
                        """INSERT INTO am_reset_code VALUES(?,?,?,?) ON CONFLICT(subject) DO UPDATE
                        SET digest=excluded.digest, expires=excluded.expires,generation=excluded.generation""",
                        (
                            target,
                            hashlib.sha256(token.encode()).digest(),
                            expiry,
                            user["generation"],
                        ),
                    )
                    audit(db, principal.sub, target, op)
                    return {"code": token, "expires": expiry}
                enabled = req["enabled"]
                if type(enabled) is not bool:
                    raise ManagementError("Choose on or off")
                if op == "suspend" and bool(user["disabled"]) != enabled:
                    db.execute(
                        "UPDATE account_policy SET disabled=? WHERE subject=?",
                        (enabled, target),
                    )
                    revoke_sessions(db, target)
                if op == "retention":
                    if enabled:
                        db.execute(
                            "INSERT OR IGNORE INTO am_retained VALUES(?)", (target,)
                        )
                    else:
                        db.execute("DELETE FROM am_retained WHERE subject=?", (target,))
                if op == "mail":
                    setting = req["setting"]
                    if setting not in MAIL:
                        raise ManagementError("Unknown mail setting")
                    if enabled:
                        db.execute(
                            "INSERT OR IGNORE INTO am_requested_mail VALUES(?,?)",
                            (target, setting),
                        )
                    else:
                        db.execute(
                            "DELETE FROM am_requested_mail WHERE subject=? AND setting=?",
                            (target, setting),
                        )
                audit(
                    db,
                    principal.sub,
                    target,
                    op
                    + (":" + req["setting"] if op == "mail" else "")
                    + (" on" if enabled else " off"),
                )
                return self.target_view(db, target)
        raise ManagementError(denied)

    def redeem(self, code, password):
        require_password(password)
        if not isinstance(code, str) or not re.fullmatch("[A-Za-z0-9_-]{43}", code):
            raise ManagementError("Invalid or expired reset code")
        # Check the high-entropy ticket before occupying an Argon2 slot.
        digest = hashlib.sha256(code.encode()).digest()
        with transaction(self.path, False) as db:
            if not db.execute(
                "SELECT 1 FROM am_reset_code WHERE digest=? AND expires>?",
                (digest, self.issuer.now()),
            ).fetchone():
                raise ManagementError("Invalid or expired reset code")
        with self.password_slot(), transaction(self.path) as db:
            row = db.execute(
                """SELECT r.subject FROM am_reset_code r JOIN account_policy p USING(subject)
                WHERE digest=? AND expires>? AND r.generation=p.generation AND p.disabled=0""",
                (digest, self.issuer.now()),
            ).fetchone()
            if not row:
                raise ManagementError("Invalid or expired reset code")
            change_password(db, row[0], self.issuer.passwords.hash(password))
            audit(db, row[0], row[0], "redeem-reset")
        return {"signInAgain": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path, help="Private issuer state directory")
    commands = parser.add_subparsers(dest="operation", required=True)
    init = commands.add_parser("migrate")
    init.add_argument("--owner", required=True, help="Verified existing subject")
    init.add_argument("--retain", action="append", default=[])
    init.add_argument("--pilot", action="append", default=[])
    role = commands.add_parser("role")
    role.add_argument("action", choices=["grant", "revoke"])
    role.add_argument("subject")
    role.add_argument("role", choices=["administrator", "moderator"])
    args = parser.parse_args()
    dbpath = private_database(args.state)
    if args.operation == "migrate":
        migrate(dbpath, args.owner, args.retain, args.pilot)
        return
    with transaction(dbpath) as db:
        user = account(db, args.subject)
        if user["disabled"]:
            raise ManagementError("Select an active account")
        if db.execute(
            "SELECT 1 FROM am_retiring WHERE subject=?", (args.subject,)
        ).fetchone():
            raise ManagementError("Account cleanup is in progress")
        if args.action == "grant":
            db.execute(
                "INSERT OR IGNORE INTO am_membership VALUES(?,?)",
                (args.subject, args.role),
            )
            db.execute("INSERT OR IGNORE INTO am_retained VALUES(?)", (args.subject,))
        else:
            if (
                args.role == "administrator"
                and not db.execute(
                    """SELECT 1 FROM am_membership JOIN account_policy USING(subject)
                    WHERE role='administrator' AND subject<>? AND disabled=0""",
                    (args.subject,),
                ).fetchone()
            ):
                raise ManagementError("Assign another active administrator first")
            db.execute(
                "DELETE FROM am_membership WHERE subject=? AND role=?",
                (args.subject, args.role),
            )
        audit(db, "operator", args.subject, args.action + " " + args.role)


if __name__ == "__main__":
    main()
