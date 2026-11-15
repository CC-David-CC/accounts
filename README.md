# Accounts

Owns account registration, sign-in, identity proofs and retained session/account policy. Its Python public API is `webos_accounts.AccountsService`, `Config`, `Failure`, and the stateless `jose` proof primitives. The development launcher uses that same policy service. Passwords, signing keys and session tokens are never ordinary inspection data.

The baseline preserves the existing Codi issuer implementation and account-policy history. The new package retains subject IDs, Argon2 records, signing-key/database coupling and session formats. Discovery no longer advertises a guest VM or peer transport. This is a development authority, not an authorized production deployment or a replacement production identity system.

Install into a separate development environment with `uv pip install -e .`. Run `python -m unittest discover -s tests -v` there. Four real synthetic-state tests cover retained identity restart, refusal of incomplete retained state, missing-user sign-in without implicit registration, and discovery without guest dependencies or secret fields. They do not establish production-user continuity. The parent also tests real browser authentication and signed file authorization against disposable development state.

The public browser package `@webos/accounts` exposes `createAccountsClient`. Its closure owns credentials; `inspect()` returns public session state. `createFileAuthority()` returns an epoch-bound human file capability that signs one-use request grants without exporting account tokens or private keys. This is not agent delegation. The Python `webos_accounts.file_authority.FileAuthority` issues and verifies the corresponding grants using the public Runtime wire contract. Storage consumes these public interfaces, never private signing keys or session maps. Real account data and credentials must stay outside this repository and public roots. Use only explicit private state directories with the loopback development launcher.

## Scoped delegation core — not enabled in the launcher

`webos_accounts.delegation.Delegations` is an optional Accounts-owned policy core.
It is not mounted by the current server and does not enable a remote agent API.
Its challenge/dispatch methods verify actual signed one-use owner or agent
proofs. Creating a delegation requires a registered owner's current session/key;
the independent agent public key is bound to a fresh secret returned only by
creation. Only its digest is retained. Ordinary owner inspection returns scope,
expiry, IDs and a public-key fingerprint, never tokens or operation grants.

Scopes bind the approving session, exact desktop/window, exact resource IDs and
command names. Resource strings have no wildcard or filesystem-path semantics.
Operation grants bind the exact intent bytes and expire within30 seconds. The
approving owner session must consume a grant exactly once before dispatch.
Owner logout, persisted session revocation, disabled accounts, password-generation
changes, expiry and explicit revocation are rechecked. Delegations/grants are
RAM-only and become unavailable when this core restarts; registered account
identity and file ownership are unchanged.

Consumers must enforce the returned scope against **actual component resource
metadata**, not merely the resources declared by an agent. Returned actor fields
are metadata, not caller credentials. A browser integration needs an unforgeable
invocation context bound to the admitted intent and current account epoch.
No HTTP adapter, owner-consent UI, authenticated agent transport or agent file
authority is installed here. Any future adapter must enforce origin/method,
bounded bodies and admission budgets. User-presence steps stay user-controlled.

These operation grants have a distinct type/audience and are rejected as
file-gateway confirmations. Never use the existing human file authority to
silently perform an agent's file operation. That integration and its server
ownership/provenance tests remain required before enabling agents.

Run `python -m unittest discover -s tests -v` in the component backend environment.
The delegation tests use real generated signing keys and synthetic retained
account state, including concurrent consumption and existing account-policy
revocation. They do not qualify end-to-end agent operation of the desktop.
