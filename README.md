# Accounts

Owns account registration, sign-in, identity proofs and retained session/account policy. Its Python public API is `webos_accounts.AccountsService`, `Config`, `Failure`, and the stateless `jose` proof primitives. The development launcher uses that same policy service. Passwords, signing keys and session tokens are never ordinary inspection data.

The baseline preserves the existing Codi issuer implementation and account-policy history. The new package retains subject IDs, Argon2 records, signing-key/database coupling and session formats. Discovery no longer advertises a guest VM or peer transport. This is a development authority, not an authorized production deployment or a replacement production identity system.

Install into a separate development environment with `uv pip install -e .`. Run `python -m unittest discover -s tests -v` there. Four real synthetic-state tests cover retained identity restart, refusal of incomplete retained state, missing-user sign-in without implicit registration, and discovery without guest dependencies or secret fields. They do not establish production-user continuity. The parent also tests real browser authentication and signed file authorization against disposable development state.

The public browser package `@webos/accounts` exposes `createAccountsClient`. Its closure owns credentials; `inspect()` returns public session state. `createFileAuthority()` returns an epoch-bound human file capability that signs one-use request grants without exporting account tokens or private keys. This is not agent delegation. The Python `webos_accounts.file_authority.FileAuthority` issues and verifies the corresponding grants using the public Runtime wire contract. Storage consumes these public interfaces, never private signing keys or session maps. Real account data and credentials must stay outside this repository and public roots. Use only explicit private state directories with the loopback development launcher.

## Scoped operation delegation

`webos_accounts.delegation.Delegations` owns the operation policy.
`DelegationAuthority` wraps it with exact, same-origin JSON POST routes under
`/api/v1/agents/`. It caps bodies, applies issuer admission budgets and
returns uncached responses. Hosts select this wrapper explicitly. The current
viewer launcher and deployed service use their existing authorities.
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
Desktop still needs consent presentation, live command dispatch and an
agent file authority. User-presence steps stay user-controlled.

The browser Accounts client exposes an epoch-bound `createOperationAuthority()`
when issuer discovery advertises `agentOperations.version` as
`webos-agent-operations/1`. The capability approves, lists, revokes and consumes
delegations under the current owner session. Approval returns the agent
credential for handoff, and list/inspect omit credentials. Grants and exact
intent are consumed through signed requests. The capability rejects calls after
the account changes or signs out.

These operation grants have a distinct type/audience and are rejected as
file-gateway confirmations. Never use the existing human file authority to
silently perform an agent's file operation. That integration and its server
ownership/provenance tests remain required before enabling agents.

Run `python -m unittest discover -s tests -v` in the component backend environment.
The delegation tests use real generated signing keys and synthetic retained
account state. They verify the HTTP boundary, exact-intent authorization,
single-use and concurrent consumption, and existing account-policy revocation.
End-to-end agent operations require a separate test with a live Desktop.

## Retained identity core and current policy checks

The original42 identity-service tests now live at `tests/test_reference_service.py`, with their original test classes/assertions unchanged. They test the retained `webos_accounts.service.Service` core inside its owning repository. Their history was mechanically extracted before the import-only port. Four new tests separately exercise the current public AccountsService policy: current registration bounds and legacy long-password sign-in; concurrent registration across independent service instances without overwrite; separate username/proxy peer budgets; and persisted sessions with final logout. The complete layered suite passes67 tests (42 core,21 existing policy/delegation,4 current policy).

The historical42-test suite against the public policy does not establish complete policy equivalence: four old assertions differ. Current registration accepts4–32-character passwords, the aggregate shared-proxy ceiling is1200 requests/minute, registered sessions persist across restart, and the old race fixture uses a password longer than the current registration maximum. These differences are recorded in private phase28 evidence, including the failed comparison. The old assertions were preserved; they were not weakened to qualify the current profile.

Original source: `active-system/codiserver-server-v0.3.0/tests/test_service.py` at `4f72ea86928666189b32f6f05c2c697a37341d06`; earlier `desktop-preview/` history retained. Filtered baseline `dad40a136cc693b33562ea095d4b2f7fa05a908d`, mechanical merge `94fb54bad2169f8749dbaeca32c71d88b6c53ac7`. Private phase28 retains commit maps, exact blob/mode proof, baseline and old-source-hidden test commands. No production implementation or deployment changed.

The stateless configuration helper `webos_accounts.mount.validate_base_path(value)` is also public. It returns an empty mount prefix or slash-separated ASCII names unchanged, with a128-character maximum; it raises ValueError for other values. Server components use this shared issuer mount convention without importing account/session internals. It neither reads credentials nor grants authority.

## Browser sign-in retention

`createAccountsClient({persistSession: true})` explicitly enables browser
retention. Call `restore()` before presenting Login or opening account views.
It returns public session metadata after a successful signed server renewal,
or null for an absent, invalid or expired remembered login. A transient server/
network failure rejects without erasing the record or admitting cached identity.
The default remains memory-only for hosts that have not opted in.

Accounts alone owns `webos-account-session-v1` IndexedDB records, scoped by
same-origin issuer and API mount. They hold the registered session token, public
identity metadata and a structured-cloned, nonextractable Web Crypto private key.
The key is never exported; passwords are never retained. Restore verifies the
stored key pair locally, proves possession to the existing server, verifies the
fresh authority signature and checks the exact account/session/key binding.
An expired cached certificate is not authority and does not prevent renewal of
a still-valid server session. The existing eight-hour server deadline remains
fixed; refresh/browser reopening does not extend it.

Ordinary inspection adds only `retention`, a public status string. No token,
private key or raw stored record is exposed by the client. Browser storage is
best effort and can be cleared/evicted. If unavailable, an interactive login
can work in the current tab with an explicit persistence warning; it does not
promise that this login will be remembered. Same-origin trusted applications
share browser authority; IndexedDB and nonextractable keys do not create an
isolation boundary against such code or a compromised browser.

Logout first confirms removal of its exact retained record, then revokes the
server session. A local forget failure leaves sign-out retryable and the current
session intact. An unknown server outcome leaves the credential forgotten so
refresh cannot silently restore it. Conditional record deletion prevents an old
tab from erasing a newer account's remembered login. Restore rechecks that its
record is still current after the network wait; it cannot install an obsolete
account over a concurrent sign-out/login. Renewal never rewrites retained
credentials. Open tabs do not silently switch accounts; the server continues to
authorize their operations, and the next page load uses the current remembered
login. Explicit sign-out invalidates other tabs sharing that server session.

The parent `tests/accounts_persistence_browser.mjs` uses real Login, Chromium
profile restart, IndexedDB/CryptoKey and signed Accounts HTTP. It covers corrupted
records, mismatched keys/accounts, transient renewal failures, expired private
fixture sessions, concurrent tabs and uncertain logout. The parent desktop
suite additionally checks actual Files/Text and draft recovery. Its synthetic
expiry changes only its own disposable SQLite state, never a hosted account.
No Python issuer, stored-account format or backend deployment changes are needed.
