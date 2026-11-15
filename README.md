# Accounts

Owns account registration, sign-in, identity proofs and retained session/account policy. Its Python public API is `webos_accounts.AccountsService`, `Config`, `Failure`, and the stateless `jose` proof primitives. The development launcher uses that same policy service. Passwords, signing keys and session tokens are never ordinary inspection data.

The baseline preserves the existing Codi issuer implementation and account-policy history. The new package retains subject IDs, Argon2 records, signing-key/database coupling and session formats. Discovery no longer advertises a guest VM or peer transport. This is a development authority, not an authorized production deployment or a replacement production identity system.

Install into a separate development environment with `uv pip install -e .`. Run `python -m unittest discover -s tests -v` there. Four real synthetic-state tests cover retained identity restart, refusal of incomplete retained state, missing-user sign-in without implicit registration, and discovery without guest dependencies or secret fields. They do not establish production-user continuity or HTTP/browser authentication acceptance.

The browser identity implementation remains preserved under `active-system/network/`; its public package/capability port is pending. Storage must consume public authorization interfaces, never private signing keys or session maps. Real account data and credentials must stay outside this repository and public roots. Use only explicit private state directories with the loopback development launcher.
