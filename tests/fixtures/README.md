# Test fixtures (not secrets)

These certificates and the private key exist **only for the automated tests** in `tests/e2e.rs`.
They were generated for this repository, are valid until 2126, and protect nothing.
Never use them for a real server.

- `ca.pem`       — test certificate authority
- `server.pem`   — server certificate for `localhost` / `127.0.0.1`, signed by `ca.pem`
- `server.key`   — private key of `server.pem` (test only)
- `other_ca.pem` — an unrelated CA, used to check that untrusted certificates are rejected
