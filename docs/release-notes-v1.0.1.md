# v1.0.1 — browser wallet-login fixes

Recommended upgrade for anyone on v1.0.0. Fixes the real-browser sign-in flow.

- Fix: SIWE messages with an optional EIP-4361 statement line are now accepted
  (v1.0.0 rejected them with "expected 10 lines").
- Fix: byte-exact message transport — the message is now transmitted and verified as
  the exact bytes the wallet signed, fixing a signer-mismatch caused by browsers
  normalizing form newlines (\n → \r\n).
- Fix: authenticator error paths now re-render the login form instead of returning
  HTTP 500.
- Added a one-command local demo environment (demo/) and browser-transport regression
  tests.

Download w3auth-keycloak-plugin-1.0.1.jar below.
