# v1.0.2 — Ethereum sign-in fixes + security hardening

Required upgrade if you are on v1.0.1: the v1.0.1 Ethereum (SIWE) login is rejected
by strict EIP-4361 wallets, including current MetaMask. v1.0.2 is verified end-to-end
against real MetaMask (Ethereum) and real Phantom (Solana). Solana login was
unaffected.

- Fix: challenge nonce is now alphanumeric hex, matching the EIP-4361 nonce
  grammar (the previous base64url nonce could contain characters strict wallets
  reject).
- Fix: the expected SIWE domain now defaults to the browser-facing host:port, so
  domain-binding validation matches the domain the wallet actually signs.
- Fix: the login page now submits the EIP-55 checksummed address, which strict
  wallets require in the SIWE message.
- Security: wallet login fails closed on pre-registration account collisions —
  an existing user must match both wallet namespace and address before sign-in.
- Security: authentication errors shown to the browser are now generic; details
  are logged server-side only (no internal error reflection).
- Releases are now built and published by GitHub Actions (from this release
  onward), with a SHA-256 checksum asset.

Download w3auth-keycloak-plugin-1.0.2.jar below and verify it against
checksums-1.0.2.txt.
