---
name: w3auth-security
description: >-
  Security review checklist for the W3-Auth backend's crypto and auth paths.
  Use this whenever writing or reviewing code in the challenge, verification,
  or session packages, or anything touching SIWE messages, signature
  verification (ecrecover / EIP-1271 / EIP-6492), nonces, JWTs, or refresh
  tokens. Also use it when adding tests for those paths or when tempted to
  change a production setting to make a test pass. Demands failure-path tests
  and blocks the common "false fix" footguns.
---

# W3-Auth security rules

Security-sensitive code (challenge, verify, session) must have tests for the
**failure paths**, not just the happy path: expired nonce, reused nonce, wrong
domain, wrong chainId, signer mismatch.

## Verification is claim validation, not address recovery

Recovering the signer is necessary but never sufficient. You must:

1. Recover the signer, AND
2. Check it equals the address claimed inside the signed message, AND
3. Validate the message fields — domain, nonce, issuedAt/expiration, chainId —
   against what the server actually issued.

Address recovery alone authenticates nobody.

## Server is authoritative

Domain, nonce, and expiry are server-controlled. The Redis nonce TTL is the
**real** expiry gate; the message's own timestamps are a secondary check with a
small clock-skew tolerance. The SIWE `domain` field must match our domain — that
is the anti-phishing / anti-cross-site-replay control, not optional.

## Atomic single-use nonce

Consume the nonce atomically (`GETDEL` or a Lua script). A `GET` then a later
`DEL` is a replay bug. Fail closed if the nonce is missing, expired, or already
used. A sequential single-use test does **not** prove concurrency — guard
atomicity with an N-threads / exactly-one-success test that goes through the real
adapter.

## Tokens

- Access token: short-lived JWT, **HS256** for V1. Subject is the identity key
  format (`eip155:0x...`), plus a `jti` and audience. Short lifetime is the
  revocation story on the hot path.
- Refresh token: opaque random string; store **only its hash**. Rotate on every
  use; reusing an already-rotated token is treated as theft and revokes the
  whole family via `family_id`.
- No JWT denylist in V1.

## Don't log secrets

Never log raw signatures, raw refresh tokens, or full SIWE messages at info
level.

## No false fixes (hard rule)

Do not weaken a production contract to make a test go green. Specifically:

- Do not add `@Transactional` (or any annotation) to production code just to
  satisfy a test — use a `TransactionTemplate` in the test instead.
- Do not change the transaction isolation level to paper over a failing test.
  `REPEATABLE_READ` was once introduced to fix a failing test and manufactured a
  snapshot hazard; it was reverted to the specified `READ_COMMITTED`. The fix is
  the real bug or the test, never the production setting.
- Do not pre-warm a pool to suppress a legitimate concurrency failure.

## Smart-contract wallet artifacts (M3+)

Bytecode and signature test vectors for EIP-1271 / EIP-6492 work are supplied
and verified **externally**, never generated to match the decoder under test.
Prove behaviour with accept-valid + reject-forged + reject-tampered, not byte
comparison alone.

For a deployless validator exercised via `eth_call` with `to=null` (contract-creation
mode), the single-byte accept return is the behavioural proof — it simultaneously
implies correct CREATE2 address derivation, the factory deployed to that exact
address, and EIP-1271 inner validation passed. Do not assert `eth_getCode` is
non-empty after the call: a deployless `eth_call` does not persist the deploy, so
post-call code is empty by design. Counterfactual wallet addresses must be computed
in-test (keccak256 chain), never hardcoded — a hardcoded address hides a derivation
bug behind a green test.
