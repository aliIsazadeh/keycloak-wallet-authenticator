> [!WARNING]
> This document is DEPRECATED. Please refer to the corresponding ANTIGRAVITY documents in the root and under docs/ instead. Do not modify this legacy file.

# Architecture — Wallet Authentication Backend

This is the full reasoning behind the rules in the root `CLAUDE.md`. When a
decision is unclear, this document wins.

## 1. Purpose and philosophy

The backend does one thing: prove that a client controls the private key for a
crypto wallet, then issue a login session. Everything else is detail.

It is **protocol-driven, not SDK-driven.** Every client — Reown AppKit,
MetaMask, raw WalletConnect, or a custom SDK built later — reduces to the same
three inputs: a `message`, a `signature`, and a claimed `accountId`. No wallet
vendor's code or concepts appear in the backend.

We follow the **rule of three**: build the first concrete implementation, add a
second when it actually exists, and only abstract when real duplication shows
up. We do not build for imagined future protocols.

## 2. Identity model

Identity is a **CAIP-10 account id**: `namespace:reference:address`
(e.g. `eip155:1:0xabc...`). Internally we store and key on `(namespace,
address)` — not the full string — because:

- For EVM (`eip155`), the **address is the identity**. The same private key
  controls every EVM chain. So `chainId` is **session/auth context**, not part
  of the identity key. Putting chainId in the unique key would split one user
  into many identities.
- EVM addresses are case-insensitive but EIP-55 checksums encode data in the
  case. So `CaipAccountId` **must canonicalize** (lowercase the EVM address) in
  its construction. An un-normalized `CaipAccountId` must be impossible to
  build. This protects the `(namespace, address)` uniqueness.

The central value object is `CaipAccountId`. Everything downstream speaks
`CaipAccountId`, never raw strings.

## 3. Code structure (V1: single Gradle module)

V1 is a **single Gradle module** (Kotlin DSL) with clean packages. Multi-module
is deferred — it is structure we do not yet need (rule of three applied to the
build itself). The dependency rule we care about is enforced with an **ArchUnit
test** instead of separate modules:

> The core packages — `identity`, `challenge`, `verification`, `session`,
> `usecase` — must not import Spring, JPA, Redis, or `infrastructure`.

Packages:

| Package          | Holds                                                            |
| ---------------- | --------------------------------------------------------------- |
| `identity`       | `CaipAccountId`, `Namespace`, `WalletIdentity`                  |
| `challenge`      | `Challenge`, `Nonce`, `ChallengeStore` (port), `ChallengePolicy`|
| `verification`   | `SignatureVerifier`, `EthereumSignatureVerifier`, SIWE parser   |
| `session`        | access/refresh token logic, `SessionStore` (port)              |
| `usecase`        | `RequestChallenge`, `VerifyAndAuthenticate`, `RefreshSession`, `Logout` |
| `infrastructure` | JPA entities + repositories, Redis adapters, Flyway migrations  |
| `security`       | Spring Security config, JWT filter                              |
| `api`            | REST controllers, request/response DTOs                         |

**When to split into real modules later:** when a heavy dependency needs
isolating, or when you want to publish the wire contract as its own artifact
for client SDKs. Not before. Note: web3j (`core` + `crypto`) landed at M3
without triggering a module split — the dependency was isolated to
`verification` and `infrastructure` via the `ChainClient` port, which was
sufficient. The split remains deferred until it earns its keep.

## 4. Persistence: ephemeral vs durable

**Redis (ephemeral, TTL-based):**

| Key pattern                    | Holds                              | TTL        |
| ------------------------------ | ---------------------------------- | ---------- |
| `challenge:{nonce}`            | claimed accountId, domain, chainId | 2–5 min    |
| `ratelimit:challenge:{ip}`     | request counter                    | window     |
| `ratelimit:challenge:{addr}`   | request counter                    | window     |

Nonces are **never** written to Postgres. The verify step consumes the
challenge **atomically** (`GETDEL` or Lua) so two concurrent verifies of the
same nonce cannot both succeed.

**PostgreSQL (durable), owned by Flyway migrations:**

- `wallet_identity` — `id (uuid)`, `namespace`, `address`, `status`,
  `created_at`, `last_login_at`. Unique on `(namespace, address)`.
- `refresh_token` — `id`, `identity_id (fk)`, `family_id`, `token_hash`
  (store the hash, never the raw token), `replaced_by`, `expires_at`,
  `revoked_at`. The refresh-token row **is** the session record in V1 — do not
  create a separate session table that duplicates it.
- `auth_event` — `id`, `identity_id (fk)`, `event_type`, `chain_id`, `ip`,
  `created_at`. Audit trail; later feeds rate-limit/anomaly logic.

## 5. Authentication flow

Two round trips. The server is authoritative on domain, nonce, and expiry.

**POST /v1/auth/challenge** — input: claimed account (namespace + address +
chainId).
1. Validate the CAIP format.
2. Generate a nonce (≥128 bits, CSPRNG).
3. Store the challenge in Redis with a TTL.
4. Return the canonical SIWE message to sign (server fills in domain, uri,
   nonce, issuedAt, expirationTime) plus the nonce.

**POST /v1/auth/verify** — input: the signed message + signature.
1. Parse the SIWE message.
2. **Atomically consume** the nonce from Redis. Fail closed if it is missing,
   expired, or already used.
3. Validate message fields against the issued challenge and policy: domain,
   uri, chainId, issuedAt/expiration (with small clock-skew tolerance).
4. Verify the signature (V1: EOA `ecrecover` only).
5. Check the recovered signer equals the address claimed inside the message.
6. Derive the `CaipAccountId`; upsert `wallet_identity`.
7. Issue a short access JWT + a refresh token; persist the refresh-token row.

**POST /v1/auth/refresh** — validate the presented refresh token against its
stored hash, issue a new pair, mark the old one `replaced_by`, and revoke the
whole family if a already-rotated token is reused (reuse = likely theft).

**POST /v1/auth/logout** — revoke the refresh-token family.

## 6. Session design

- **Access token:** JWT, ~10 minutes, **HS256** with a strong secret for V1.
  Claims: subject = `namespace:address` (the identity key — no chainId,
  per §2), a `jti`, an audience. Short lifetime means
  no revocation needed on the hot path; it just expires.
  The subject is defined canonically in
  `CaipAccountId.IdentityKey.toJwtSubject()` so it cannot drift between
  `/verify` and (coming) `/refresh`.
  - *Why HS256 not RS256/ES256:* asymmetric signing only earns its keep when a
    separate service or SDK verifies tokens without sharing the secret. V1 is
    one service that both issues and verifies. Because access tokens are short,
    switching algorithms later is cheap (no long-lived tokens to migrate).
- **Refresh token:** opaque random string; only its **hash** is stored.
  Rotated on every use; reuse detection revokes the family via `family_id`.
- **No JWT denylist in V1.** "Invalidation" means "within ~10 minutes" via
  expiry. Add a Redis `jti` denylist later only if instant kill is required.

## 7. Security rules

- **Domain binding.** The SIWE `domain` field must match our domain. This is
  the anti-phishing / anti-cross-site-replay control. Verifying the signature
  without checking domain is a real vulnerability.
- **Atomic single-use nonce.** See §4.
- **Hashed refresh tokens.** A database leak must not hand out live sessions.
- **Rate limit** the unauthenticated `/challenge` endpoint per IP and per
  address — it is a cheap spam/DoS surface.
- **Do not log** raw signatures, raw refresh tokens, or full messages at info
  level.

### Smart-contract wallet support (M3, shipped)

M3 extended verification to cover smart-contract wallets. Two sub-milestones:

**M3a — EIP-1271 (deployed contracts).** A `ChainClient` port lives in
`verification` (no web3j import): methods `getCode` and
`isValidErc1271Signature`. `Web3jChainClient` in `infrastructure` implements
it. The `ContractAwareSignatureVerifier` dispatcher wraps
`EthereumSignatureVerifier` behind the same `SignatureVerifier` seam and routes
each request. Dispatch order is load-bearing:

1. Check for the EIP-6492 magic suffix on the decoded signature **first** — a
   6492 wrapper is a property of the signature, not the address, and can appear
   on an already-deployed contract. Routing by `getCode` first would mis-route
   a wrapped signature to the plain 1271 path.
2. `eth_getCode`: code present → EIP-1271 `isValidErc1271Signature`; empty →
   EOA `ecrecover`.

The RPC URL is bound via `walletauth.chain.rpc-url`; the web3j bean is lazy so
the app boots without a live node.

**M3b — EIP-6492 (counterfactual / not-yet-deployed wallets).** The 6492 branch
calls `ChainClient.isValidSignatureDeployless`, implemented in
`Web3jChainClient` as a deployless `eth_call` (`to=null`) to the
`ValidateSigOffchain` universal validator — compiled solc 0.8.28, stored as a
verified bytecode constant. The validator deploys the wallet counterfactually
inside a single EVM frame, calls `isValidSignature`, and returns `0x01` (valid)
or `0x00` (invalid). The full EIP-6492-wrapped signature is passed whole over
the port; the validator unwraps internally. `Eip6492Envelope` in `verification`
performs a pure-Java well-formedness gate (bounds checks on the ABI-encoded
body) before any RPC call is made; malformed envelopes are rejected in-process.

## 8. The one allowed interface

```java
public interface SignatureVerifier {
    VerifiedIdentity verify(VerificationRequest request) throws VerificationException;
}
```

Two concrete implementations exist:

- `EthereumSignatureVerifier` — EOA `ecrecover` path.
- `ContractAwareSignatureVerifier` — the dispatcher introduced at M3; routes
  each request across the EOA, EIP-1271, and EIP-6492 paths. Wraps
  `EthereumSignatureVerifier` internally.

The interface began as a **test seam** (so `VerifyAndAuthenticate` can be
tested with a one-liner stub). The real second case arrived at M3 and confirmed
the abstraction was correct. It is not a future-protocol hook — the seam now
has two real implementations, which is the rule-of-three justification.

## 9. Build order

- **M0** ✅ — project skeleton, `CaipAccountId` + value objects, Redis
  `ChallengeStore` with atomic consume, `/challenge` endpoint, docker-compose
  for Postgres + Redis, ArchUnit guard test. Goal: issue and store a nonce.
- **M1** ✅ — SIWE parsing + full field validation, EOA `ecrecover`, signer-
  equals-claim check, identity upsert, access JWT. Goal: an EOA wallet logs in
  end-to-end.
- **M2** ✅ — refresh tokens, rotation, reuse detection, logout.
- **M3a** ✅ — EIP-1271 deployed smart-contract wallets; `ChainClient` port +
  `Web3jChainClient` adapter (web3j core); `ContractAwareSignatureVerifier`
  dispatcher. RPC dependency introduced. Module split justified but explicitly
  deferred — web3j landed single-module.
- **M3b** ✅ — EIP-6492 counterfactual wallets; `Eip6492Envelope` well-formedness
  gate; `isValidSignatureDeployless` via deployless `eth_call` to the
  `ValidateSigOffchain` universal validator.
- **M4** — a second namespace (Solana, Ed25519) to prove the abstraction; only
  then harden any registry. Unscoped.

Cross-cutting from M1 onward: rate limiting, audit logging, Testcontainers
integration tests.

## 10. Open decisions / revisit later

- Whether the server returns the full message to sign (current plan) or the
  client builds it and the server re-validates every field.
- Whether to publish the wire contract (OpenAPI) as a separate module for
  client SDKs.
- Instant access-token revocation (Redis `jti` denylist) — only if a real need
  appears.
- M0 derives the SIWE `Expiration Time` from `issuedAt + nonceTtl` (one
  config, the Redis TTL). Clock-skew tolerance for validating that timestamp
  is deferred to M1's message-validation step, as a separate
  `clockSkewTolerance` margin applied when *checking* the timestamp — not as
  a second expiry window at generation time.
