# Architecture — Wallet Authentication Backend

This is the full reasoning behind the rules in the root `ANTIGRAVITY.md` / `CLAUDE.md`
(and `.agents/AGENTS.md`). When a decision is unclear, this document wins.

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

## 3. Code structure (M5: multi-module Gradle)

V1 started as a **single Gradle module** with clean packages — multi-module was
structure we did not yet need (rule of three applied to the build itself). The
real forcing case arrived at **M5**: the Keycloak plugin needed the
verification engine as its own framework-free artifact. The project is now
three modules (Kotlin DSL) coordinated by a root build with a centralized
version catalog (`gradle/libs.versions.toml`):

| Module                   | Role                                                           |
| ------------------------ | -------------------------------------------------------------- |
| `w3auth-core`            | Framework-free Java library: identity, challenge, verification, session, usecase. Depends on web3j `crypto` (signing math) but never Spring/JPA/Redis. |
| `w3auth-keycloak-plugin` | Keycloak Authenticator SPI plugin (fat JAR) — **the product**, see §7a. |
| `examples/self-hosted-rest-api` | **Reference example, not the product.** Spring Boot REST application: `api`, `config` (composition root), `infrastructure` (JPA/Redis/Flyway/`Web3jChainClient`), `security`. Self-hosting demo on the same core. |

Core packages in `w3auth-core`:

| Package          | Holds                                                            |
| ---------------- | --------------------------------------------------------------- |
| `identity`       | `CaipAccountId`, `Namespace`, `WalletIdentity`, `WalletIdentityStore` (port), `SolanaCluster`, `SolanaPublicKey`, `Base58` |
| `challenge`      | `Challenge`, `Nonce`, `ChallengeStore` (port), `ChallengePolicy`, `RateLimiter` (port), `SiweMessageFactory`, `SiwsMessageFactory` |
| `verification`   | `SignatureVerifier`, `EthereumSignatureVerifier`, `ContractAwareSignatureVerifier`, `NamespaceRoutingSignatureVerifier`, `SolanaSignatureVerifier`, `ChainClient` (port), `Eip6492Envelope`, SIWE/SIWS parsers |
| `session`        | `JwtService`, `JwtPolicy`, access/refresh token logic, `RefreshTokenStore` (port) |
| `usecase`        | `RequestChallenge`, `VerifyAndAuthenticate`, `RefreshSession`, `Logout`, `AuthEventStore` (port) |

The dependency rule is now enforced twice:

> The core packages — `identity`, `challenge`, `verification`, `session`,
> `usecase` — must not import Spring, JPA, Redis, or `infrastructure`.

First by the **module boundary** (`w3auth-core` simply has no framework on its
compile classpath), and second by the **ArchUnit test** (`LayerBoundaryTest`
in `examples/self-hosted-rest-api`), which keeps guarding against `infrastructure`
imports leaking back into core packages.

**Any further split** (e.g. publishing the wire contract as its own artifact
for client SDKs) needs the same class of forcing reason the M5 split had. Not
before.

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

This split applies to the standalone API. The Keycloak plugin (§7a) has no
Redis or Postgres of its own: the nonce lives in the Keycloak auth-session
note and user records live in Keycloak's own store.

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
4. Verify the signature (EVM: EOA or EIP-1271/6492; Solana: Ed25519).
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
  `/verify` and `/refresh`.
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

## 7a. Keycloak Authenticator plugin (M5, shipped)

`w3auth-keycloak-plugin` packages the same verification engine as a Keycloak
**Authenticator SPI** so wallets can log in directly through Keycloak's
browser flow. Design decisions:

- **Nonce in the auth-session note, not Redis.** `W3AuthAuthenticator`
  generates a nonce (`Nonce.generate()`), stores it as an auth note on the
  Keycloak authentication session, and renders `w3auth-login.ftl` (FreeMarker
  template with `window.ethereum` / Phantom `window.solana` connectors). On
  postback it parses the SIWE/SIWS message, requires the message nonce to
  equal the stored note, and removes the note on success — the same
  single-use discipline as Redis `GETDEL`, using Keycloak's own session
  storage instead of a new infrastructure dependency.
- **Server-authoritative fields still apply.** `expected-domain` and
  `expected-uri` are Keycloak admin config (with safe localhost defaults via
  a blank-tolerant `getConfigValue`); issuedAt/expiration are checked with a
  ±5 min skew window.
- **`HttpChainClient` instead of web3j-core.** The plugin implements the
  `ChainClient` port over Java 21's native `HttpClient` with manual ABI
  encoding/decoding. This keeps web3j-core's heavy transitive tree
  (RxJava/OkHttp) off Keycloak's server classpath. If no `ethereum-rpc-url`
  is configured, the EVM path degrades to EOA-only verification.
- **Identity mapping preserves decision §2.** The Keycloak username is
  `CaipAccountId.identityKey().toJwtSubject()` (`namespace:address`), so
  switching chains never bifurcates one wallet owner into multiple Keycloak
  users. Address, namespace, and chainId are stored as user attributes.
- **Fat JAR, BouncyCastle excluded.** The plugin jar bundles `w3auth-core`
  and its runtime deps but excludes `bcprov`, which Keycloak's boot classpath
  already provides (bundling it causes runtime linkage clashes).
- **Proven against a real Keycloak.** `W3AuthAuthenticatorIntegrationTest`
  runs Keycloak 25.0.2 in Testcontainers, imports a test realm with the
  custom browser flow, and drives the full OIDC login with signed messages.

## 8. The one allowed interface

```java
public interface SignatureVerifier {
    VerifiedIdentity verify(VerificationRequest request) throws VerificationException;
}
```

Four concrete implementations exist:

- `EthereumSignatureVerifier` — EOA `ecrecover` path.
- `ContractAwareSignatureVerifier` — the EVM dispatcher introduced at M3;
  routes each request across the EOA, EIP-1271, and EIP-6492 paths. Wraps
  `EthereumSignatureVerifier` internally.
- `SolanaSignatureVerifier` — Ed25519 path introduced at M4.
- `NamespaceRoutingSignatureVerifier` — the top-level dispatcher introduced
  at M4; routes by namespace (`eip155` vs `solana`) to the verifiers above.

The `ChainClient` port likewise has two adapters: `Web3jChainClient` in the
standalone API and the zero-dependency `HttpChainClient` in the Keycloak
plugin (§7a).

The interface began as a **test seam** (so `VerifyAndAuthenticate` can be
tested with a one-liner stub). The real second case arrived at M3, and M4/M5
kept confirming the abstraction. It is not a future-protocol hook — the seam
has real implementations, which is the rule-of-three justification.

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
- **M4** ✅ — a second namespace (Solana, Ed25519) to prove the abstraction; only
  then harden any registry.
- **M5** ✅ — refactor to multi-module Gradle (`w3auth-core`,
  `w3auth-standalone-api`, `w3auth-keycloak-plugin`) with a version catalog;
  Keycloak Authenticator SPI plugin with `HttpChainClient`, login theme, and
  Testcontainers end-to-end tests against Keycloak 25.0.2.
- **Cross-cutting** ✅ — rate limiting on challenge requests, audit logging of auth events in Postgres, and Testcontainers integration tests.

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
