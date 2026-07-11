# Architecture — Keycloak Wallet Authenticator

The design and reasoning behind Keycloak Wallet Authenticator. When a decision is
unclear, this document is the reference.

## 1. Purpose and philosophy

It does one thing: prove that a client controls the private key for a crypto
wallet, then issue a login session. Everything else is detail.

It is **protocol-driven, not SDK-driven.** Every client — Reown AppKit, MetaMask,
raw WalletConnect, or a custom SDK — reduces to the same three inputs: a `message`,
a `signature`, and a claimed `accountId`. No wallet vendor's code or concepts appear
in the backend. This is what lets the same verification engine power both the
Keycloak plugin and the standalone REST API unchanged.

## 2. Identity model

Identity is a **CAIP-10 account id**: `namespace:reference:address`
(e.g. `eip155:1:0xabc...`). Internally the system stores and keys on
`(namespace, address)` — not the full string — because:

- For EVM (`eip155`), the **address is the identity**. The same private key controls
  every EVM chain, so `chainId` is **session/auth context**, not part of the identity
  key. Putting `chainId` in the unique key would split one user into many identities.
- EVM addresses are case-insensitive, but EIP-55 checksums encode data in the case.
  So the `CaipAccountId` value object **canonicalizes** (lowercases the EVM address)
  at construction — an un-normalized identity is impossible to build. This protects
  the `(namespace, address)` uniqueness.

Everything downstream speaks `CaipAccountId`, never raw strings.

## 3. Module layout

A multi-module Gradle build (Java 21, Kotlin DSL, centralized version catalog):

| Module | Role |
| --- | --- |
| `w3auth-core` | Framework-free Java library: identity, challenge, verification, session, use cases. Depends on web3j `crypto` (signing math) but never Spring / JPA / Redis. |
| `w3auth-keycloak-plugin` | Keycloak Authenticator SPI plugin (fat JAR) — **the product**. See §7. |
| `examples/self-hosted-rest-api` | **Reference example, not the product.** A Spring Boot REST application built on the same core: API controllers, composition root, infrastructure (JPA / Redis / Flyway / `Web3jChainClient`), Spring Security. Shows how to self-host wallet login without Keycloak. |

Core packages in `w3auth-core`:

| Package | Holds |
| --- | --- |
| `identity` | `CaipAccountId`, `Namespace`, `WalletIdentity`, `SolanaPublicKey`, `Base58` |
| `challenge` | `Challenge`, `Nonce`, `ChallengePolicy`, SIWE/SIWS message factories |
| `verification` | `SignatureVerifier` and its implementations, `ChainClient` port, `Eip6492Envelope`, SIWE/SIWS parsers |
| `session` | `JwtService`, `JwtPolicy`, refresh-token logic |
| `usecase` | `RequestChallenge`, `VerifyAndAuthenticate`, `RefreshSession`, `Logout` |

The dependency rule — core must not import Spring, JPA, Redis, or infrastructure — is
enforced twice: by the **module boundary** (`w3auth-core` has no framework on its
compile classpath) and by an **ArchUnit test** in the self-hosted REST API example.

## 4. Persistence: ephemeral vs durable (standalone API)

**Redis (ephemeral, TTL-based):** challenge nonces (`challenge:{nonce}`, 2–5 min TTL)
and rate-limit counters. Nonces are **never** written to Postgres, and the verify
step consumes the challenge **atomically** (`GETDEL` or Lua) so two concurrent
verifies of the same nonce cannot both succeed.

**PostgreSQL (durable), owned by Flyway migrations:** `wallet_identity`
(unique on `(namespace, address)`), `refresh_token` (stores the token *hash*, never
the raw token; the row is the session record), and `auth_event` (audit trail).

The Keycloak plugin has no Redis or Postgres of its own — the nonce lives in the
Keycloak authentication-session note and users live in Keycloak's own store (§7).

## 5. Authentication flow

Two round trips. The server is authoritative on domain, nonce, and expiry.

**Challenge** — validate the CAIP account, generate a ≥128-bit CSPRNG nonce, store the
challenge with a TTL, and return the canonical SIWE/SIWS message to sign.

**Verify** — parse the message, **atomically consume** the nonce (fail closed if
missing/expired/used), validate message fields against the issued challenge and
policy (domain, uri, chainId, issuedAt/expiration with clock-skew tolerance), verify
the signature, check the recovered signer equals the address claimed *inside* the
message, derive the `CaipAccountId`, upsert the identity, and issue a session.

The standalone API additionally offers **refresh** (rotating refresh tokens with
reuse detection that revokes the whole family) and **logout** (revoke the family).

## 6. Session design (standalone API)

- **Access token:** JWT, ~10 minutes, **HS256** with a strong secret. Subject is the
  identity key `namespace:address` (no chainId). Short lifetime means no revocation on
  the hot path — it simply expires. HS256 over RS256/ES256 because V1 is one service
  that both issues and verifies; asymmetric signing only earns its keep when a
  separate service verifies without sharing the secret, and short tokens make a later
  switch cheap.
- **Refresh token:** opaque random string; only its hash is stored; rotated on every
  use; reuse detection revokes the family.

## 7. Keycloak Authenticator plugin

`w3auth-keycloak-plugin` packages the same verification engine as a Keycloak
**Authenticator SPI** so wallets can log in through Keycloak's browser flow.

- **Nonce in the auth-session note, not Redis.** The authenticator generates a nonce,
  stores it as a Keycloak auth note, and renders a login template that talks to
  `window.ethereum` / Phantom `window.solana`. On postback it requires the message
  nonce to equal the stored note and removes the note on success — the same single-use
  discipline as `GETDEL`, using Keycloak's own session storage, adding no
  infrastructure.
- **Server-authoritative fields.** `expected-domain` and `expected-uri` are admin
  config (with safe localhost defaults); issuedAt/expiration are checked with a ±5 min
  skew window.
- **`HttpChainClient` instead of web3j-core.** The plugin implements the `ChainClient`
  port over Java 21's native `HttpClient` with manual ABI encoding, keeping web3j-core's
  heavy transitive tree (RxJava/OkHttp) off Keycloak's classpath. With no RPC URL
  configured, the EVM path degrades to EOA-only.
- **Identity mapping.** The Keycloak username is the canonical `namespace:address`, so
  switching chains never bifurcates one wallet owner into multiple Keycloak users.
  Address, namespace, and chainId are stored as user attributes.
- **Fat JAR, BouncyCastle excluded.** The plugin bundles `w3auth-core` and its runtime
  deps but excludes `bcprov`, which Keycloak's boot classpath already provides
  (bundling it causes runtime linkage clashes).
- **Proven against a real Keycloak.** The integration test runs Keycloak 25 in
  Testcontainers, imports a realm with the custom browser flow, and drives the full
  OIDC login with signed messages.

## 8. Security rules

- **Domain binding.** The SIWE `domain` must match the configured domain — the
  anti-phishing / cross-site-replay control. Verifying a signature without checking
  domain is a real vulnerability.
- **Atomic single-use nonce.** See §4.
- **Hashed refresh tokens.** A database leak must not hand out live sessions.
- **Rate limit** the unauthenticated challenge endpoint per IP and per address.
- **Do not log** raw signatures, raw refresh tokens, or full messages at info level.

### Smart-contract wallet support

**EIP-1271 (deployed contracts).** A `ChainClient` port (no web3j import) exposes
`getCode` and `isValidErc1271Signature`. A dispatcher wraps the EOA verifier behind
the same `SignatureVerifier` seam and routes each request. Dispatch order is
load-bearing: check for the EIP-6492 magic suffix on the signature **first** (a 6492
wrapper is a property of the signature, not the address, and can appear on an
already-deployed contract), then `eth_getCode` — code present → EIP-1271, empty → EOA
`ecrecover`.

**EIP-6492 (counterfactual / not-yet-deployed wallets).** The 6492 branch performs a
deployless `eth_call` to the `ValidateSigOffchain` universal validator, which deploys
the wallet counterfactually inside a single EVM frame, calls `isValidSignature`, and
returns valid/invalid. A pure-Java `Eip6492Envelope` well-formedness gate rejects
malformed envelopes in-process before any RPC call.

## 9. The one allowed interface

```java
public interface SignatureVerifier {
    VerifiedIdentity verify(VerificationRequest request) throws VerificationException;
}
```

Four concrete implementations: `EthereumSignatureVerifier` (EOA `ecrecover`),
`ContractAwareSignatureVerifier` (EVM dispatcher across EOA / EIP-1271 / EIP-6492),
`SolanaSignatureVerifier` (Ed25519), and `NamespaceRoutingSignatureVerifier` (routes
by namespace). The `ChainClient` port has two adapters: `Web3jChainClient` (standalone
API) and the zero-dependency `HttpChainClient` (Keycloak plugin).

## 10. Open decisions

- Whether the server returns the full message to sign (current) or the client builds
  it and the server re-validates every field.
- Whether to publish the wire contract (OpenAPI) as a separate module for client SDKs.
- Instant access-token revocation (a Redis `jti` denylist) — only if a real need
  appears.
