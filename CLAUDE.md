# CLAUDE.md — Wallet Authentication Backend

This file is the steering wheel for the project. Read it before every task.
The full reasoning lives in `.antigravity/architecture/ANTIGRAVITY_ARCHITECTURE.md` — read that too for any
design decision.

## What this is

A backend that proves a user controls a crypto wallet, then issues a login
session. It is **protocol-driven, not SDK-driven**: clients send
`(message, signature, accountId)` and nothing about any wallet vendor leaks
into the backend.

This is **NOT a Reown backend.** Today the mobile client happens to use Reown
AppKit, but the backend must never import or depend on Reown, WalletConnect,
or any wallet SDK. Future clients may be MetaMask, raw WalletConnect, or a
custom SDK — the backend treats them all identically.

It ships in two forms: a **standalone Spring Boot REST API**
(`w3auth-standalone-api`) and a **Keycloak Authenticator SPI plugin**
(`w3auth-keycloak-plugin`), both built on the same framework-free
verification engine (`w3auth-core`).

## Tech stack

- Java 21, Spring Boot, Spring Security (standalone API only)
- Gradle (Kotlin DSL), multi-module since M5, with a centralized version
  catalog (`gradle/libs.versions.toml`)
- PostgreSQL (durable data), Redis (ephemeral data) — standalone API
- Hibernate / JPA, Flyway for migrations
- JWT for access tokens, JUnit + Testcontainers for tests
- Docker / docker-compose for local Postgres + Redis
- Keycloak 25 Authenticator SPI for the IAM plugin (fat JAR, BouncyCastle
  excluded — Keycloak provides it)
- web3j 4.12.3 — `crypto` in `w3auth-core`, `core` (RPC) in
  `w3auth-standalone-api` only. The Keycloak plugin deliberately avoids
  web3j-core: `HttpChainClient` implements the `ChainClient` port over
  Java 21's native `HttpClient` to keep Keycloak's classpath clean.

## V1 scope (hold this line)

IN scope:
- SIWE (EIP-4361) and SIWS (Solana Sign-In)
- EVM chains and Solana (non-EVM)
- EOA (normal) wallets
- EIP-1271 deployed smart-contract wallets (M3a, shipped)
- EIP-6492 counterfactual smart-contract wallets (M3b, shipped)
- Multi-namespace SIWX abstraction layer (M4, shipped)
- Multi-module Gradle build + version catalog (M5, shipped)
- Keycloak Authenticator SPI plugin (M5, shipped)
- Rate limiting on challenge requests (shipped)
- Audit logging of auth events in Postgres (shipped)

OUT of scope for V1 (do not build yet):
- Wallet-protocol plugin system / dynamic protocol registry (note: the
  Keycloak Authenticator SPI plugin is a different thing and shipped at M5)
- JWT denylist / instant access-token revocation

## Locked architecture decisions

1. **Identity = CAIP-10.** Model identity as `namespace:address`
   (e.g. `eip155` + `0xabc...`). Never model it as
   `(walletAddress, provider, chainId)`.
2. **Address is identity; chainId is session context.** The unique key for a
   wallet identity is `(namespace, address)`. The same EVM key works on all
   EVM chains, so chainId belongs to the auth/session context, never the
   identity key.
3. **Canonicalize addresses inside the value object.** `CaipAccountId` must
   normalize the address (lowercase EVM) in its factory so two cases of the
   same address can never become two identities.
4. **Sessions are hybrid.** Short-lived access JWT (~10 min, **HS256** for
   V1), plus a server-side refresh token stored in Postgres. Logout revokes
   the refresh-token family. Refresh tokens rotate; reusing an old one
   revokes the whole family. No JWT denylist in V1.
5. **Ephemeral vs durable split.** In the standalone API, nonces/challenges
   live in **Redis only** with a TTL and are **never** written to Postgres.
   Wallet identities, refresh tokens, and audit logs live in Postgres. In the
   Keycloak plugin the nonce lives in the Keycloak auth-session note — same
   single-use discipline, no Redis.
6. **Atomic nonce consume.** On verify, consume the nonce atomically
   (`GETDEL` or a Lua script). A `GET` then later `DEL` is a replay bug.
7. **Verification is claim validation, not just address recovery.** Recover
   the signer AND check it equals the address inside the signed message, AND
   validate the message fields (domain, nonce, issuedAt/expiration, chainId)
   against what the server issued. Address recovery alone authenticates
   nobody.
8. **Server is authoritative on domain, nonce, and expiry.** The Redis nonce
   TTL is the real expiry gate; the message's own timestamps are a secondary
   check only.

## Module layout (multi-module since M5)

```
w3auth-core — framework-free Java library (no Spring/JPA/Redis imports)
com.w3auth.backend
├── identity/        CaipAccountId, Namespace, WalletIdentity,
│                    WalletIdentityStore (port), SolanaCluster,
│                    SolanaPublicKey, Base58
├── challenge/       Challenge, Nonce, ChallengeStore (port), ChallengePolicy,
│                    RateLimiter (port), SiweMessageFactory, SiwsMessageFactory
├── verification/    SignatureVerifier (interface), EthereumSignatureVerifier (EOA),
│                    ContractAwareSignatureVerifier (EVM dispatcher),
│                    NamespaceRoutingSignatureVerifier (namespace dispatcher),
│                    SolanaSignatureVerifier (Ed25519), ChainClient (port),
│                    Eip6492Envelope (6492 well-formedness gate),
│                    SiweMessage/SiweMessageParser, SiwsMessage/SiwsMessageParser
├── session/         JwtService, JwtPolicy, RefreshTokenStore (port),
│                    refresh-token logic
└── usecase/         RequestChallenge, VerifyAndAuthenticate, RefreshSession,
                     Logout, AuthEventStore (port)

w3auth-standalone-api — Spring Boot REST application
com.w3auth.backend
├── api/             REST controllers, request/response DTOs
├── config/          composition root: wires use cases as plain beans
├── infrastructure/  JPA entities + repos, Redis adapters, Flyway,
│                    Web3jChainClient (RPC adapter)
└── security/        Spring Security config, JwtAuthenticationFilter

w3auth-keycloak-plugin — Keycloak Authenticator SPI (fat JAR)
com.w3auth.keycloak
├── W3AuthAuthenticator / W3AuthAuthenticatorFactory
├── HttpChainClient  (zero-dependency ChainClient over java.net.http)
└── theme-resources/templates/w3auth-login.ftl
```

The M5 module split makes the core/framework boundary a compile-time
guarantee (`w3auth-core` has no Spring on its classpath). The **ArchUnit**
test (`LayerBoundaryTest` in `w3auth-standalone-api`) still guards the same
rule — core packages must not import Spring, JPA, Redis, or `infrastructure`.

## How we work together

- Small steps. One module or one endpoint at a time. Never generate the whole
  project in one shot.
- I (the human) read every diff before accepting it. Explain non-obvious
  design choices and tradeoffs as you go — I am learning backend engineering
  through this project.
- Apply the **rule of three**: build the first concrete implementation, do not
  add an interface or abstraction until a real second case forces it.
  `SignatureVerifier` began as a test seam with one implementation
  (`EthereumSignatureVerifier`); real cases arrived at M3
  (`ContractAwareSignatureVerifier`) and M4 (`SolanaSignatureVerifier`,
  `NamespaceRoutingSignatureVerifier`). The abstraction earned its keep. The
  same discipline applies to any new abstraction — no hypothetical future
  cases. The module split followed the same rule: it waited until the
  Keycloak plugin (M5) actually needed `w3auth-core` as its own artifact.
- If a request of mine weakens the architecture, push back and say so directly.
- No tutorial/demo shortcuts. Production-grade only.

## Testing

- JUnit for unit tests; Testcontainers to run a real Postgres and Redis in
  integration tests (and a real Keycloak for the plugin's end-to-end suite).
- Security-sensitive code (challenge, verify, session) must have tests for the
  failure paths: expired nonce, reused nonce, wrong domain, wrong chainId,
  signer mismatch.

## gstack skills to use (backend-relevant only)

- Plan a milestone: `/autoplan` or `/plan-eng-review`
- Spec a module: `/spec`
- After code is written: `/review`, then `/cso` (security), then `/codex`
  (second opinion) on crypto/session code
- Tests + PR: `/ship`
- Debugging: `/investigate`
- Save lessons: `/learn`

Ignore for this project: `/design*`, `/qa`, `/browse`, `/canary`, `/benchmark`
— they are for apps with a UI. This is a headless API.

## Project skills (Claude Code)

The `.claude/skills/` directory holds four skills that encode the working rules
for this project and are applied automatically before tasks in their domain:

- `w3auth-architecture` — locked identity model, layer boundaries, rule of
  three, when to split a module
- `w3auth-security` — security review checklist for challenge, verification,
  and session code paths
- `w3auth-journal` — journal discipline: write from the diff, same commit as
  the code, four-section entry format
- `w3auth-verification` — proof discipline: every "done" claim must cite a
  real artifact (HTML report, git diff, Redis output)

**When a skill and this document conflict, the skill and the repo are
authoritative.** Treat the conflict as a signal that this document has drifted
and should be reconciled.
