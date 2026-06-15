# CLAUDE.md — Wallet Authentication Backend

This file is the steering wheel for the project. Read it before every task.
The full reasoning lives in `docs/ARCHITECTURE.md` — read that too for any
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

## Tech stack

- Java 21, Spring Boot, Spring Security
- Gradle (Kotlin DSL)
- PostgreSQL (durable data), Redis (ephemeral data)
- Hibernate / JPA, Flyway for migrations
- JWT for access tokens, JUnit + Testcontainers for tests
- Docker / docker-compose for local Postgres + Redis

## V1 scope (hold this line)

IN scope:
- SIWE only (EIP-4361)
- EVM chains only
- EOA (normal) wallets only

OUT of scope for V1 (do not build yet):
- Solana / non-EVM chains
- SIWX abstraction layer
- Plugin system or protocol registry
- Smart-contract wallet verification (EIP-1271 / EIP-6492) — that is M3
- JWT denylist / instant access-token revocation
- Multi-module Gradle build (single module + packages for now)

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
5. **Ephemeral vs durable split.** Nonces/challenges live in **Redis only**
   with a TTL and are **never** written to Postgres. Wallet identities,
   refresh tokens, and audit logs live in Postgres.
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

## Package layout (single module, V1)

```
com.<org>.walletauth
├── identity/        CaipAccountId, Namespace, WalletIdentity
├── challenge/       Challenge, Nonce, ChallengeStore (port), ChallengePolicy
├── verification/    SignatureVerifier, EthereumSignatureVerifier, SIWE parser
├── session/         access/refresh token logic, SessionStore (port)
├── usecase/         RequestChallenge, VerifyAndAuthenticate, RefreshSession, Logout
├── infrastructure/  JPA entities + repos, Redis adapters, Flyway
├── security/        Spring Security config, JWT filter
└── api/             REST controllers, request/response DTOs
```

Enforce "core packages (identity, challenge, verification, session, usecase)
must not import Spring or infrastructure" with an **ArchUnit** test. This
replaces multi-module boundaries for now.

## How we work together

- Small steps. One module or one endpoint at a time. Never generate the whole
  project in one shot.
- I (the human) read every diff before accepting it. Explain non-obvious
  design choices and tradeoffs as you go — I am learning backend engineering
  through this project.
- Apply the **rule of three**: build the first concrete implementation, do not
  add an interface or abstraction until a real second case forces it. The one
  allowed interface (`SignatureVerifier`) exists as a test seam, not for a
  future protocol.
- If a request of mine weakens the architecture, push back and say so directly.
- No tutorial/demo shortcuts. Production-grade only.

## Testing

- JUnit for unit tests; Testcontainers to run a real Postgres and Redis in
  integration tests.
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
