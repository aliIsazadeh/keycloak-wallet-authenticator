---
name: w3auth-architecture
description: >-
  Architecture guardrails for the W3-Auth wallet-authentication backend.
  Use this whenever adding or changing code, deciding where new code
  belongs, naming a package, or considering a new interface, abstraction,
  Gradle module, dependency, or registry. Apply it before writing the code,
  not after. Encodes the locked CAIP-10 identity model, the core/infra layer
  boundaries enforced by ArchUnit, the ephemeral-vs-durable split, and the
  rule of three. If a request would weaken any of these, push back first.
---

# W3-Auth architecture guardrails

Source of truth is the live repo plus `ANTIGRAVITY.md` and `docs/ANTIGRAVITY_ARCHITECTURE.md`.
The project-knowledge copies of those docs can lag the repo — when a doc
conflicts with the repo or the current conversation, the repo wins, and the
drift should be flagged explicitly.

## What this backend is

It proves a client controls a wallet private key, then issues a login session.
It is **protocol-driven, not SDK-driven**: every client reduces to
`(message, signature, accountId)`. Never import or depend on Reown,
WalletConnect, or any wallet SDK — today's mobile client happening to use Reown
AppKit changes nothing.

## Identity model (locked)

- Identity is **CAIP-10**: `namespace:reference:address`.
- The unique key is `(namespace, address)`. **Address is identity; chainId is
  session context.** Never key identity on `(address, provider, chainId)` —
  that splits one wallet into many identities across EVM chains.
- `CaipAccountId` canonicalizes (lowercases the EVM address) in its factory.
  An un-normalized or structurally invalid `CaipAccountId` must be impossible
  to construct. Everything downstream speaks `CaipAccountId`, never raw strings.

## Layer boundaries (ArchUnit-enforced)

The core packages — `identity`, `challenge`, `verification`, `session`,
`usecase` — must not import Spring, JPA, Redis, or `infrastructure`. Keep them
plain Java. Concretely:

- Use cases are plain objects (no `@Service`). Spring wiring lives only in
  `config` (the composition root) and `infrastructure`.
- JSON/serialization shapes (e.g. a flat record for Redis) live in
  `infrastructure`, not in core, so Jackson never leaks into `challenge` or
  `identity`.
- A `@Configuration` class has one job; don't park an unrelated bean in it.

If a change would make a core package import the framework, that is a boundary
break — find the right home for it instead.

## Rule of three

Build the first concrete implementation. Do **not** add an interface,
abstraction, module split, or protocol registry until a real second case forces
it. The one allowed interface (`SignatureVerifier`) exists as a test seam, not a
future-protocol hook. "We might need it for Solana later" is not justification.

## Ephemeral vs durable split

Nonces and challenges live in **Redis only**, with a TTL, and are **never**
written to Postgres. Wallet identities, refresh tokens, and audit logs live in
**Postgres**, owned by Flyway migrations.

## When to actually split a module

Only when a heavy dependency needs isolating (the web3j / RPC client at M3) or
when publishing the wire contract as its own artifact. Not before.

## Pushback is expected

If a request weakens the architecture — "add a plugin registry now", "put
chainId in the identity key", "annotate the use case with `@Service`", "pull in
a wallet SDK for convenience" — say so directly and explain the tradeoff before
writing any code. No tutorial/demo shortcuts; production-grade only.
