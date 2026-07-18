# Self-Hosted REST API — reference example

> **This is not the product.** The product is the **Keycloak Wallet Authenticator**
> plugin (see the [root README](../../README.md)). This module is a working
> reference example that shows how to self-host wallet login as a standalone
> service for teams that do **not** run Keycloak.

It is a Spring Boot REST API built on the very same framework-free verification
engine (`w3auth-core`) that powers the Keycloak plugin. Nothing is forked or
re-implemented — the identity model, SIWE/SIWS parsing, signature verification
(EOA / EIP-1271 / EIP-6492), and session logic are all the shared core. This
example just adds a different set of adapters (Spring MVC, JPA/Postgres,
Redis) around it, demonstrating that the core is protocol-driven and carries no
wallet-vendor or transport assumptions.

The ArchUnit `LayerBoundaryTest` lives here and still enforces `w3auth-core`'s
framework-freedom — that core packages never import Spring, JPA, Hibernate, or
Redis — from the perspective of this example module. That guard is intentional
and stays green.

## What it demonstrates

- The two-round-trip challenge/verify flow as HTTP endpoints.
- Rotating refresh tokens with reuse detection, plus logout.
- The ephemeral-vs-durable split: nonces/rate-limits in **Redis** (TTL, never
  persisted), wallet identities / refresh tokens / audit log in **PostgreSQL**
  (owned by Flyway migrations).
- `Web3jChainClient`, the web3j-core RPC adapter of the `ChainClient` port (the
  Keycloak plugin uses a zero-dependency `HttpChainClient` instead).

## Running it

**Tests** use Testcontainers, so they spin up real Postgres and Redis (and, for
the smart-contract paths, a chain) automatically — Docker must be running:

```bash
# from the repo root
./gradlew :examples:self-hosted-rest-api:test
```

**Locally**, bring up Postgres + Redis with this example's `docker-compose.yml`,
then run the app:

```bash
# from the repo root
docker compose -f examples/self-hosted-rest-api/docker-compose.yml up -d   # starts postgres + redis
./gradlew :examples:self-hosted-rest-api:bootRun
```

See [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) for the design reasoning
behind the identity model, the ephemeral/durable split, and the session design.
