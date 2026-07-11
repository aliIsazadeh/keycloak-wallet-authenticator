# Keycloak Wallet Authenticator

**Production-grade, protocol-driven wallet login for Keycloak.** Let users sign in
with a crypto wallet — Ethereum (SIWE) or Solana (SIWS), externally-owned or
smart-contract wallets — as a native Keycloak Authenticator, with no wallet SDK
and no third-party auth service.

<!-- Badges: uncomment and fill in once CI + release are live
[![CI](https://github.com/aliIsazadeh/keycloak-wallet-authenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/aliIsazadeh/keycloak-wallet-authenticator/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Keycloak](https://img.shields.io/badge/Keycloak-25%2B-brightgreen)](https://www.keycloak.org)
-->

<img width="1200" height="592" alt="sample" src="https://github.com/user-attachments/assets/ec9d6738-2f48-4254-9d51-f010c173b74f" />


---

## Why this exists

Every existing "Sign-In With Ethereum + Keycloak" project I could find was an
abandoned proof-of-concept — pinned to dead testnets, EOA-only, no smart-contract
wallet support, and untested against a real Keycloak. Teams that already run
Keycloak for their identity and want to add wallet login are left wiring up a
second OIDC server or a fragile reverse-proxy hack.

Keycloak Wallet Authenticator is the version that isn't a toy: a real Authenticator SPI plugin,
built on a framework-free verification core, tested end-to-end against a live
Keycloak in Testcontainers.

## What it does

- **Adds wallet login to your existing Keycloak** as one Authenticator in a browser
  flow. Your passwords, MFA, and social logins stay exactly as they are — this is
  additive, not a replacement.
- **Verifies the signature, not just the address.** It recovers the signer, checks
  it matches the address claimed inside the signed message, and validates every
  server-authoritative field (domain, URI, nonce, issued-at / expiration) before
  anyone is logged in.
- **Provisions a stable Keycloak user** keyed on wallet identity, so switching
  chains never splits one wallet owner into multiple users.

## Feature matrix

| Capability | Status |
| --- | --- |
| SIWE — Sign-In With Ethereum (EIP-4361) | ✅ |
| SIWS — Sign-In With Solana | ✅ |
| EVM chains (`eip155`) | ✅ |
| Solana (Ed25519) | ✅ |
| EOA (externally-owned) wallets | ✅ |
| EIP-1271 deployed smart-contract wallets | ✅ |
| EIP-6492 counterfactual (pre-deploy) smart-contract wallets | ✅ |
| Single-use nonce (replay-protected) | ✅ |
| Domain / URI binding (anti-phishing) | ✅ |
| Tested against real Keycloak (Testcontainers) | ✅ |
| Zero wallet-SDK dependency | ✅ |
| Zero external auth service | ✅ |

## How it works

Two round trips, and the server is authoritative on domain, nonce, and expiry:

1. **Challenge.** When the Web3 Wallet Authenticator runs, it generates a 128-bit
   CSPRNG nonce, stores it in the Keycloak authentication-session note (no Redis, no
   extra infrastructure), and renders a login page that talks to the browser wallet
   (`window.ethereum` / Phantom `window.solana`).
2. **Verify.** On postback it parses the SIWE/SIWS message, requires the message
   nonce to equal the stored note (single-use — the note is removed on success),
   validates domain / URI / timestamps (±5 min skew), verifies the signature, and
   confirms the recovered signer equals the claimed address. Only then is a Keycloak
   user provisioned or logged in.

The Keycloak username is the canonical identity key `namespace:address`, so the same
wallet is always the same user regardless of chain. Address, namespace, and chain ID
are stored as user attributes (`w3auth_address`, `w3auth_namespace`, `w3auth_chainId`).

For EVM smart-contract wallets, the plugin talks to an Ethereum node over Java 21's
native `HttpClient` (`HttpChainClient`) — deliberately avoiding web3j-core so
Keycloak's server classpath stays clean.

## Quickstart

**Requirements:** Keycloak 25+, Java 21, an EVM RPC endpoint only if you need
smart-contract wallet support.

### 1. Build the plugin JAR

```bash
./gradlew :w3auth-keycloak-plugin:jar
# produces w3auth-keycloak-plugin/build/libs/w3auth-keycloak-plugin-<version>.jar
```

Or grab the prebuilt JAR from the [latest release](https://github.com/aliIsazadeh/keycloak-wallet-authenticator/releases).

### 2. Install it into Keycloak

```bash
cp w3auth-keycloak-plugin/build/libs/w3auth-keycloak-plugin-*.jar \
   /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

### 3. Add it to a browser flow

In the admin console: **Authentication → Flows**, duplicate the **browser** flow,
add an execution, choose **Web3 Wallet Authenticator**, and bind the flow to your
realm (or an application) as the browser flow.

### 4. Configure it

On the authenticator's config, set:

| Setting | Key | Default | Notes |
| --- | --- | --- | --- |
| Expected Domain | `expected-domain` | `localhost` | Must match the SIWE/SIWS `domain`. This is the anti-phishing control — set it to your real domain in production. |
| Expected URI | `expected-uri` | `http://localhost:8080` | Must match the message `uri`. |
| Ethereum RPC URL | `ethereum-rpc-url` | *(empty)* | JSON-RPC endpoint for EIP-1271 / EIP-6492 verification. **Leave empty and smart-contract wallets are disabled — EVM falls back to EOA-only.** |

That's it. Users can now log in with a wallet.

## Security model

- **Domain binding** is enforced — a signature valid for another site's domain is
  rejected. This is the anti-phishing / cross-site-replay control.
- **Single-use nonces** — the challenge nonce is consumed on verify and cannot be
  replayed.
- **Claim validation, not address recovery** — the recovered signer must equal the
  address inside the signed message; recovery alone authenticates nobody.
- **Server-authoritative fields** — domain, URI, and expiry are checked against
  server config and policy, with a ±5 minute clock-skew tolerance.

Found a vulnerability? See [SECURITY.md](SECURITY.md). Please do not open a public
issue for security reports.

## Repository layout

This repo is a multi-module Gradle build (Java 21, Kotlin DSL, centralized version
catalog):

| Module | Role |
| --- | --- |
| `w3auth-core` | Framework-free verification engine: identity, challenge, SIWE/SIWS parsing, signature verification, sessions. No Spring / JPA / Redis on its classpath. |
| `w3auth-keycloak-plugin` | The Keycloak Authenticator SPI plugin — **the product, and this README's focus**. Fat JAR, BouncyCastle excluded (Keycloak provides it). |
| `examples/self-hosted-rest-api` | **Reference example, not the product.** A standalone Spring Boot REST auth API built on the same core, showing how to self-host wallet login without Keycloak. See [its README](examples/self-hosted-rest-api/README.md). |

The same verification engine powers both the plugin and the reference REST API —
the architecture is protocol-driven, so no wallet vendor's code ever leaks into it.

## Design notes

The deeper reasoning — why identity is modeled as CAIP-10 `namespace:address`, why
nonces are consumed atomically, the EIP-6492 dispatch ordering, why HS256 for
short-lived tokens — lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Self-hosting without Keycloak (reference example)

Not running Keycloak? The repo ships a small **reference example** that
demonstrates the *same* verification core (`w3auth-core`) self-hosted as a
standalone Spring Boot REST API, with its own Postgres/Redis adapters and
challenge/verify/refresh/logout endpoints. It is a demonstration, **not the
product** — the Keycloak plugin above remains the headline. If you already run
Keycloak, ignore this; use the plugin.

See [`examples/self-hosted-rest-api`](examples/self-hosted-rest-api/README.md)
to run it.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Who built this

I build production-grade wallet and crypto-identity authentication infrastructure.
If your team needs wallet login in Keycloak (or elsewhere), or custom web3 identity
integration, I'm available for consulting and integration work.

- GitHub: [@aliIsazadeh](https://github.com/aliIsazadeh)
- Contact: isazadhali@gmail.com · [LinkedIn](https://www.linkedin.com/in/ali-isazadeh-7b2524215/)
