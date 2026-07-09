# v1.0.0 — First stable release

Production-grade wallet login for Keycloak: Sign-In With Ethereum (EIP-4361) and Sign-In With Solana as a native Authenticator SPI plugin. No wallet SDK, no third-party auth service, no new infrastructure — drop in one JAR.

## Highlights

- **SIWE + SIWS** — Ethereum (all `eip155` EVM chains) and Solana (Ed25519)
- **Smart-contract wallets** — EIP-1271 (deployed) and EIP-6492 (counterfactual, pre-deploy), via any JSON-RPC endpoint; cleanly degrades to EOA-only if no RPC URL is configured
- **Replay-protected** — single-use 128-bit CSPRNG nonces stored in Keycloak's own authentication-session notes (no Redis)
- **Anti-phishing** — server-authoritative domain and URI binding, ±5 min clock-skew tolerance on timestamps
- **Stable identity** — users keyed on CAIP-10 `namespace:address`, so one wallet is always one Keycloak user regardless of chain
- **Clean classpath** — chain client built on Java 21's native `HttpClient` (no web3j/RxJava/OkHttp); BouncyCastle excluded from the fat JAR (Keycloak provides it)
- **Tested for real** — end-to-end integration tests against a live Keycloak 25 in Testcontainers

## Requirements

- Keycloak 25+
- Java 21
- An EVM JSON-RPC endpoint (only if you want smart-contract wallet support)

## Install

```bash
cp w3auth-keycloak-plugin-1.0.0.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

Then in the admin console: **Authentication → Flows** → duplicate the **browser** flow → add the **Web3 Wallet Authenticator** execution → bind the flow to your realm.

## Configuration

| Setting | Key | Default |
| --- | --- | --- |
| Expected Domain | `expected-domain` | `localhost` |
| Expected URI | `expected-uri` | `http://localhost:8080` |
| Ethereum RPC URL | `ethereum-rpc-url` | *(empty — smart-contract wallets disabled)* |

Set `expected-domain` to your real domain in production — it is the anti-phishing control.

## Security

Signature verification is claim validation, not just address recovery: the recovered signer must equal the address claimed inside the signed message, and domain, URI, nonce, and expiry are all validated server-side before anyone is authenticated. Details in [docs/ARCHITECTURE.md](https://github.com/aliIsazadeh/keycloak-wallet-authenticator/blob/master/docs/ARCHITECTURE.md).

Found a vulnerability? See [SECURITY.md](https://github.com/aliIsazadeh/keycloak-wallet-authenticator/blob/master/SECURITY.md) — please don't open a public issue.

## Assets

- `w3auth-keycloak-plugin-1.0.0.jar` — the Keycloak plugin (fat JAR, ~6.2 MB)

---

Licensed under Apache-2.0. Built and maintained by [@aliIsazadeh](https://github.com/aliIsazadeh) — available for wallet-auth consulting and integration work: isazadhali@gmail.com
