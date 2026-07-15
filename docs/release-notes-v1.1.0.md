# v1.1.0 — Native direct-grant login

Adds a native app path: a mobile/desktop client can now sign in with a wallet signature by
POSTing straight to Keycloak's OIDC token endpoint — no browser, no redirect, no embedded
webview. SIWE and SIWS both work end-to-end on this path, matching the browser flow's coverage.

## Highlights

- **Direct-grant authenticator** — a new `w3auth-direct-grant-authenticator`, bound to a
  client-scoped `direct_grant` flow override, that accepts `grant_type=password` with a wallet
  signature instead of a username/password and returns real Keycloak-issued tokens.
- **Challenge-issuing realm endpoint** — `POST /realms/{realm}/w3auth/challenge` builds the
  SIWE/SIWS message a native client needs to sign, unauthenticated, with the same server-authoritative
  domain/URI/nonce discipline as the browser flow.
- **SIWE + SIWS on the native path** — both namespaces verified end-to-end over direct-grant, not
  just the browser flow (Ethereum EOA and Solana Ed25519).
- **Single generic failure** — every rejection reason on the token endpoint collapses to one
  `invalid_grant` OAuth2 error, so a bad signature, a replayed nonce, and a domain mismatch are
  all indistinguishable to a client or attacker — no oracle.
- **Shared verification core** — the direct-grant path and the browser path verify signatures and
  provision users through the same collaborator (`W3AuthVerificationService`), so the v1.0.3
  stock-realm profile-completion fix applies identically to both, proven by a dedicated
  stock-realm regression test on the direct-grant path.
- **Wire contract documented** — see [`docs/native-api.md`](native-api.md) for the full
  request/response contract, realm configuration, and the semantics an SDK must honor
  (byte-exact message transport, single-use nonce, no client-side message modification).

## Configuration

Direct-grant reads the same realm attributes the challenge endpoint uses to build the message —
not `AuthenticatorConfig` — so both sides always agree on what was signed:

| Attribute                  | Default                 | Meaning |
|-----------------------------|--------------------------|---------|
| `w3auth.expected-domain`   | `localhost`              | App's declared metadata domain for native clients — not the Keycloak host |
| `w3auth.expected-uri`      | `http://localhost:8080`  | The signed message's `URI:` field |
| `w3auth.ethereum-rpc-url`  | unset                    | If set, EVM verification supports EIP-1271/6492 smart-contract wallets on this path too |

Full setup (realm attributes, the client-scoped `direct_grant` flow override) is documented in
[`docs/native-api.md`](native-api.md).

## Known gaps carried forward

Smart-contract wallet verification (EIP-1271/6492) is covered at the core layer against a live
Anvil chain, and the direct-grant path routes to the same verifier as the browser path — but no
Keycloak-plugin-level integration test yet exercises that RPC-backed branch end-to-end for either
flow. See the coverage note in [`docs/native-api.md`](native-api.md) for why this is deferred
rather than forced into this release.

## Assets

- `w3auth-keycloak-plugin-1.1.0.jar` — the Keycloak plugin (fat JAR)

The KMP SDK (a separate repo) is the intended client for this release's native direct-grant
contract.

---

Licensed under Apache-2.0. Built and maintained by [@aliIsazadeh](https://github.com/aliIsazadeh) — available for wallet-auth consulting and integration work: isazadhali@gmail.com
