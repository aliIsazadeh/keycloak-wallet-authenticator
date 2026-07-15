# Native direct-grant wire contract

**Minimum plugin version: 1.1.0.**

This is the contract a native client (no browser, no redirect) signs against to log a wallet
in through Keycloak's OIDC token endpoint. It is generated from the actual provider code —
[`W3AuthChallengeResourceProvider`](../w3auth-keycloak-plugin/src/main/java/com/w3auth/keycloak/W3AuthChallengeResourceProvider.java)
and
[`W3AuthDirectGrantAuthenticator`](../w3auth-keycloak-plugin/src/main/java/com/w3auth/keycloak/W3AuthDirectGrantAuthenticator.java)
— not from a spec, so it cannot drift out of sync with what the plugin actually does. The KMP
SDK (a separate repo) is the intended client of this contract.

## Flow

```
1. POST /realms/{realm}/w3auth/challenge   → { messageHex, nonce, expiresAt }
2. Wallet signs the exact bytes of messageHex
3. POST /realms/{realm}/protocol/openid-connect/token   grant_type=password
                                                          → standard OIDC token response
```

## 1. Challenge — `POST /realms/{realm}/w3auth/challenge`

Unauthenticated. Request body (JSON):

| Field       | Required | Notes                                   |
|-------------|----------|------------------------------------------|
| `accountId` | yes      | CAIP-10 string, e.g. `eip155:1:0xabc...` or `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:<base58 address>` |
| `clientId`  | no       | Recorded alongside the nonce; not otherwise validated by this endpoint |

Success response (`200`, JSON):

```json
{ "messageHex": "<hex of UTF-8 message bytes>", "nonce": "<hex nonce>", "expiresAt": "<ISO-8601>" }
```

`messageHex` is a SIWE (EIP-4361) message for `eip155:*` account ids, or a SIWS (Sign-In With
Solana) message for `solana:*` account ids — the endpoint dispatches on the CAIP-10 namespace.

Error response (`400`, JSON): `{"error":"invalid_request"}` — returned for a missing/blank body,
a missing/blank `accountId`, or an `accountId` that fails CAIP-10 parsing or namespace-specific
address validation. The response never echoes the rejected input.

## 2. Token — `POST /realms/{realm}/protocol/openid-connect/token`

Standard OIDC token endpoint, `grant_type=password`, with these fields:

| Field                 | Required | Notes |
|-----------------------|----------|-------|
| `grant_type`          | yes      | Must be `password` |
| `client_id`           | yes      | Must be a client with this realm's `direct_grant` flow bound to `w3auth-direct-grant-authenticator` (via `ClientRepresentation.authenticationFlowBindingOverrides`, client-scoped — see realm setup below) |
| `w3auth_account_id`   | yes      | The same CAIP-10 string passed to the challenge endpoint |
| `w3auth_message_hex`  | yes      | The `messageHex` returned by the challenge endpoint, byte-for-byte unmodified |
| `w3auth_signature`    | yes      | The wallet's signature over the message bytes — hex (`0x`-prefixed or bare) for both EVM (65-byte ECDSA) and Solana (64-byte Ed25519); Solana signatures also accept base58 |

Success: a standard OIDC token response (`200`) — real Keycloak-issued `access_token` and
`refresh_token`, same as any other grant.

Failure: **always** `401` with a generic OAuth2 `invalid_grant` error body —
`{"error":"invalid_grant","error_description":"Invalid wallet credentials"}` — regardless of
which check failed (missing fields, malformed hex, nonce missing/expired/already-consumed,
`w3auth_account_id` not matching the account the nonce was issued for, domain/uri/expiry
mismatch, bad signature, signer-address mismatch, or a pre-registration username collision).
This is deliberate: a distinguishable error per failure reason would be an oracle for an
attacker probing account existence or nonce validity. Do not branch client-side logic on the
error body's contents beyond checking `error == "invalid_grant"`.

## Realm configuration (realm attributes)

Set on the realm (admin API), not on `AuthenticatorConfig` — a native client's flow has no
authenticator-config context reachable at the challenge endpoint, so both the challenge endpoint
and the direct-grant authenticator read the same realm attributes to guarantee they agree:

| Attribute                     | Default                  | Meaning |
|--------------------------------|--------------------------|---------|
| `w3auth.expected-domain`      | `localhost`               | For native clients, this is the **app's declared metadata domain** (e.g. the universal-link / Apple App Site Association domain) — **not** the Keycloak host. Wallets bind the signed SIWE/SIWS domain field to the app's registered domain. |
| `w3auth.expected-uri`         | `http://localhost:8080`   | The `URI:` field of the signed message; server-authoritative, checked against the message at verify time. |
| `w3auth.ethereum-rpc-url`     | unset                     | If set, EVM verification routes through `ContractAwareSignatureVerifier` (EIP-1271 deployed / EIP-6492 counterfactual smart-contract wallets) instead of EOA-only `ecrecover`. If unset, only EOA wallets verify. |

Realm setup also requires a client-scoped `direct_grant` flow override: a custom flow whose
single execution is `w3auth-direct-grant-authenticator`, bound via
`ClientRepresentation.authenticationFlowBindingOverrides` — see
[`W3AuthDirectGrantIntegrationTest`](../w3auth-keycloak-plugin/src/test/java/com/w3auth/keycloak/W3AuthDirectGrantIntegrationTest.java)
for the exact admin-API sequence. This is client-scoped: the realm's default `direct_grant`
flow and other clients are unaffected.

## Semantics the SDK must honor

- **`messageHex` is byte-exact.** The bytes the wallet signs must be exactly the bytes returned
  in `messageHex` — decode the hex to raw bytes, sign those bytes, do not re-encode, reformat,
  or normalize whitespace/casing. The server hashes/verifies against those exact bytes; any
  re-encoding breaks signature verification.
- **The nonce is single-use with a 300-second TTL.** It is consumed atomically
  (`SingleUseObjectProvider.remove`) on the first token request that reaches it — a replayed
  token request with the same nonce always fails, even with a byte-identical valid signature.
- **The client validates but never modifies the server message.** There is no client-side
  template for constructing a SIWE/SIWS message from scratch for this flow — the server is
  authoritative on domain, uri, nonce, and timestamps (architecture decision #8). The client's
  job is: request a challenge, present the returned message to the wallet unmodified, submit
  the wallet's signature.

## Coverage note — EIP-1271 / EIP-6492 on the direct-grant path

Smart-contract wallet verification itself (EIP-1271 deployed contracts, EIP-6492 counterfactual
contracts) is covered at the core layer against a live Anvil chain:
`ContractAwareSignatureVerifierTest` and `ContractAwareVerifierIntegrationTest` (core module) and
`Eip6492CounterfactualIntegrationTest` (`examples/self-hosted-rest-api`). The direct-grant
authenticator routes to the same `ContractAwareSignatureVerifier` as the browser authenticator,
through the same `W3AuthVerificationService` collaborator, whenever `w3auth.ethereum-rpc-url` is
set — it is not separate code.

What is **not yet covered**: no Keycloak-plugin-level integration test (browser or direct-grant)
exercises the `w3auth.ethereum-rpc-url`-configured branch end-to-end against a live chain. This
is a pre-existing gap (it predates the direct-grant work — the browser authenticator has the same
gap) rather than something Slice C introduced. Wiring Anvil into the plugin module's Testcontainers
suite would mean either pulling `web3j-core` into the plugin's test classpath or hand-rolling
contract deployment over `HttpChainClient` — disproportionate for v1.1 given the plugin module's
deliberate choice to keep `web3j-core` off its classpath entirely (see the root `CLAUDE.md`).
Deferred to a later milestone.
