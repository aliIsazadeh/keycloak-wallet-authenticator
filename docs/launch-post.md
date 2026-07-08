# Building a production-grade wallet-login authenticator for Keycloak

*SIWE, Solana, and smart-contract wallets — as a native Keycloak plugin, with no wallet SDK and no third-party auth service.*

---

If you already run Keycloak and you want users to log in with a crypto wallet, your
options today are bad. You can stand up a *second* OIDC server just for
Sign-In-With-Ethereum and federate it in. You can reverse-proxy your way through a
mismatch of endpoint paths and pray. Or you can find one of the handful of
open-source "Keycloak + Ethereum" projects on GitHub — every one of which, when I
went looking, turned out to be a proof-of-concept pinned to a dead testnet,
EOA-only, and never tested against a real Keycloak.

So I built the version that isn't a toy. This post is what it does, and the
engineering decisions I think are worth sharing.

## The one-sentence version

W3-Auth is a Keycloak Authenticator SPI plugin that lets users sign in with a wallet
— Ethereum (SIWE / EIP-4361) or Solana (SIWS), externally-owned or smart-contract
wallets — as one authenticator inside your existing browser flow. It doesn't replace
your passwords, MFA, or social logins. It sits next to them.

It supports EOA wallets, EIP-1271 deployed smart-contract wallets, and EIP-6492
counterfactual (not-yet-deployed) wallets, across EVM chains and Solana. It has zero
dependency on any wallet SDK, and it's tested end-to-end against a real Keycloak 25
running in Testcontainers.

## Decision 1: protocol-driven, not SDK-driven

The single most important design choice is what the backend refuses to know. It
doesn't know about Reown, WalletConnect, MetaMask, or Phantom. Every client, no
matter the vendor, collapses to the same three inputs: a `message`, a `signature`,
and a claimed `accountId`. No wallet vendor's concepts leak past the front door.

That's what lets the same verification engine power both the Keycloak plugin and a
standalone REST API without change. The engine is a framework-free Java library with
no Spring, JPA, or Redis on its classpath — a boundary enforced at compile time by
the module split and re-checked by an ArchUnit test.

## Decision 2: verification is claim validation, not address recovery

This is the mistake that turns a wallet login into a vulnerability. Recovering the
address that signed a message tells you *someone* signed *something*. It does not
tell you they meant to log into *your* site, right *now*.

So the plugin does all of this before anyone is authenticated:

- It recovers the signer **and** checks it equals the address claimed *inside* the
  signed message.
- It enforces **domain binding** — the SIWE `domain` must match your configured
  domain. This is the anti-phishing / cross-site-replay control. Skip it and a
  signature farmed on a phishing page replays against you.
- It validates the `uri`, and the `issuedAt` / `expiration` timestamps with a ±5
  minute clock-skew tolerance.
- The **nonce is single-use.** It's generated server-side (128-bit CSPRNG), stored
  in Keycloak's own authentication-session note, required to match on postback, and
  removed on success. No replay.

Notably, the nonce lives in Keycloak's session storage — not Redis. The plugin adds
*zero* new infrastructure. That was a hard requirement: a Keycloak operator should
be able to drop in a JAR, not stand up a datastore.

## Decision 3: smart-contract wallets without dragging web3j into Keycloak

EOA verification is just `ecrecover`. Smart-contract wallets are where it gets
interesting, because the wallet is a contract and "is this signature valid?" is a
question only the chain can answer.

- **EIP-1271** (deployed contract wallets): call the wallet's
  `isValidSignature` via an Ethereum node.
- **EIP-6492** (counterfactual wallets that aren't deployed yet): the signature is
  wrapped in an envelope that deploys the wallet counterfactually inside a single
  `eth_call` frame, checks the signature, and unwinds. The dispatch order matters —
  you have to detect the 6492 wrapper *first*, because it's a property of the
  signature, not the address, and can appear even on an already-deployed contract.

The catch: doing this normally means pulling in web3j-core, which drags RxJava and
OkHttp onto Keycloak's server classpath. So instead the plugin implements the chain
client over **Java 21's native `HttpClient`** with hand-rolled ABI encoding. If you
don't configure an RPC URL, EVM verification cleanly degrades to EOA-only. Keycloak's
classpath stays clean either way.

(One more packaging detail that costs everyone an afternoon the first time: the
plugin ships as a fat JAR but **excludes BouncyCastle**, because Keycloak already
provides it on the boot classpath and bundling a second copy causes runtime linkage
clashes.)

## Decision 4: identity is the address, not the chain

A wallet identity is modeled as a CAIP-10 account — `namespace:address` — and keyed
on exactly that. Not `(address, provider, chainId)`. The reason: for EVM, the same
private key controls every chain, so putting `chainId` in the identity key would
split one human into many accounts the moment they switch networks. Chain ID is
session context, not identity. The Keycloak username is the canonical
`namespace:address`, so a wallet owner is always the same Keycloak user.

## Using it

```bash
# build
./gradlew :w3auth-keycloak-plugin:jar

# install
cp w3auth-keycloak-plugin/build/libs/w3auth-keycloak-plugin-*.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build && /opt/keycloak/bin/kc.sh start
```

Then in the admin console, add the **Web3 Wallet Authenticator** to a copy of the
browser flow, set your expected domain and URI, optionally add an RPC URL for
smart-contract wallets, and you're done.

## Where it is, and where it isn't

It's open source under Apache-2.0. It's a real plugin, not a demo — but it's early,
and I'd genuinely like eyes on the security-sensitive paths. If you run Keycloak and
have wanted wallet login, try it and tell me where it breaks.

Repo: **[github.com/aliIsazadeh/w3-auth](https://github.com/aliIsazadeh/w3-auth)**

And if your team needs wallet auth or web3 identity wired into your stack — Keycloak
or otherwise — this is the kind of thing I build. I'm reachable at isazadhali@gmail.com.
