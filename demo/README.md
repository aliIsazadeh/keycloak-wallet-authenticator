# Wallet-login demo (local only)

Spins up Keycloak 25 with the `w3auth-keycloak-plugin` installed and a
`wallet-demo` realm whose **browser flow** is the Web3 Wallet Authenticator
(`w3auth-authenticator`). Nothing here is security-hardened (HTTP only,
`sslRequired: none`, `admin`/`admin`, no TLS). Don't reuse this config outside
your machine.

## Quickstart (Docker only, no Java needed)

```bash
docker compose -f demo/docker-compose.yml up
```

This downloads the released plugin JAR from GitHub and starts Keycloak with
`start-dev --import-realm`, which auto-imports `demo/realm-export.json`
(realm `wallet-demo`) on boot. Wait for
`Running the server in development mode` in the logs.

To pin a different plugin version: `W3AUTH_VERSION=1.1.0 docker compose -f demo/docker-compose.yml up`.

## Try the wallet login

Open:

```
http://localhost:8080/realms/wallet-demo/account
```

This redirects into the realm's browser flow, which is bound entirely to the
Web3 Wallet Authenticator — you'll land straight on the wallet-signature
login page. Connect a wallet (MetaMask for Ethereum, Phantom for Solana),
sign the SIWE/SIWS message, and you're in.

- **Expected domain:** `localhost:8080`
- **Expected URI:** `http://localhost:8080`

(These match the authenticator's defaults, set explicitly in
`realm-export.json` under `authenticatorConfig`.)

> **Configuration:** `expected-domain` must equal the browser-facing origin
> authority exactly — host, plus port when non-default — because wallets
> enforce EIP-4361 domain-binding. Since Keycloak here is served at
> `localhost:8080`, `expected-domain` must be `localhost:8080`, not bare
> `localhost` — otherwise the wallet rejects the sign-in with an error like
> *"the domain in the sign-in message does not match the requesting app's
> origin"*, which gives no hint that the fix is in Keycloak's authenticator
> config.

## Running against a locally built JAR (dev workflow)

Working on the plugin itself? Build the fat JAR and run the local variant,
which mounts `w3auth-keycloak-plugin/build/libs/` instead of downloading a
release:

```bash
./gradlew :w3auth-keycloak-plugin:jar
docker compose -f demo/docker-compose.local.yml up
```

The whole `build/libs` directory is mounted, so the demo is not coupled to a
specific version string — any JAR Gradle writes there is picked up
automatically.

## Note: account clients are intentionally not in the realm export

`realm-export.json` deliberately does **not** define the stock `account` /
`account-console` clients. Keycloak's realm import bootstraps them itself, and
that bootstrap is what composites `view-profile` / `manage-account` into
`default-roles-<realm>`. Hand-defining those clients suppresses the bootstrap,
so wallet users (auto-granted the default role by `addUser()`) end up without
`account:view-profile` and the Account Console fails with a 401. Leave them out.

## Admin console

`http://localhost:8080/admin` — login `admin` / `admin` — if you want to poke
at the realm, flow, or authenticator config directly.

## Recording the README demo GIF

See [RECORDING.md](RECORDING.md) for the shot list and the ffmpeg commands
that turn a screen capture into the optimized `demo/demo.gif` used at the top
of the root README.

## Teardown

```bash
docker compose -f demo/docker-compose.yml down -v
```

The `-v` drops Keycloak's embedded database volume (and the downloaded-plugin
volume), so the next `up` reimports the realm fresh.
