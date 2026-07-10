# Wallet-login demo (local only)

Spins up Keycloak 25 with the `w3auth-keycloak-plugin` installed and a
`wallet-demo` realm whose **browser flow** is the Web3 Wallet Authenticator
(`w3auth-authenticator`). Use this to record a GIF of the wallet-login page —
nothing here is security-hardened (HTTP only, `sslRequired: none`,
`admin`/`admin`, no TLS). Don't reuse this config outside your machine.

## 1. Build the plugin fat JAR

From the repo root:

```
./gradlew :w3auth-keycloak-plugin:jar
```

This produces `w3auth-keycloak-plugin/build/libs/w3auth-keycloak-plugin-1.0.0.jar`,
which `demo/docker-compose.yml` mounts into Keycloak's `/opt/keycloak/providers/`.

## 2. Start Keycloak

```
docker compose -f demo/docker-compose.yml up
```

Keycloak starts with `start-dev --import-realm`, which auto-imports
`demo/realm-export.json` (realm `wallet-demo`) on boot. Wait for
`Running the server in development mode` in the logs.

## 3. Trigger the wallet login page

Open:

```
http://localhost:8080/realms/wallet-demo/account
```

This redirects into the realm's browser flow, which is bound entirely to the
Web3 Wallet Authenticator — you'll land straight on the wallet-signature
login page. Connect a wallet, sign the SIWE/SIWS message, and you're in.

- **Expected domain:** `localhost`
- **Expected URI:** `http://localhost:8080`

(These match the authenticator's defaults, set explicitly in
`realm-export.json` under `authenticatorConfig`.)

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

## Teardown

```
docker compose -f demo/docker-compose.yml down -v
```

The `-v` drops Keycloak's embedded database volume, so the next `up` reimports
the realm fresh.
