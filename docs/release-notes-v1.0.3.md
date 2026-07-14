# v1.0.3 — Stock-realm required-action fix

Recommended upgrade if you self-host on a Keycloak 25 realm with default settings:
v1.0.2 wallet login diverted to an unexpected "Update Account Information" screen
after a valid signature, instead of completing directly.

- Fix: wallet-provisioned users now get their profile completed (address-derived
  placeholder first name / last name / email) at first login, so Keycloak's
  default declarative user profile no longer triggers a `VERIFY_PROFILE`
  diversion on realms that haven't disabled it. Login now completes in one
  round trip on any stock Keycloak 25 realm. Full investigation and evidence:
  `docs/investigation-stock-realm-required-actions.md`.
- Docs: README now explains the placeholder profile data and how to configure
  your realm if you want to collect a real email/name from wallet users
  instead.

Who's affected: self-hosters running a Keycloak realm with its default
declarative user-profile settings (no custom required-action configuration).
The bundled demo realm and existing test realms were not affected by the
underlying bug — they already disabled the relevant required action — so this
was a self-hosting gap, not a live-demo regression.

v1.0.2 users on stock (default) Keycloak realms should upgrade.

Download w3auth-keycloak-plugin-1.0.3.jar below and verify it against
checksums-1.0.3.txt.
