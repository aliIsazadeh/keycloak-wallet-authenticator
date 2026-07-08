# Security Policy

Keycloak Wallet Authenticator is authentication software. Security reports are taken
seriously and handled with priority.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, report privately using one of:

- GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the repository's **Security** tab), or
- Email: **isazadhali@gmail.com**

Please include, as far as you can:

- The affected module and version (or commit).
- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof-of-concept.
- Any suggested remediation.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial **assessment** within 10 business days.
- Coordinated disclosure: I'll agree a disclosure timeline with you and credit you
  in the release notes and advisory unless you prefer to remain anonymous.

## Scope

Security-sensitive areas of particular interest:

- Signature verification (EOA `ecrecover`, EIP-1271, EIP-6492, Solana Ed25519).
- Nonce handling and replay protection.
- Domain / URI binding and message-field validation.
- Session and identity provisioning in the Keycloak Authenticator.

## Supported versions

The latest released version receives security fixes. Older versions are
best-effort. Until a `1.0` release, treat the `main` branch as the supported line.
