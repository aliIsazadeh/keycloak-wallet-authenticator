---
name: w3auth-verification
description: >-
  Proof discipline for the W3-Auth backend and its SDKs. Use this whenever
  reporting test results, build status, or whether something is "done" —
  anything that claims tests pass, a Testcontainers or Anvil run succeeded, a
  build is green, or a feature is complete. ALSO use it whenever writing,
  reviewing, or pinning ANY cryptographic constant or test vector (addresses,
  hashes, signatures, public keys, bytecode, checksummed hex, golden vectors).
  Also use it before closing out a work session. Forces every claim to be
  checked against a real artifact (HTML report, git diff, Redis output,
  docker ps) instead of a console total or a remembered number.
---

# Verifying claims for W3-Auth

**"Done" means watching it work, not "the code exists."** Check every claim
against an actual artifact — file contents, `git diff`, the HTML test report,
Redis output — never against a summary or memory.

## Test counts (authority rule)

Test counts come **only** from the per-class lines in
`build/reports/tests/test/index.html`. Never quote the Gradle console total or a
number from conversation. A hallucinated count is exactly why this rule exists;
treat any count not read from that HTML report as unverified.

## Testcontainers validity

A Testcontainers-based test only counts as genuinely run if `docker ps`
confirmed Docker was up **before** the run. A Docker-down run can cache a false
failure that looks real. Confirm Docker first, then trust the result.

## Anvil quirk (load-bearing)

When using the Anvil EVM node in a Testcontainers harness:

- Anvil CLI flags are silently ignored. Set the bind address via the
  `ANVIL_IP_ADDR=0.0.0.0` environment variable, not a flag.
- Readiness requires a real RPC probe. A bare port-listening check is not
  enough — the port can be open before the node answers RPC.

## Concurrency tests

Concurrency tests must call the real adapter through the Spring proxy, not raw
SQL or raw Redis commands — otherwise they don't exercise the production path.
Do not pre-warm the connection pool to suppress a legitimate failure; that's a
blindfold, not a fix.

## Crypto constants & golden vectors (NEVER hand-type)

**No cryptographic constant is ever typed, retyped, or "transcribed" by hand.**
Not an address, hash, signature, public key, checksummed-hex string, bytecode
blob, or golden-vector expected value. This has failed three separate times in
this project, each caught late:

1. `Eip55ChecksumTest`'s first golden vector was hand-typed with ONE
   wrong-case character (`...88F6f4` vs canonical `...88F6F4`) — a fixture
   that would have failed a correct implementation. The exact bug class this
   project exists to catch, reintroduced by the test guarding against it.
2. The SIWS reject-wrong-key test shipped `@Disabled` because the RFC 8032
   TEST 1 pubkey's base58 form could not be trusted as typed; it was enabled
   only after the encoding was independently confirmed.
3. Bytecode constants required a four-layer proof chain because a single
   mutated byte silently breaks everything downstream.

A pinned constant must arrive by exactly one of these routes:

- **Copy-paste from the canonical source** (EIP/RFC spec examples, compiled
  `.bin` output) — mechanically, never read-and-retype. EIP-55 vectors come
  byte-for-byte from the spec's own example addresses.
- **Programmatic generation with the same primitive the code verifies
  against** — e.g. the `DirectGrantSiwsIntegrationTest` pattern: BouncyCastle
  `rfc8032.Ed25519` keypair generated with explicit length assertions, its
  base58 address round-tripped through the project's own
  `SolanaPublicKey.decode` BEFORE being pinned.
- **Human-supplied verified artifact** (bytecode): four layers before trust —
  (1) provenance from the canonical source; (2) stored as ONE unbroken line
  on disk (check with `findstr`/`grep -c`, not a summary); (3) byte-for-byte
  length comparison against the compiled source; (4) a live behavioural run.

**Golden vectors for the SDK (spec §7) follow the same law:** every expected
value is emitted by a generator script or captured from the already-proven
backend e2e flow (the v1.1.0 direct-grant tests are a trusted oracle), written
to a vectors file that tests consume. A hand-typed "golden" value is worse
than no test — it enshrines the typo as truth and fails correct code.

The final proof is always behavioural, not byte comparison: accept-valid +
reject-forged + reject-tampered. Before pinning any constant, round-trip it
through the project's own decoder and assert the result.

## Parallel-chat hazard

Work may be split across multiple chats. The authoritative state is the most
recent merged commit plus the current conversation. Refuse to act on stale
instructions carried over from another chat that contradict the merged repo.

## Closing a session

Don't end on "the code is written." Confirm: the relevant artifact was inspected
(report / diff / Redis), the full suite is green from a **clean** build, and the
git steps were done — feature branch, `--no-ff` merge to master, `status`,
push. State git steps explicitly; they are not optional closing details.
