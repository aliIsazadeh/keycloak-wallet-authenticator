---
name: w3auth-verification
description: >-
  Proof discipline for the W3-Auth backend. Use this whenever reporting test
  results, build status, or whether something is "done" — anything that claims
  tests pass, a Testcontainers or Anvil run succeeded, a build is green, or a
  feature is complete. Also use it before closing out a work session. Forces
  every claim to be checked against a real artifact (HTML report, git diff,
  Redis output, docker ps) instead of a console total or a remembered number.
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

## Security-critical artifacts

Bytecode constants and signature test vectors are supplied and verified
externally, never hand-assembled here. Verify a bytecode constant is one
unbroken line on disk (e.g. `findstr` on Windows) rather than trusting a
summary that reports it. The real proof is behavioural: accept-valid +
reject-forged + reject-tampered, not a byte-for-byte comparison.

## Parallel-chat hazard

Work may be split across multiple chats. The authoritative state is the most
recent merged commit plus the current conversation. Refuse to act on stale
instructions carried over from another chat that contradict the merged repo.

## Closing a session

Don't end on "the code is written." Confirm: the relevant artifact was inspected
(report / diff / Redis), the full suite is green from a **clean** build, and the
git steps were done — feature branch, `--no-ff` merge to master, `status`,
push. State git steps explicitly; they are not optional closing details.



