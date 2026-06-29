---
name: w3auth-journal
description: >-
  How to write docs/JOURNAL.md entries for the W3-Auth backend. Use this
  whenever finishing a step or feature and writing its journal entry, or just
  before a milestone merge. Also use it when updating the journal's big-picture
  section after a structural change. Encodes the two-part structure, the
  two-commit citation rule (code first, journal entry second citing the code
  hash), and the What / Why-with-rejected-alternative / Learned / Open-next
  entry format written from the diff, not from memory.
---

# W3-Auth journal discipline

`git`, the tests, `CLAUDE.md`, and `docs/ARCHITECTURE.md` hold the mechanical
record of *what* was built. The journal captures what those can't: the **why**,
the **rejected alternative**, and the **lesson**. If the journal would only
restate the diff, it isn't pulling its weight.

## Two parts

- **Part 1 — Big Picture.** Update **only** when the project's structure
  changes: a new milestone, a package added, the roadmap revised. Holds the
  project summary, package map, and roadmap.
- **Part 2 — Step Log.** A new entry per step, written on the feature branch in
  a **second commit** that follows the code commit and cites it by hash. Never
  backfilled as an afterthought, never a retroactive rewrite of "what we always
  intended."

## Entry format (Part 2)

Each entry has four sections:

- **What** — the concrete change: classes/files added or modified, the test
  coverage. Write it from the actual diff.
- **Why** — the reasoning, *including the alternative that was rejected and the
  reason it lost*. This is the heart of the entry.
- **Learned** — the durable engineering lesson, phrased so it generalizes.
- **Open / next** — what was deferred and what comes next.

Each entry's heading carries the milestone, a short title, and the commit hash,
e.g. `## M3a · step N — <title>   (commit <hash>)`.

## Write from the diff, not memory

Drafting from the diff surfaces gaps that memory papers over — for example, an
assertion that was added to one test class but silently missing from another.
Memory tends to record the intent; the diff records what actually shipped.

## Cadence

One JOURNAL entry per feature, written on the feature branch in **two commits**
before the `--no-ff` merge to master:

1. **Commit the code.** That commit produces the hash the entry will cite.
2. **Write the JOURNAL entry as a second commit** on the same branch, citing the
   code commit's hash in the heading. One shot — no amend, no stamp commit, no
   placeholder.

Both commits land on the feature branch before the merge. The entry is never
backfilled after merge and never a retroactive rewrite.

Heading format: `## <milestone> · <step> — <title>   (commit <code-hash>)`.
