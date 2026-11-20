---
name: Change Review
description: Read recent git changes, suggest simple numbered fixes, apply only the ones the user picks, and verify before reporting
---

# Change Review & Minimal Fixes

Workflow for "read the changes" requests followed by fixing a subset of
the findings.

## 1. Read the changes

- `git status --porcelain` + `git log --oneline -5` to locate the target.
  If the working tree is clean, review the latest commit.
- Dump the diff to a temp file and read it in full — large diffs run to
  thousands of lines; don't sample or summarize from stats alone.
- Cross-check findings against the current tree with `grep` (references to
  removed symbols, leftover identifiers, files that became unreferenced).

## 2. Suggest fixes

- Enumerate issues as a **numbered list**; each item gets a concrete
  minimal fix, an effort estimate, and a recommendation
  (do / skip / user's call).
- Keep fixes simple: delete dead code, restore missing coverage, one-line
  default or constant changes. No refactors.
- Do not propose changes to anything the project marks as sensitive —
  consult the project's AGENTS.md / contributing docs first.

## 3. Apply only what the user picks

- Wait for the user to select task numbers before editing anything.
- Before deleting a file: grep the whole source tree for references —
  including the symbol's own declaration — and confirm zero hits.
- When editing bounds, guards, or safety checks, preserve the existing
  structure and change only the intended value; guards exist for reasons
  that may not be obvious from the diff.

## 4. Verify

- Run the project's test suite / verification commands (check the
  project docs for the exact command and any required environment).
- Capture the full output, including compiler/linter warnings.
- Distinguish warnings caused by your changes from pre-existing ones:
  if the baseline is unclear, run the suite once before editing to
  establish it.

## 5. Report

- State per task: what changed, which files, verification result.
- List pre-existing warnings observed during verification — even ones
  you didn't cause — so they stay on record, but mark them clearly as
  pre-existing and out of scope.
- Note tasks the user deferred so they aren't lost.
- Leave changes uncommitted unless asked to commit.
