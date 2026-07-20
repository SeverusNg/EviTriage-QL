# Known limitations

This document describes the checked-in **Gate A** baseline. Items below are
intentional scope boundaries, not implicit claims of partial implementation.

## Functional boundary

- Only local ProjectSpec targets can be materialized. The schema reserves typed
  Git/dataset identities for forward compatibility, but remote checkout,
  dataset acquisition, and submodule materialization are unavailable.
- `require_clean_git` is validated as configuration metadata, but Gate A does
  not invoke Git or calculate a dirty-patch digest. Formal Git-backed
  experiments wait for the repository-acquisition gate; local snapshots are
  identified by a complete source-tree SHA-256 instead.
- The implemented build configuration is metadata/validation only. Gate A
  accepts Maven declarations but does not execute Maven; Gradle, explicit
  commands, repository scripts, and arbitrary commands are unavailable.
- CodeQL discovery may be reported by `doctor`, but no CodeQL database or scan
  is created. The configured `2.26.1` version is a reference prerequisite for a
  later smoke run.
- SARIF ingest and normalization are not implemented.
- Path/function context, evidence registries, claims, and artifact-addressed
  evidence graphs are not implemented.
- Fake/Replay/real LLM adapters and Analyst/Rebuttal/Judge are not implemented.
- Deterministic TP/FP/NMC policy and JSONL/HTML reports are not implemented;
  therefore this gate produces no security classification.
- Verification sandboxes, calibration, benchmark datasets, paper statistics,
  PostgreSQL, and GitHub alert integration remain later milestones.

## Operational boundary

- SQLite is the only storage backend in Gate A and the schema is deliberately
  minimal; it is not a multi-user service database.
- Gate A reserves workflow-event rows but does not yet implement the workflow
  state machine or database-enforced append-only event semantics. Those audit
  guarantees begin with the corresponding later workflow gate.
- The workspace manager confines application-managed paths, but this is not an
  operating-system sandbox. Gate A intentionally does not execute target code.
- Environment diagnostics prove discoverability, not that an external tool can
  successfully analyze an arbitrary repository.
- The example fixtures demonstrate configuration switching and isolation; they
  are not a representative vulnerability benchmark.
- No clean-room release or real CodeQL smoke result should be inferred until it
  is recorded with an actual command and exit code in the progress log.

## Security and research interpretation

- A `license_hint` records operator-supplied metadata and is not legal advice or
  automated license verification.
- A successful ProjectSpec validation means that the configuration satisfies
  Gate A constraints. It says nothing about whether the target is safe to build
  or contains a vulnerability.
- The software is pre-release research infrastructure. Do not rely on it as the
  sole basis for vulnerability disclosure, alert dismissal, or production risk
  acceptance.

These limitations should be removed only in the same change that adds working
implementation, tests, and reproducibility evidence for the corresponding gate.
