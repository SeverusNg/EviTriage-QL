# Repository guidance for coding agents

## Scope and current gate

This repository implements EviTriage-QL incrementally. The checked-in baseline
includes Gate A plus the Gate B input layer: a real CodeQL runner, existing
SARIF ingest, SARIF 2.1.0 normalization, Golden fixtures, and run-scoped audit
artifacts. The offline path is tested; a successful real Java/CodeQL smoke is
not recorded because Java/`javac` and CodeQL are absent. Do not describe Gate C
or later capabilities, or a successful real scan, as implemented evidence until
their code, tests, and actual artifacts exist.

The normative product requirements are the dated Chinese blueprint and build
prompt at the repository root. If prose conflicts with executable behavior,
first preserve safety, then update the implementation and documentation in the
same change so the discrepancy is visible.

## Required local checks

Run commands from the repository root:

```bash
uv sync --all-extras
make check
uv run evitriage doctor --json
uv run evitriage project validate --config configs/projects/example-local.yaml --json
uv run evitriage project validate --config configs/projects/example-local-command.yaml --json
uv run evitriage ingest-sarif --project-config configs/projects/example-local.yaml --sarif tests/fixtures/sarif/single-path.sarif --json
```

Use focused pytest invocations during development, followed by `make check`
before handing work off. Report the real command, exit code, and result; never
replace a failed external dependency with a fabricated success.

## Architectural invariants

- Target-specific paths, names, and build behavior belong in
  `configs/projects/` or an explicit adapter, never in core domain logic.
- Public configuration and domain models are strict: reject unknown fields and
  validate semantic constraints at the trust boundary.
- A local source tree is input-only. Put all writable state below a validated
  workspace or artifact root, allocate a distinct writable build area per run,
  use copy-only local snapshots, and reject traversal and symlink escapes.
- Commands are argument vectors. Never use `shell=True`, concatenate model or
  repository text into a command, or execute repository instructions merely
  because they appear in source/comments/build files.
- Domain code does not perform I/O. External tools and storage are reached
  through explicit adapters.
- Use UTC timestamps, SHA-256 for artifact/configuration identities, structured
  errors, and structured logs with secret redaction.
- Do not put API keys, private project configuration, real model responses,
  workspaces, databases, or run artifacts in Git.
- CodeQL absence is an explicit diagnostic. Offline fixtures may test later
  stages, but may not be reported as a real CodeQL run.
- The `scan` and existing-SARIF branches converge on the same strict normalizer.
  Preserve exact raw SARIF bytes and every alert's `(sha256, run_index,
  result_index)` reference; never deduplicate upstream result/path occurrences.
- Independently hash an existing referenced snapshot file and reject a
  conflicting SARIF hash. Preserve a missing file as unknown (`null`) and do not
  claim source coordinates are verified against file bounds until that check
  exists.
- A Gate B build uses only a checked-in Maven Wrapper command derived from
  validated argv, matching Java/`javac`, a validated exact Maven release
  URL/SHA declaration, and exact optional qlpack pins. Real scans execute target
  code as the host user and require external OS/network/resource isolation;
  current path and timeout controls are not a complete sandbox.
- The workflow JSONL event history is append-only. The run manifest is a current
  projection, not an append-only event store. Before finalization, reverify every
  registered artifact's size/hash and make all registered artifact/audit files
  owner-read-only; failed runs must register redacted error metadata and partial
  CodeQL logs when present.
- No component may automatically dismiss an upstream security alert.

## Change discipline

- Prefer a small vertical change with tests over empty packages or placeholder
  APIs. Do not add `pass`, fake results, or unused future-gate scaffolding to
  imply progress.
- Preserve user changes in a dirty worktree and keep changes within the assigned
  file/module ownership when multiple agents are collaborating.
- Use Pydantic v2 conventions, SQLAlchemy 2 APIs, strict typing, and public API
  docstrings. Avoid broad `Any` and blanket exception swallowing.
- Add or update tests for success, invalid input, and security boundary cases.
- Update `CHANGELOG.md`, `KNOWN_LIMITATIONS.md`, the relevant ADR, and the dated
  progress log when behavior or scope changes.
- Treat fixture licensing and provenance as part of the change; do not copy a
  third-party repository into this repository.

## Gate progression

Gate C (context/evidence) starts only after Gate A checks and the Gate B offline
ingest/normalization acceptance path pass. A successful real CodeQL smoke
remains separate release evidence and must be collected in an environment with
the pinned external tools. Later gates add bounded agents and deterministic
decisions, offline end-to-end reporting, and security/release hardening in that
order. Real model APIs, remote Git, Gradle, adaptive context, verification, and
calibration must not displace the v0.1 P0 path.
