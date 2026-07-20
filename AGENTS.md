# Repository guidance for coding agents

## Scope and current gate

This repository implements EviTriage-QL incrementally. The checked-in baseline
is Gate A: package/CLI foundations, strict configuration, ProjectSpec and
ProjectRegistry, managed workspaces, minimal SQLite storage, diagnostics, tests,
and CI. Do not describe Gate B or later capabilities as implemented until their
code and acceptance tests exist.

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
  and reject traversal and symlink escapes.
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

Gate B (CodeQL/SARIF) starts only after Gate A commands and tests pass. Later
gates add context/evidence, bounded agents and deterministic decisions, offline
end-to-end reporting, and security/release hardening in that order. Real model
APIs, remote Git, Gradle, adaptive context, verification, and calibration must
not displace the v0.1 P0 path.

