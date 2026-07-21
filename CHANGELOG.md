# Changelog

All notable changes to this project will be documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and tagged
releases will follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Gate A Python package and CLI engineering foundation.
- Strict local `ProjectSpec` validation and a registry shared by two example
  Java fixture configurations.
- Managed, run-isolated workspace allocation with boundary validation.
- Structured diagnostics through `evitriage doctor --json`.
- Minimal SQLite metadata schema and migration command.
- Ruff, mypy, pytest, coverage, and GitHub Actions quality checks.
- Initial architecture decision, progress evidence log, security guidance, and
  documented Gate A limitations.
- Gate B `scan`, `ingest-sarif`, and `normalize` CLI inputs that converge on one
  deterministic SARIF normalizer.
- A real CodeQL command builder/runner with pinned-version checks, managed
  database/output paths, Maven Wrapper-only build plans, timeouts, structured
  failures, same-JDK Java/`javac` major checks, and hashed
  command/stdout/stderr artifacts.
- Strict public ProjectSpec, normalized-alert bundle, run-manifest, and CLI run-
  summary contracts with generated JSON Schemas.
- Bounded SARIF 2.1.0 ingest for runs, rules, results, locations,
  related locations, code flows, fingerprints, and partial fingerprints, with
  duplicate occurrences and precise raw result references preserved.
- Original Golden SARIF fixtures covering single, multiple, absent, duplicate,
  malformed, multi-run, Windows-path, and hostile-URI cases.
- Run-scoped raw/normalized artifacts, an append-only workflow event log, and a
  current/final run manifest with SHA-256 artifact identities.
- Registration of the resolved ProjectSpec and workspace ownership descriptor,
  plus redacted structured error metadata and partial CodeQL logs for failed
  runs.
- Checked-in Apache Maven Wrapper 3.3.4 launchers for the two synthetic Java
  fixtures, declaring Maven 3.9.9 and its distribution checksum.
- Gate B integration tests showing Golden ingest and real-runner output use the
  same normalization and audit path.
- Exact semantic-version pins for optional query/model packs and validation of
  the Maven Wrapper's credential-free distribution URL and declared SHA-256.

### Security

- Local targets are treated as untrusted input and original source directories
  remain outside writable run areas.
- Secrets and generated runtime state are excluded from version control.
- External-tool absence is reported explicitly rather than converted to a fake
  successful result.
- Adapter/executable matching rejects shell and inline-interpreter build
  commands; ProjectSpec cannot redirect writes into source/docs trees.
- Gate A rejects unsupported Gradle/explicit build declarations, empty trusted
  allowlists, parent traversal, root symlinks, and cross-process project-ID
  source collisions instead of silently widening trust.
- Workspace snapshots are owner-only, content-addressed, reverified before
  copying, bounded by repository resource limits, copy-only for local targets,
  and cleaned only with a matching ownership descriptor; rejected source/root
  overlap is side-effect free.
- CLI usage failures remain structured in `--json` mode, validation errors omit
  raw inputs, and SQLite timestamps round-trip as timezone-aware UTC values.
- The committed ProjectSpec JSON Schema is checked with a standards-compliant
  validator so array cardinality cannot drift from runtime validation.
- SARIF input is bounded and read without following symlinks; source URIs that
  traverse parents, use remote/UNC authorities, leave the configured snapshot,
  or cross a snapshot symlink fail closed.
- Existing referenced source files are independently SHA-256 hashed; a
  conflicting SARIF artifact hash fails closed, while an absent file is
  represented explicitly with no verified artifact digest.
- Raw SARIF bytes are copied byte-for-byte and hashed, and every normalized
  alert retains the raw artifact SHA-256 plus run/result indexes; duplicate
  results and paths are never silently dismissed.
- Gate B external processes use validated argument vectors with `shell=False`;
  bare host Maven and escaping/symlinked wrappers are rejected before execution.
- External tools receive an explicit environment-variable allowlist rather than
  API, GitHub, SSH, or proxy variables from the parent process; persisted logs
  are length-bounded and redacted.
- Missing Java/`javac`/CodeQL, a configured tool-version mismatch, timeout,
  non-zero exit, and malformed output all remain explicit failed runs with no
  success surrogate.
- Finalization reopens every registered artifact, rejects a size/digest change,
  and makes all registered artifact and audit files owner-read-only (`0400`).

### Not yet implemented or verified

- Gate C and later: program context, evidence/claims, LLM workflows,
  deterministic TP/FP/NMC policy, JSONL/HTML reports, and the offline end-to-end
  `make demo` path.
- A successful real CodeQL-to-SARIF Java smoke. Java/`javac` and CodeQL were
  absent in the recorded development environment; the real runner is retained
  and its unavailable-tool failure is tested and documented rather than
  replaced by Golden data.
