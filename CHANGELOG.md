# Changelog

All notable changes to this project will be documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and tagged
releases will follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Pinned the development frontend to `uv 0.8.3` with an executable
  `tool.uv.required-version` gate and made persistent, login-shell-discoverable
  tool installation part of environment acceptance; ephemeral `/tmp`
  bootstraps no longer qualify as deployed tooling.
- Updated environment evidence to distinguish installed Java/CodeQL tooling
  from a completed real Java/CodeQL smoke and from vulnerability findings.
- Resolved the blueprint's Java `security-extended` alias to the bundle-pinned
  `codeql/java-queries` suite expected by the CodeQL CLI, instead of passing the
  action-style shorthand as a nonexistent query pack.
- Tightened the SARIF text-location boundary to require the specification's
  `run.columnKind` for non-empty result runs and preserve that coordinate unit
  on every normalized location.
- Added narrow compatibility for CodeQL's exact, case-insensitive `%SRCROOT%`
  artifact base convention and materialized SARIF's default
  `endLine=startLine` when an `endColumn` is present; all other unknown URI
  bases still fail closed.
- Prevented Java lexical callable extraction from treating `try` and other
  control headers containing nested calls as method declarations.

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
- A recorded CodeQL `2.26.1`/Java 17 smoke of the `example-local` fixture that
  reached `NORMALIZED` with preserved real SARIF and zero alerts.
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
- Gate C Level 0 normalized metadata plus bounded Level 1 `fixed_window` and
  lexical Java `path_function_slice` context, with per-alert `SliceArtifact`
  hashes, source-coordinate checks, token estimates, and explicit omissions.
- A strict artifact-addressed Evidence Registry, Claim contract, closed
  evidence/claim relationship validation, deterministic Graphviz export, and
  escaped source/path navigation HTML that carries no verdict.
- Shared `NORMALIZED → CONTEXT_READY` processing for scan and existing-SARIF
  branches, generated Gate C JSON Schemas, and context/evidence artifact records
  in the finalized run manifest.
- Gate C coverage for normalized additional/related locations in Level 0,
  bounded source selection, slice references, and source-map navigation.
- Gate C-Extra acceptance documentation requiring a real query-positive
  Socket-to-path CodeQL result to reach `CONTEXT_READY` before Gate D begins.
- An original Apache-2.0 Socket-to-path CWE-22 Java case, strict shared case
  schema, SHA-bound machine-readable ground truth, and fixture-boundary tests.
- A recorded CodeQL 2.26.1/Java 17 Gate C-Extra run in which
  `java/path-injection` produced one complete eight-step path and reached
  `CONTEXT_READY` with a complete callable slice, four evidence items, zero
  claims, and fully verified owner-read-only artifacts.

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
- Gate C reads only normalized, snapshot-relative locations through bounded
  no-follow regular-file access; missing, binary, oversized, invalid-coordinate,
  digest-mismatched, and over-budget context remains explicit rather than being
  guessed or silently expanded.
- Source text and lexical guard/sanitizer matches remain escaped, neutral,
  untrusted data; no component upgrades a CodeQL path or source name into an
  automatic vulnerability classification.
- Source-coordinate checks use the declared SARIF UTF-16-code-unit or Unicode-
  code-point measurement instead of silently assuming Python string indexing;
  a leading UTF-8 BOM does not shift columns, and missing or unsupported
  `columnKind` values fail at the input boundary.
- The CodeQL `%SRCROOT%` mapping is an exact reserved-token exception bound to
  the validated snapshot root; arbitrary undeclared `uriBaseId` values,
  traversal, and symlink escapes remain rejected.

### Not yet implemented or verified

- Gate D and later: generated claims, LLM workflows, deterministic TP/FP/NMC
  policy, decision JSONL/HTML reports, and the offline end-to-end `make demo`
  path. AST/CFG-backed, caller/callee, adaptive, configuration, and test context
  also remain later scope.
