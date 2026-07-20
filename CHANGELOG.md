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
  copying, bounded by repository resource limits, and cleaned only with a
  matching ownership descriptor; rejected source/root overlap is side-effect
  free.
- CLI usage failures remain structured in `--json` mode, validation errors omit
  raw inputs, and SQLite timestamps round-trip as timezone-aware UTC values.
- The committed ProjectSpec JSON Schema is checked with a standards-compliant
  validator so array cardinality cannot drift from runtime validation.

### Not yet implemented

- Gate B and later: CodeQL execution, SARIF ingest/normalization, program
  context, evidence/claims, LLM workflows, TP/FP/NMC policy, and reports.
