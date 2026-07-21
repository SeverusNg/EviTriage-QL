# ADR 0001: Establish a strict local-first modular monolith

- **Status:** Accepted
- **Date:** 2026-07-20
- **Decision owners:** EviTriage-QL contributors
- **Applies to:** Gate A and the v0.1 P0 foundation

## Context

EviTriage-QL will eventually combine repository acquisition, Java builds,
CodeQL, SARIF, program context, structured model calls, evidence policy, and
research reporting. Each boundary processes potentially malicious input, while
the 2026-07-27 v0.1 deadline requires a reproducible offline vertical slice.

The first gate must prove that the software is not hard-coded to one target and
that no analysis step needs to write into the user's original source tree. It
also needs an environment that CI and a new researcher can reproduce before
external tools and models are introduced.

## Decision

We will build a typed Python 3.12 modular monolith with the following choices:

1. Use a `src/` package, Typer CLI, Pydantic v2 strict models, SQLAlchemy 2,
   SQLite by default, `uv 0.8.3`, pytest, Ruff, and mypy strict. Enforce the uv
   version through project configuration.
2. Make ProjectSpec the only target-selection boundary. Gate A supports local
   sources only. Two different fixture configurations must pass through the
   same ProjectRegistry; core modules contain no target names or target-specific
   paths.
3. Reject unknown configuration fields. Build commands are argument vectors,
   source/storage paths are canonicalized, and project/run identifiers are safe
   slugs. ProjectSpec cannot configure secrets, model endpoints/prompts, or tool
   privileges.
4. Treat target source as untrusted and input-only. WorkspaceManager allocates
   distinct run-owned paths below configured roots, checks containment and
   symlink boundaries, and never cleans a path it does not own.
5. Put I/O behind explicit project, workspace, tool, and storage adapters. Keep
   domain models free of I/O and provider SDK types.
6. Use structured, redacted logging and a typed error hierarchy. External-tool
   absence is an observable result, not a fabricated success.
7. Store only minimal Gate A metadata in SQLite. Runtime source copies,
   databases, artifacts, logs, and future model responses stay outside Git.
8. Keep CI offline with respect to models. Its canonical steps are
   `uv sync --all-extras` and `make check`; a real CodeQL smoke is a separately
   recorded later-gate requirement.
9. Install gate-required tools in persistent user/system locations that are
   discoverable on a fresh login-shell `PATH`. An ephemeral bootstrap may be
   used for recovery, but cannot satisfy deployment, reproduction, or handoff
   evidence. Record the source, version, integrity verification, install path,
   command, and exit code for environment provisioning.
10. Do not create empty packages or placeholder success paths for Gate B+. Add an
   interface only with executable behavior needed by the current gate, or
   document the future seam without claiming implementation.

## Why this decision

A modular monolith minimizes deployment and operational variability for a
deadline-driven research artifact while still enforcing dependency boundaries.
Strict declarative configuration makes project switching testable and gives
future manifests a stable digest. Local-only acquisition and copy-on-write run
areas reduce the highest early risk: accidentally executing against or
modifying a researcher's original checkout.

SQLite makes a clean-room, single-machine reproduction practical. SQLAlchemy
keeps a future backend adapter possible without making PostgreSQL a Gate A
dependency. Fake/Replay model adapters can later preserve offline CI without
letting provider types leak into the domain.

## Alternatives considered

### Hard-code the first Java fixture

Rejected. It would make the demo quick but invalidate the core research claim
that target software is replaceable by configuration and would encourage
target-specific logic in later analyzers.

### Analyze directly in the user's checkout

Rejected. Maven, CodeQL, and test tooling can create or overwrite files. A
read-only input plus run-isolated writable copy is easier to audit and clean.

### Start with services and PostgreSQL

Rejected for v0.1. They add networking, deployment, migration, and concurrency
failure modes before the evidence pipeline exists. The chosen boundaries allow
that evolution later if research collaboration requires it.

### Make configuration permissive for forward compatibility

Rejected. Silently ignored fields can hide typos or attempted privilege changes
and make experiments non-reproducible. Schema changes must be explicit and
versioned.

### Require a real model or CodeQL in CI

Rejected for the baseline. A paid/remote model would make CI non-deterministic
and risk source disclosure. CodeQL is still a real later runner and smoke
requirement, but golden inputs will support offline CI once Gate B exists.

## Consequences

Positive consequences:

- configuration switching, path ownership, and source immutability are directly
  testable;
- a clean environment needs only Python/uv/Make for Gate A;
- later tool/provider integrations have explicit trust boundaries;
- configuration and artifact provenance can use stable SHA-256 identities.

Costs and constraints:

- local repositories must be copied or snapshotted before any writable build,
  which consumes time and disk space;
- remote Git, Gradle, PostgreSQL, real model providers, and the analysis
  pipeline are intentionally unavailable at Gate A;
- every schema evolution requires migration/version work instead of permissive
  passthrough;
- file locking and canonical containment must work across supported platforms.

## Security implications

This decision reduces, but does not eliminate, risk from malicious repositories.
Workspace containment is not an OS sandbox, so Gate A executes no target build.
Later build and verification gates require time/resource limits, disabled
network by default, non-root execution where applicable, validated command
construction, and recorded provenance. Repository prose is data and can never
alter system prompts or tool permissions.

## Validation

The decision is satisfied only when both checked-in local ProjectSpecs validate
through the same registry, independent runs receive distinct managed writable
paths, fixture directory digests remain unchanged, database migration works,
and `make check` plus `evitriage doctor --json` complete with honestly recorded
results.

## Revisit criteria

Revisit this ADR if a supported platform cannot safely provide the required
canonical-path/locking semantics, if multi-user experiments justify a service
backend, or if later adapters reveal a domain dependency on a vendor SDK. Such a
change requires a new ADR; it must not silently weaken the invariants above.
