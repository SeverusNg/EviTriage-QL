# ADR 0011: Make Gate G release artifacts closed and independently verifiable

- Status: Accepted
- Date: 2026-07-23
- Gate: G (release engineering tranche)

## Context

Gates A–F made the offline pipeline executable and auditable, but the repository
had no command that built the Python distributions, exported the exact locked
dependency inventory, generated an SBOM, froze prompt/schema identities, and
closed those files under one checksum manifest. The version in `CITATION.cff`
also still said `0.1.0-dev` while the package, lock, and runtime reported
`0.1.0`.

The first source-distribution clean-room attempt exposed a separate release
blocker. `make check` reached the secret scan and failed because the scanner
unconditionally invoked `git ls-files`; a legitimate sdist intentionally has no
`.git` directory. Treating that failure as an environmental success would make
the release path non-reproducible.

## Decision

1. `make release-artifacts` builds the wheel and sdist offline, exports all
   locked runtime/development dependencies with distribution hashes, runs the
   release test/demo evidence commands, and then invokes the release assembler
   and metadata builder. `make release-verify` reopens the resulting closure
   without rebuilding it.
2. The metadata builder requires the versions in `pyproject.toml`, `uv.lock`,
   `src/evitriage/__init__.py`, and `CITATION.cff` to match exactly. It records
   the SHA-256 of `uv.lock`, a deterministic digest over every public schema,
   and the literal Agent prompt version.
3. The builder emits a deterministic CycloneDX 1.5 SBOM for every package in
   `uv.lock`. Runtime-reachable packages have required scope; dev-only packages
   have optional scope. Available sdist URLs and SHA-256 values come directly
   from the lock and are not independently invented license assertions.
4. `release-manifest.json` registers the wheel, sdist, hashed dependency
   inventory, SBOM, uv-created output `.gitignore`, and the six-case
   report/manifest/matrix/full-test/security-test evidence frozen in ADR 0012.
   `SHA256SUMS` covers those records plus the manifest itself. Unknown/stale files, symlinks,
   traversal-shaped names, duplicate JSON/checksum entries, and size/hash
   mismatches fail closed.
5. The secret scan keeps Git as the authority in a checkout. When `.git` is
   absent, it permits only a source tree identified by matching `PKG-INFO`,
   `pyproject.toml`, and `uv.lock`; it scans every regular source-distribution
   file except explicit top-level runtime/build directories. Other symlinks and
   non-regular files fail closed.
6. Release commands do not create a Git tag, publish a package, sign a file, or
   claim a hosted/second-host result. The manifest field saying real CodeQL
   evidence is required remains a requirement tied to the separate recorded
   smoke; it is not converted into a model decision.

## Consequences

- Reviewers can verify byte identity for a release directory and relate the
  SBOM, prompt, schemas, package metadata, and lock without trusting filenames.
- A source archive can now run the same `make check` contract as a Git checkout;
  runtime virtual environments and generated artifacts do not pollute the
  source secret scan.
- The SBOM is dependency inventory, not a dependency-license or vulnerability
  audit. No signature, provenance service, or tamper-proof publication channel
  is supplied.
- The previously recorded six-case and example/test P0 blockers are closed by
  ADR 0012. Tagging, signing, hosted/second-host reproduction, and publication
  remain explicit operator/external actions and are not inferred from a local
  release-directory verification.
