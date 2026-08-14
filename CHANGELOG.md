# Changelog

[English](CHANGELOG.md) | [简体中文](CHANGELOG.zh-CN.md)

All notable changes to this project will be documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and tagged
releases will follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Added exact query-family dispatch for four Java resource-leak rules and
  independent strict `resource-leak-1.0` Analyst/Rebuttal/Judge contracts.
- Added bounded Java lifecycle evidence with complete enclosing-method source,
  acquisition/release/exit candidates, same-file one-hop callee context, and
  explicit omissions; repository text remains untrusted inert data.
- Added a conservative resource policy for TP/FP/NMC and tests for TWR,
  `finally`, early exits, sequential close failures, locks, ownership transfer,
  unknown callees/frameworks, prompt injection, schema repair, and evidence IDs.
- Added strict manifest-driven existing-SARIF preflight/run/evaluate commands,
  per-case run isolation, zero-result closure, before/after comparison,
  bilingual aggregate reports, and post-finalization V1-baseline evaluation.
- Added a Git-safe RocketMQ V2 experiment package under `experiments/` with
  frozen input identities, sanitized result/run indexes, bilingual reports, and
  package-level SHA-256 verification; raw source-bearing artifacts remain ignored.

### Changed

- Preserved legacy security schemas and canonical Replay identities by routing
  resource rules through separate models and workflow code.
- Added bounded transient DeepSeek transport retries for network errors, 429,
  and 5xx responses; 401/403 are never retried.
- Batch failures remain structured failures and mark the experiment incomplete;
  successfully completed sibling decisions remain in the aggregate and are
  never replaced with fabricated NMC rows.
- Made non-empty evidence references visible in the resource JSON Schema and
  included bounded field-level validation issues in the single repair request;
  this fixed a live model/schema mismatch without weakening evidence closure or
  changing legacy request identities.

### Security

- Preflight validates all source commits/clean status, SARIF hashes/counts,
  query families, ProjectSpecs, and output roots before credential resolution.
- V1 human labels can be opened only by the separate evaluation command after
  automatic decisions are immutable and are never sent to a model.
- Private target paths, source, SARIF, credentials, real model traffic,
  workspaces, and artifacts remain excluded from Git.

## [0.2.0] - 2026-07-23

### Added

- Added provider-neutral DeepSeek credential discovery and loading through
  `EnvironmentCredentialProvider`, `SystemdCredentialProvider`,
  `PassCredentialProvider`, and `CredentialResolver`.
- Added `triage --credential-provider
  environment|systemd-creds|pass|auto`, fixed auto priority, non-secret
  per-provider JSON status, and hidden double-prompt pass/GPG enrollment.

### Changed

- Moved credential selection out of `DeepSeekLLM`; the adapter now receives one
  already validated in-memory key and remains responsible only for the fixed
  official HTTPS request boundary.
- Retained the fixed TPM2/systemd credential path and legacy enrollment
  behavior while documenting pass as the persistent WSL-friendly option and
  environment input as the one-process option.

### Security

- Pass uses the fixed `evitriage/deepseek-api-key` entry, strict ASCII path
  validation, a validated non-writable root/current-user executable, fixed
  argument vectors, bounded captured output and timeout, standard-input
  enrollment, and a pwd-derived minimal child environment with extensions,
  proxies, tokens, and API keys excluded.
- Auto fallback stops after any configured provider has malformed data, unsafe
  permissions, or a load/decrypt failure. Tests use injected runners and
  simulated HTTPS and verify that key material is absent from argv,
  environments, status, exceptions, logs, and files.

## [0.1.0] - 2026-07-23

### Changed

- Expanded the default offline demo from the Gate E three-label fixture to the
  exact v0.1 six-case matrix: CWE-22 TP/FP/NMC, CWE-78 TP/FP, and a prompt-
  injection case, with 18 identity-bound Replay calls and no automatic dismiss.
- Made the six-case Maven fixture self-contained with its own Maven 3.9.9/SHA-
  pinned wrapper and a matching source/build root; a real CodeQL 2.26.1 scan
  now completes over that project and records four query results separately
  from the synthetic six-result decision fixture.
- Made the Git checkout secret scan tolerate tracked files that are genuinely
  deleted in the working tree while continuing to reject existing symlinks,
  non-regular files, and paths outside the checkout.
- Made the credential scan work in both Git checkouts and identified source
  distributions, while rejecting non-runtime symlinks/non-regular files; this
  closes the first Gate G clean-room `make check` blocker without weakening the
  checkout's Git commit-eligible boundary.
- Aligned `CITATION.cff` with the package/lock/runtime `0.1.0` version and
  updated its scope statement to the bounded offline vertical path.
- Hardened every triage model task payload with deterministic secret redaction
  before canonical request hashing, and repeated the check at the DeepSeek
  provider boundary without mutating exact local evidence artifacts.
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
- Isolated the missing-DeepSeek-credential CLI unit test from the operator's
  persistent credential store so an ordinary test run cannot silently make
  paid network requests when a live key is deployed.
- Recorded an operator-authorized DeepSeek smoke through the TPM2 credential
  path: three strict role responses were accepted and the synthetic fixture
  reached `JUDGED` with a conservative `NMC` decision and
  `auto_dismiss=false`. This is live-path evidence, not a quality benchmark.

### Added

- Strict SHA-bound manifests and Java 17 compile coverage for all six v0.1
  microcases, plus ADR 0012 documenting their synthetic provenance and release
  acceptance boundary.
- Release assembly of the reviewed six-row JSONL report, escaped HTML, finalized
  run manifest, case/demo summaries, and actual full/security pytest summaries;
  all are registered in `release-manifest.json` and `SHA256SUMS`.
- Gate G `make release-artifacts` and `make release-verify` targets for the
  wheel, source distribution, hash-bearing locked dependency inventory,
  CycloneDX 1.5 SBOM, prompt/schema/version freeze metadata, closed manifest,
  and `SHA256SUMS` verification.
- ADR 0011, source-distribution reproducibility instructions, draft rc1 release
  notes/blocker assessment, and release tamper/symlink/version-drift tests.
- Gate F `security`, `golden`, and `e2e` pytest markers plus a directly
  selectable `make security-test` acceptance suite for prompt injection,
  malicious URI, path/symlink escape, HTML escape, shell metacharacters, and
  secret redaction.
- ADR 0010 documenting the Gate F attack-class matrix, outbound redaction
  boundary, coverage contract, and residual confidentiality limits.
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
- A provider-neutral `StructuredLLM` protocol plus offline ordered `FakeLLM`
  and read-only, request-hash-addressed `ReplayLLM` adapters with strict JSON
  response validation.
- Strict Claim-draft, Analyst, Rebuttal, Judge, FinalDecision, invocation,
  stage-artifact, TriageResult, and triage-summary contracts with ten new
  generated public JSON Schemas.
- A bounded Analyst → Rebuttal → Judge workflow with at most one response repair
  per role, at most six calls per alert, exact alert-occurrence evidence closure,
  code-assigned content-derived Claim IDs, and per-request size limits.
- A deterministic TP/FP/NMC policy that requires a supported source/path/sink
  evidence bundle or decisive successful verification for TP, decisive Rebuttal
  evidence for FP, returns NMC for conflicts/unknowns/missing critical evidence,
  preserves raw confidence only as metadata, and fixes `auto_dismiss` to false.
- Gate D tests for Fake TP/FP/NMC paths, complete three-role Replay, request-hash
  stability, repair exhaustion, prompt-injection containment, and Replay cache
  miss/symlink/duplicate-key boundaries.
- An existing-SARIF `triage` CLI that binds a trusted Replay profile/cache to
  the ProjectSpec, reuses the Gate B/C pipeline, persists Analyst/Rebuttal/Judge
  artifacts, and finalizes the journal through
  `ANALYZED → REBUTTED → JUDGED`.
- Stable content-derived analysis identities, separate from operational run
  IDs, so equivalent source/SARIF input produces reproducible evidence and
  Replay request hashes across fresh managed runs.
- Terminal `MODEL_FAILED` and `POLICY_REJECTED` workflow states; model failures
  persist bounded non-content request and partial-invocation provenance.
- An opt-in `DeepSeekLLM` adapter for the official DeepSeek V4-Pro/Flash HTTPS
  Chat Completions API, using JSON Output and the existing strict structured
  response/evidence validation path.
- A credential-free `deepseek-v4-pro` LLM Profile and an explicit example
  ProjectSpec whose `remote_llm_allowed` policy makes external evidence/source
  transfer visible rather than implicit.
- A commit-eligible credential-pattern scanner in `make check`; ignored secret
  files remain outside Git, while suspicious DeepSeek assignments, common API
  key shapes, and private-key blocks fail the check without printing values.
- A Linux TPM2/systemd credential command that accepts a rotated DeepSeek key
  through a hidden prompt, writes only an owner-private encrypted blob outside
  the checkout, and lets `triage` automatically decrypt it through an in-memory
  pipe. The one-process environment variable remains an ephemeral fallback.
- A first Gate E offline reporting slice integrated into `triage`: every
  normalized alert now produces one strict, independently parseable JSONL row
  and one self-contained HTML audit view before the run is finalized.
- Strict `AlertReport` and `TriageReportBundle` contracts, generated public
  schemas, and closed checks binding report alerts, slices, evidence, Claims,
  critical references, analysis identity, and run provenance.
- Registered `report` artifacts at `reports/decisions.jsonl` and
  `reports/index.html`, including tool/config/source provenance, ordered paths,
  Analyst/Rebuttal Claims, evidence, TP/FP/NMC decision, unknowns, context
  history, explicit unperformed verification, next actions, and limitations.
- A fixed, Apache-2.0, synthetic NMC Replay bundle whose strict manifest binds
  the ProjectSpec, Golden SARIF, source-tree identity, offline profile,
  canonical request hashes, response-file hashes, expected decision, and
  limitations.
- An offline `make demo` target that closes the existing-SARIF path through
  normalization, context, evidence, Analyst/Rebuttal/Judge, deterministic NMC,
  JSONL/HTML reports, and a finalized run manifest without CodeQL, an API key,
  or a real model.
- A subprocess E2E acceptance test that runs `make demo` in an isolated
  checkout, strictly parses its one-line summary/report, rechecks every
  registered artifact's size/hash and `0400` mode, and proves the input source
  tree is unchanged.
- A strict `EvidenceSupplement` contract and generated schema for explicit
  human/test/verification assertions, bound to the project, repository
  snapshot, raw SARIF, and exact result occurrence. Supplements are preserved
  as input artifacts and merged through code-assigned evidence IDs without
  accepting Claims or desired labels.
- Three original Apache-2.0 Java path microcases, a three-result Golden SARIF,
  an identity-bound synthetic test-evidence supplement, and nine fixed Replay
  responses that exercise the ordinary policy and reports for one TP, one
  decisive FP, and one NMC.
- A completed offline Gate E `make demo` acceptance path whose three strict
  JSONL rows and escaped HTML summary contain all three labels, nine ordered
  Agent invocations, complete manifest provenance, immutable artifacts, and no
  Java, CodeQL, credential, network, or real-model dependency.
- `triage --scan` as the alternative to `triage --sarif`, carrying actual
  CodeQL runner output through the shared normalizer, context/evidence,
  Analyst/Rebuttal/Judge, policy, and reports in one run. Controlled-runner
  integration coverage proves the complete state/artifact path.

### Security

- Credential-shaped content in evidence or prior model text is now redacted
  before it can enter Fake/Replay/remote model requests; direct DeepSeek calls
  apply the same defense before constructing the HTTPS body.
- The Gate F E2E regression proves an injected source comment cannot become a
  model instruction and script-shaped untrusted report text is HTML-escaped;
  a separate command-builder regression preserves shell metacharacters as one
  quoted Maven argument while subprocess execution remains `shell=False`.
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
- Model responses cannot cite evidence outside the exact alert fingerprint and
  raw SARIF occurrence. Unknown evidence/claim IDs invalidate the response and
  receive no more than the configured single repair.
- Evidence supplements are bounded no-follow inputs with strict schemas and
  exact project/snapshot/SARIF/occurrence binding. Identity mismatches,
  duplicate entries, or unsupported decisive-neutral assertions finalize as
  `POLICY_REJECTED`; the original input is retained for audit.
- Repository/SARIF text is carried only as `untrusted_code_data`; fixed role
  prompts deny instructions and tool permissions found inside it. Gate D ships
  Replay with bounded no-follow cache reads. The optional DeepSeek adapter is
  pinned to `api.deepseek.com:443`, sends credentials only as a Bearer header,
  discards provider error bodies, and requires matching remote-upload policy in
  the trusted profile and ProjectSpec.
- The HTML report escapes SARIF messages, path messages, source excerpts,
  Claims, evidence, unknowns, and all other untrusted text. JSONL/HTML report
  artifacts are hash-registered and finalized owner-read-only with the run;
  reports cannot enable automatic alert dismissal.

### Not yet implemented or verified

- Post-v0.1: the standalone `report --run-id` command, a general trusted
  Replay cache writer/producer attestation, prior-run continuation, and a fresh
  real CodeQL scan-to-`JUDGED` acceptance artifact. Providers beyond the narrow
  DeepSeek V4 integration,
  AST/CFG-backed, caller/callee, adaptive, configuration, and test context also
  remain later scope.
