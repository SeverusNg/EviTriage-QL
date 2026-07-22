# Known limitations

This document describes the checked-in **Gate E offline P0 vertical closure**:
integrated reporting, both fresh triage inputs, and a deterministic three-label
offline demo.
Items below are intentional scope boundaries or unresolved verification gaps,
not implicit claims that the complete v0.1 research workflow exists.

## Functional boundary

- Only local ProjectSpec targets can be materialized. The schema reserves typed
  Git/dataset identities for forward compatibility, but remote checkout,
  dataset acquisition, and submodule materialization are unavailable.
- Local snapshots support only `snapshot_mode: copy`; Git worktrees, hard links,
  and other acquisition/materialization strategies are rejected.
- `require_clean_git` is validated as configuration metadata, but the local
  input path does not invoke Git or calculate a dirty-patch digest. Local
  snapshots are identified by a complete source-tree SHA-256 instead.
- Gate B scanning supports only the Maven adapter with a checked-in `./mvnw` or
  `./mvnw.cmd`. That explicitly configured, validated repository wrapper is the
  only repository script executed; bare host Maven, Gradle, explicit adapters,
  and arbitrary/unconfigured repository scripts are rejected. The two examples
  declare Maven 3.9.9 through Maven Wrapper 3.3.4 and run Maven with `--offline`.
- The Maven Wrapper launcher can require a one-time distribution download when
  its cache is empty. That bootstrap is not performed by the offline Golden
  SARIF path and must be prepared separately for an offline real scan.
- Maven 3.9.9 and its distribution checksum are declarative wrapper properties,
  not an observed runtime tool identity. The Gate B runner does not invoke
  `mvnw --version`, hash an already cached distribution, or prove that a
  pre-existing wrapper cache matches the declared checksum. Cache integrity is
  an external supply-chain prerequisite.
- The original Gate B CodeQL CLI `2.26.1`/Java 17 smoke produced valid SARIF
  with 120 rule descriptors and zero results. Gate C-Extra then added a distinct
  real scan of the SHA-bound Socket case: one `java/path-injection` result, one
  complete eight-step path, and complete context reached `CONTEXT_READY`. These
  environment-specific runs validate the runner/query/pipeline combination;
  they are not an EviTriage classification, proof of exploitability, evidence
  about arbitrary repositories, or clean-room reproduction. Golden SARIF
  remains separate synthetic input, not captured output from either run.
- The built-in `security-extended` shorthand is currently mapped only for the
  v0.1 `java-kotlin` path. Adding another CodeQL language requires an explicit,
  tested bundle-suite mapping rather than guessing a pack or filename.
- The SARIF parser intentionally normalizes a supported SARIF 2.1.0 subset:
  runs, driver rules, results, artifacts, URI bases, physical/related
  locations, code flows/thread flows, fingerprints, and properties. Unknown
  extension fields are ignored. A non-empty result run without the required
  `columnKind`, an unsupported column unit, or a result without a resolvable
  physical source location is rejected instead of guessed. The exact
  case-insensitive `%SRCROOT%` convention is mapped to the validated snapshot
  root; other undeclared URI bases are rejected. An omitted `endLine` uses the
  SARIF same-line default when `endColumn` is present.
- `ingest-sarif` requires a selected local source tree so source URIs can be
  interpreted relative to a validated snapshot root. Gate B does not prove that
  the operator selected the source revision that produced the SARIF, nor does
  it require every referenced file to exist. It is not a source-free SARIF
  viewer; source/SARIF correspondence remains operator-supplied provenance.
- Gate C's Java callable boundary finder is a dependency-free lexical extractor,
  not an AST/CFG or compiler analysis. It handles the checked-in fixtures and
  ignores braces in comments/string literals, but complex Java syntax may fall
  back to a fixed window with `function_boundary_unresolved`. It does not infer
  missing CodeQL edges or semantic reachability.
- Gate C accepts only bounded regular UTF-8 source files up to 1 MiB. Its token
  estimate is deterministic UTF-8 bytes divided by four, not a provider
  tokenizer. The default per-alert budget is 24,000 estimated tokens.
- Level 1 does not yet include caller/callee expansion, AST-resolved guards,
  sanitizer definitions, configuration/test summaries, overrides, framework
  binding, or dynamic dispatch. Lexically matched guard/sanitizer lines are
  explicitly neutral candidates. `adaptive_slice` returns
  `FEATURE_NOT_AVAILABLE` rather than pretending to work.
- Missing, binary, oversized, changed, out-of-bounds, or over-budget source
  produces a hashed `partial` SliceArtifact with omissions; it does not make the
  whole alert disappear and does not fabricate source. Existing locations are
  checked against the current snapshot using the run-declared UTF-16-code-unit
  or Unicode-code-point column semantics during context extraction, while
  absent files remain unknown. A leading UTF-8 BOM is excluded from coordinate
  and excerpt text but remains covered by the raw artifact digest. Visual
  columns and tab expansion are not inferred because SARIF columns are
  measurement units, not rendered offsets.
- The Evidence Registry and Claim schemas enforce artifact/evidence references,
  but Gate C generates evidence only and emits no claims. The DOT graph and
  escaped source-map HTML are navigation artifacts, not vulnerability reports.
- `FakeLLM`, read-only `ReplayLLM`, strict Agent/decision schemas, the ordered
  Analyst/Rebuttal/Judge workflow, and deterministic policy now exist as a
  bounded Python library core. Replay consumes trusted
  `<request-sha256>.json` entries. The repository supplies only fixed synthetic,
  SHA-256-inventoried demo bundles, including one with TP, FP, and NMC; it does
  not supply a general cache writer, external-producer attestation, token usage,
  or latency measurements.
- An opt-in DeepSeek adapter supports only `deepseek-v4-pro` and
  `deepseek-v4-flash` at the fixed official `api.deepseek.com:443` Chat
  Completions endpoint. It accepts either the one-process `DEEPSEEK_API_KEY`
  input or the fixed TPM2/systemd encrypted credential store, plus exact
  `remote_llm_allowed` declarations in both the LLM Profile and ProjectSpec.
  Checked-in acceptance tests use simulated HTTPS only. One separately
  authorized live smoke on 2026-07-23 verified the TPM2 credential path,
  current account/model access, three accepted role responses, and a completed
  `JUDGED` run for one synthetic fixture. It did not capture provider token
  usage or billing, exercise retry/rate-limit/error behavior, establish ongoing
  availability, or benchmark output quality and accuracy.
- Persistent DeepSeek credentials currently require Linux `systemd-creds`, a
  usable TPM2 device, and operator access to `/dev/tpmrm0`. Enrollment fails
  closed if those prerequisites, private ownership, or `0600`/`0400` file modes
  are absent. There is no macOS/Windows keychain adapter yet.
- The `triage` command accepts exactly one of existing SARIF or a new CodeQL
  scan plus a trusted LLM profile, allocates a fresh run, reuses the shared Gate
  B/C path, and persists `ANALYZED → REBUTTED → JUDGED` artifacts. The scan
  form has controlled-runner integration coverage, but no fresh real CodeQL
  scan-to-`JUDGED` artifact is claimed. It cannot continue a previously
  finalized Gate C run by `run_id`; standalone `scan`/`ingest-sarif` commands
  still honestly stop at `CONTEXT_READY`.
- Optional supplemental evidence is a trusted operator/test assertion, not an
  independently verified fact or human label. The strict input binds project,
  snapshot, SARIF, and exact occurrence, is preserved and hash-registered, and
  cannot directly set Claims or a label. These controls expose provenance and
  prevent accidental cross-run use; they cannot establish that the producer's
  assertion is true. Verification sandboxes and human-review attestation remain
  unimplemented.
- The synthetic Gate D tests exercise TP, decisive FP, conflicting NMC, and
  missing-decisive-rebuttal downgrade decisions. They are policy/adapter test
  evidence, not vulnerability conclusions about the Java fixtures or the
  earlier real CodeQL result.
- A fresh successful `triage` run now writes registered
  `reports/decisions.jsonl` and `reports/index.html` artifacts before
  finalization. There is no standalone `report --run-id` command, no
  cross-run aggregation/CSV/Markdown export, and no way to attach reports to a
  previously finalized Gate C/D run. No component automatically dismisses an
  upstream alert; every `FinalDecision.auto_dismiss` value is structurally
  fixed to `false`.
- Report JSONL intentionally carries the bounded SliceArtifact and evidence
  needed for replayable audit, so it can contain selected source excerpts and
  must be handled with the same confidentiality controls as the source
  snapshot. HTML escapes untrusted content to prevent active markup; escaping
  is not content redaction or authorization to publish sensitive code.
- `make demo` now completes three existing-SARIF cases and emits one TP, one FP,
  and one NMC report without Java, CodeQL, an API key, network access, or a real
  model. Their evidence supplement and Replay responses are synthetic test
  oracles, not independently validated vulnerability labels or accuracy data.
  Verification sandboxes, calibration, benchmark datasets, paper statistics,
  PostgreSQL, and GitHub alert integration remain later milestones.

## Operational boundary

- `pyproject.toml` enforces `uv 0.8.3`, but the repository does not vendor the
  uv executable or an installer. Operators must install the pinned release in a
  persistent location, verify its upstream integrity, and expose it on the
  login-shell `PATH`; an ephemeral bootstrap is not clean-room evidence. A uv
  upgrade requires an explicit pin, lock, documentation, and evidence update.
- SQLite remains a deliberately minimal local metadata backend. Gate C audit
  artifacts and workflow state are file-backed under each managed run root;
  normalized alerts and events are not yet transactionally indexed in SQLite.
- `workflow-events.jsonl` is append-only for a run. `run-manifest.json` is a
  current summary rewritten after validated transitions; it must not be
  interpreted as an append-only database log. Finalization revalidates every
  registered artifact's size/digest and makes all registered artifact and audit
  files owner-read-only.
- The CLI always allocates a new run and accepts no caller-supplied run ID or
  idempotency key. `RunJournal` refuses pre-existing audit files rather than
  resuming them, so crash recovery, completed-state replay, and multi-process
  continuation of one run are not implemented.
- Normalized/domain `run_id` is a content-derived `analysis_identity` over the
  source snapshot, raw SARIF, commit, and normalizer version; the manifest
  `run_id` remains the distinct operational execution identifier. This split is
  required for Replay hashes to survive fresh managed runs, but callers must not
  confuse analysis identity with an append-only execution record.
- Owner-read-only final permissions and content hashes make accidental changes
  detectable but are not a tamper-proof ledger: the filesystem owner or root
  can change permissions and rewrite artifacts. Research retention should copy
  completed runs into an independently controlled, content-addressed archive.
- A judged manifest covers input, normalization, context, evidence, model-stage,
  decision, and report artifact hashes. Invocation records persist prompt/request/
  response hashes plus provider profile/model identity, but not raw prompts,
  raw Replay entries, or token/latency observations. The manifest does not
  attest who produced a Replay entry.
- A DeepSeek run sends the selected evidence payload—including bounded source
  excerpts—to an external provider. TLS and an explicit upload policy reduce
  accidental disclosure but do not make remote processing confidential from
  DeepSeek or eliminate provider retention/jurisdiction risks. Do not use the
  remote profile for source that policy or contract forbids uploading.
- The API key is never placed in model messages or run artifacts, and provider
  error bodies are discarded. It still exists briefly in process memory and in
  the outbound Authorization header. TPM2 protects the encrypted at-rest blob
  from off-machine decryption, not from an already authorized same-user
  process. Root inspection, a compromised runtime, shell tracing, or provider
  compromise remain outside the repository's protection boundary; use a
  dedicated account and a secret manager for higher assurance.
- The commit-eligible secret scan recognizes DeepSeek assignments, common
  `sk-...` tokens, and private-key blocks, but pattern scanning cannot prove the
  absence of every possible credential format. Human review and provider-side
  key rotation/revocation remain necessary.
- Public Pydantic records are frozen against top-level field reassignment, but
  nested mapping values such as fingerprints, properties, and tool versions are
  ordinary mutable Python dictionaries. Callers must not treat in-process
  objects as deeply immutable; the serialized artifact plus SHA-256 is the
  current reproducibility boundary.
- The runner executes the repository's `mvnw` directly as the same host user.
  Managed paths, wrapper validation, argument-vector execution, and timeouts do
  not constitute an operating-system sandbox. There is no container/cgroup
  CPU, memory, or process-count quota; `network_policy: disabled` is not yet an
  OS-enforced network namespace; and a timeout does not guarantee termination
  of every descendant process. The current `capture_output` path can also hold
  unbounded target stdout/stderr in memory before writing redacted artifacts.
  Only trusted fixtures/repositories should be scanned until external isolation
  and resource controls are supplied.
- The subprocess environment allowlist excludes ambient API/GitHub/SSH/proxy
  variables, but retains platform variables including `HOME` for tool
  operation. With no filesystem sandbox, the target build can still read files
  accessible to the host user (for example Maven settings or other home-
  directory credentials). Use a disposable, externally isolated execution
  account/home for real scans.
- Diagnostics prove discoverability, and unit/integration doubles prove runner
  behavior; neither is evidence that external CodeQL can successfully analyze
  an arbitrary repository.
- A dry-run/build-plan command is not implemented. Query-suite and pack
  arguments are recorded, and optional query/model packs require exact semantic
  version pins, but locally resolved pack lock/content digests and a CodeQL
  database metadata inventory are not yet complete research provenance.
- A referenced regular snapshot file is independently SHA-256 hashed and a
  conflicting SARIF declaration is rejected. Missing referenced files remain
  allowed with no verified normalized digest. Gate C checks coordinates only
  for source files it can safely open; absent files retain the unknown/unverified
  distinction.
- SARIF input is bounded to 128 MiB, normalization to 100,000 results and
  100,000 path steps, and source snapshotting has separate entry/depth/byte
  bounds. Very large production analyses may require explicit policy changes.
- The example fixtures demonstrate configuration switching, isolation, and an
  intended CWE-22/CWE-78 source pattern; they are not a representative
  vulnerability benchmark. The Gate D integration NMC is generated from a
  synthetic Replay response and is not an externally validated fixture label.
- Gate C-Extra covers only one real query-positive CWE-22 path. Its completion
  does not replace the pending six-case TP/FP/NMC/prompt-injection matrix or
  establish generalization to public or real-project benchmarks.
- No hosted CI result or clean-room real-tool reproduction should be inferred
  until its actual command, exit code, tool versions, and artifacts are
  recorded in the progress log.

## Security and research interpretation

- A `license_hint` records operator-supplied metadata and is not legal advice or
  automated license verification. The Maven Wrapper launcher retains its own
  Apache-2.0 provenance; CodeQL and Maven distributions remain external tools.
- A successful ProjectSpec validation means only that the configuration
  satisfies current trust-boundary constraints. A successful normalization
  means only that SARIF facts were represented deterministically; neither says
  that the target is safe or that an alert is exploitable.
- Stable alert/path fingerprints identify normalized content and occurrences;
  they are not vulnerability identities across arbitrary repository revisions.
- The software is pre-release research infrastructure. Do not rely on it as the
  sole basis for vulnerability disclosure, alert dismissal, or production risk
  acceptance.

These limitations should be removed only in the same change that adds working
implementation, tests, and reproducibility evidence for the corresponding
capability.
