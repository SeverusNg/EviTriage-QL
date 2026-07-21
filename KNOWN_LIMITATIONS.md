# Known limitations

This document describes the checked-in **Gate B input-layer** baseline. Items
below are intentional scope boundaries or unresolved verification gaps, not
implicit claims that the complete v0.1 research workflow exists.

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
- The CodeQL runner exists and is pinned to CLI `2.26.1`, but a successful real
  Java/CodeQL smoke has **not** been executed in the recorded environment:
  Java/`javac`, CodeQL, and a prepared Maven cache were unavailable. The
  checked-in Golden SARIF is synthetic test input, not captured evidence from
  either Java fixture.
- The SARIF parser intentionally normalizes a supported SARIF 2.1.0 subset:
  runs, driver rules, results, artifacts, URI bases, physical/related
  locations, code flows/thread flows, fingerprints, and properties. Unknown
  extension fields are ignored, while a result without a resolvable physical
  source location is rejected instead of guessed.
- `ingest-sarif` requires a selected local source tree so source URIs can be
  interpreted relative to a validated snapshot root. Gate B does not prove that
  the operator selected the source revision that produced the SARIF, nor does
  it require every referenced file to exist. It is not a source-free SARIF
  viewer; source/SARIF correspondence remains operator-supplied provenance.
- Path/function context, evidence registries, claims, and artifact-addressed
  evidence graphs are not implemented.
- Fake/Replay/real LLM adapters and Analyst/Rebuttal/Judge are not implemented.
- Deterministic TP/FP/NMC policy and JSONL/HTML reports are not implemented;
  therefore Gate B produces no security classification and cannot dismiss an
  upstream alert.
- The complete offline `make demo`, verification sandboxes, calibration,
  benchmark datasets, paper statistics, PostgreSQL, and GitHub alert
  integration remain later milestones.

## Operational boundary

- SQLite remains a deliberately minimal local metadata backend. Gate B audit
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
- Owner-read-only final permissions and content hashes make accidental changes
  detectable but are not a tamper-proof ledger: the filesystem owner or root
  can change permissions and rewrite artifacts. Research retention should copy
  completed runs into an independently controlled, content-addressed archive.
- The Gate B manifest covers the input/normalization stage and its artifact
  hashes. It is not yet the complete v0.1 manifest for context, prompts,
  provider/model identity, decisions, and reports.
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
  allowed with no verified normalized digest, and coordinates are not checked
  against actual file line/column bounds. Later evidence extraction must retain
  those unknown/unverified distinctions.
- SARIF input is bounded to 128 MiB, normalization to 100,000 results and
  100,000 path steps, and source snapshotting has separate entry/depth/byte
  bounds. Very large production analyses may require explicit policy changes.
- The example fixtures demonstrate configuration switching, isolation, and an
  intended CWE-22/CWE-78 source pattern; they are not a representative
  vulnerability benchmark and have no EviTriage TP/FP/NMC labels at this gate.
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
