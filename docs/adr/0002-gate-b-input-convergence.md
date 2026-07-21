# ADR 0002: Converge real CodeQL and Golden SARIF before normalization

- **Status:** Accepted
- **Date:** 2026-07-21
- **Decision owners:** EviTriage-QL contributors
- **Applies to:** Gate B and downstream alert provenance

## Context

The v0.1 workflow needs two materially different input modes. A development
environment with Java, a Maven distribution, and CodeQL must be able to build a
small fixture and produce real SARIF. Offline CI and clean research replay must
also be able to consume an existing SARIF artifact without those external
tools. The second mode is essential for determinism, but it creates a risk: an
offline fixture could be mistaken for a real scan, or two ingestion paths could
normalize the same CodeQL facts differently.

Both branches process untrusted content. A real scan executes a target build;
existing SARIF can contain malicious URIs, malformed coordinates, duplicate
keys, very large structures, or misleading extension properties. Downstream
evidence must be able to point back to the exact raw result without silently
dropping duplicate occurrences.

## Decision

We will implement Gate B as two provenance-distinct branches that converge on
one parser and normalizer:

1. `scan` receives a validated local ProjectSpec and a managed RunWorkspace.
   `CodeQLRunner` accepts only a Maven Wrapper build plan, starts CodeQL and
   Java/`javac` through validated argv with `shell=False`, applies timeouts,
   checks the configured CodeQL version and same-JDK Java/`javac`, validates the
   wrapper's exact Apache Maven release URL/SHA declaration and exact optional
   qlpack pins, resolves the Java `security-extended` blueprint alias to
   `codeql/java-queries:codeql-suites/java-security-extended.qls` in the pinned
   bundle,
   passes an explicit non-secret environment allowlist, and records commands,
   exits, durations, bounded/redacted stdout/stderr, and hashes.
2. `ingest-sarif` copies an operator-selected bounded regular file into the run
   artifact root without following symlinks. `normalize` is an explicit CLI
   spelling of the same existing-SARIF normalization path.
3. Both branches preserve exact raw bytes and SHA-256 before strict SARIF 2.1.0
   parsing. No Golden fixture is promoted to a real-scan result.
4. One `SarifNormalizer` produces strict, frozen top-level, provider-neutral
   alert records. It preserves all result and path occurrences in source order,
   including duplicates, and represents missing paths/snippets as unknown
   rather than inventing facts.
5. Every normalized alert retains `(raw_sarif_sha256, run_index, result_index)`.
   Stable domain-separated hashes identify normalized alerts and paths without
   replacing occurrence provenance.
6. SARIF locations are interpreted relative to the validated source snapshot
   root. The resolver never fetches a URI and rejects traversal, remote/UNC
   authorities, unsafe schemes, containment escapes, and symlink crossings.
   CodeQL's exact case-insensitive `%SRCROOT%` base convention maps to that
   already validated root even when `originalUriBaseIds` omits it; every other
   undeclared base still fails closed. An omitted region `endLine` uses SARIF's
   same-line default when `endColumn` is present.
   The operator remains responsible for selecting the source revision that
   actually produced an ingested SARIF artifact. If a referenced regular file
   exists, its SHA-256 is independently computed and a conflicting SARIF hash
   is rejected; a missing file remains allowed with no verified normalized
   digest.
7. A run-scoped journal validates input-layer state transitions, appends a JSONL
   event history, registers the resolved ProjectSpec/workspace descriptor and
   hashed artifacts/tool versions, and maintains a current/final manifest.
   Before finalization it rechecks every registered size/digest and makes every
   registered artifact plus audit file `0400`. A terminal failure registers a
   redacted error artifact and recognized partial CodeQL logs without creating
   a successful normalized output.
8. The checked-in Java fixtures carry upstream Apache Maven Wrapper 3.3.4
   `only-script` launchers, declare Maven 3.9.9 and its distribution checksum,
   and use Maven `--offline`. Wrapper-cache bootstrap and attestation remain
   separately controlled prerequisites for an offline real scan; the runner
   does not observe the cached Maven binary's actual version/digest.
9. Local source materialization is copy-only. The original tree remains input-
   only, the content-addressed snapshot is read-only, and each real build uses a
   separate writable copy.

The successful branches therefore converge as follows:

```text
existing bytes → SARIF_INGESTED ──────────────────────┐
                                                     ├→ shared normalize → NORMALIZED
real build → CodeQL DB → SCANNED → real SARIF ──────┘
```

## Why this decision

A single normalizer makes offline tests representative of downstream data
semantics without misrepresenting tool provenance. Exact raw preservation and
index-based references make later claims auditable even when SARIF contains
identical repeated results. Snapshot-bound path resolution prevents a SARIF
document from selecting arbitrary local or remote content.

Maven Wrapper-only plans make the intended build tool version project-declared
and the launcher boundary testable while keeping target-specific build behavior
in ProjectSpec. Cache attestation remains external. Typed failure states
preserve the critical distinction between “normalization passed on Golden
input” and “CodeQL really ran successfully.”

## Alternatives considered

### Use only Golden SARIF until release

Rejected. It would make offline tests easy but leave no executable real-tool
adapter and encourage a false claim that fixture normalization proves CodeQL
integration.

### Require CodeQL in every CI job

Rejected for the Gate B baseline. CodeQL distribution/licensing, download size,
Java/Maven caches, and platform variance would make the core offline path less
reproducible. A separately recorded real smoke remains required release
evidence.

### Maintain separate real and Golden normalizers

Rejected. The same SARIF facts could acquire different identities or missing-
field semantics, invalidating replay and making later evidence branch-specific.

### Deduplicate identical results or paths during ingest

Rejected. Repetition can be meaningful CodeQL occurrence data. Automatic
deduplication would discard upstream alerts and break exact raw-result
traceability.

### Normalize URI paths lexically without a source snapshot

Rejected. Lexical cleanup alone cannot prove containment or detect a symlink
crossing. It would also permit source-free results that later evidence could not
reliably locate.

## Consequences

Positive consequences:

- offline Golden tests and real scan output have one deterministic contract;
- every alert/path remains reproducible and traceable to exact raw bytes;
- missing external tools and malformed inputs are visible terminal failures;
- existing snapshot content can corroborate or contradict a SARIF artifact
  hash without inventing content for missing paths;
- source trees remain input-only and writable tool output stays run-scoped;
- later context/evidence modules receive one branch-independent interface.

Costs and constraints:

- existing SARIF must be accompanied by an operator-selected local source
  snapshot; Gate B does not independently prove that it is the producing
  revision;
- strict source URI binding rejects SARIF that is syntactically legal but
  cannot be safely mapped to the snapshot;
- real scans require separately installed CodeQL/JDK and a prepared pinned
  Maven cache;
- artifact copies, command logs, event history, and manifests consume storage;
- the current workspace and timeout controls are not a complete OS sandbox.

## Security implications

The system never executes instructions found in SARIF or repository prose.
CodeQL command values are derived from validated configuration only, and all
application-managed subprocess calls use argv with `shell=False`. Raw input is
bounded; output and source locations must stay below validated roots. A real
target build still runs as the host user. Descendant-process termination,
memory-bounded output, network isolation, and CPU/memory/process quotas require
external controls appropriate to the environment.

SARIF-declared artifact hashes and coordinates are preserved as provenance. An
existing regular snapshot file is independently hashed and a conflict is
rejected; a missing file remains allowed with no verified digest. Coordinates
were not checked against actual file line/column bounds in Gate B. Gate C now
keeps those distinctions explicit and validates available files using the
run-declared SARIF `columnKind`.

Golden fixtures must be labelled as original synthetic inputs. They may prove
parser, normalizer, state, and downstream replay behavior, but they may never be
cited as evidence that the CodeQL CLI analyzed a fixture.

## Validation

This decision is satisfied when:

- Golden single-path, multi-path, pathless, duplicate, missing-snippet,
  multi-run, Windows-URI, invalid-coordinate, and malicious-URI cases have
  executable tests;
- the CodeQL runner has tests for argv construction, version/missing-tool
  handling for Java/`javac`/CodeQL, Maven Wrapper URL/SHA boundaries, exact
  qlpack pins, timeouts, exits, and artifact records;
- integration tests demonstrate both branches enter the same normalizer and
  produce the expected state history and failure audit artifacts;
- exact raw bytes, verified source hash, normalized output, resolved spec/
  descriptor, event log, and manifest are present for a successful offline CLI
  run, and every registered file is finalized `0400`;
- a tool-less real `scan` produces an explicit `CODEQL_TOOL_UNAVAILABLE`
  failure and a failed manifest;
- a successful real Java/CodeQL smoke is recorded separately when its external
  prerequisites exist. Run `20260721T114113190209Z-8d9afd2ef3b7` satisfies
  this environment-specific criterion with `NORMALIZED` zero-result SARIF;
  clean-room reproduction remains separate evidence.

## Revisit criteria

Revisit this ADR if SARIF version support expands, a second build adapter is
implemented, external sandboxing becomes part of the runner contract, or a
remote source acquisition mode changes how source identities and URIs are
bound. Any change must preserve raw provenance, branch convergence, explicit
real-versus-replay identity, and the rule that upstream alerts are not silently
dismissed.
