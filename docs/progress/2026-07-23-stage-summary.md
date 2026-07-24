# EviTriage-QL stage summary

[English](2026-07-23-stage-summary.md) | [简体中文](2026-07-23-stage-summary.zh-CN.md)

**Report date:** July 23, 2026  
**Executability review:** July 24, 2026  
**Subject:** Ubuntu server and Windows WSL2 experimental progress

> This is an evidence-bounded stage handoff, not a replacement specification
> for current behavior. Use the CLI, strict schemas, tests,
> [README](../../README.md), and
> [known limitations](../../KNOWN_LIMITATIONS.md) to determine what is
> currently available.

## 0. Executability conclusion

**Overall conclusion: conditionally executable.** The offline acceptance
baseline, release-closure verification, and real CodeQL scan over the fixed
fixture have concrete commands. DeepSeek and strict two-host experiments still
depend on external state, operator authorization, and measurement/automation
work that has not yet been completed.

| Scope | Assessment | Prerequisite or gap |
| --- | --- | --- |
| Offline quality gates and six-case Replay | Directly executable | Dependencies must be synchronized; `make demo` needs no network or API key |
| Historical artifact audit on this host | Executable on the review host, but not portable | `artifacts/` and `dist/` are Git-ignored and will not exist in another clone |
| Real CodeQL scan of the fixed Java fixture | Conditionally executable | CodeQL 2.26.1, JDK 17, offline Maven 3.9.9 caches; executes trusted fixture build code |
| DeepSeek `triage --scan` | Execute only after explicit authorization | Uploads bounded source/evidence and incurs network use and cost; credentials must remain outside the repository |
| Strict two-host clean-room reproduction | Not yet a one-command workflow | No unified script, common input bundle, or machine-readable cross-host result aggregation |
| Token, cost, and latency measurement | Only duration can be derived from timestamps | Invocation records do not persist provider token usage or cost; instrumentation is required first |
| Public-dataset and ablation experiments | A research plan, not a runnable entry point | No frozen dataset, provenance/license inventory, label protocol, experiment configs, or aggregator |

This review made the following corrections:

- moved the document under `docs/progress/` and added a complete language pair;
- fixed repository-relative links that previously included one extra
  `EviTriage-QL/` path component;
- separated checked-in release/progress evidence from Git-ignored host-local
  artifacts;
- added commands, risks, and acceptance conditions for offline acceptance,
  real scans, and explicitly authorized remote end-to-end runs;
- made clear that “repeat three times and report tokens/cost” is not fully
  executable until measurement fields are implemented.

## 1. Project objective

EviTriage-QL performs secondary triage of CodeQL static-analysis alerts. It
preserves CodeQL source-to-sink paths, extracts bounded source context and
addressable evidence, and then runs Analyst, Rebuttal, and Judge in order. The
result is one of:

- `TP`: the evidence supports a true positive;
- `FP`: decisive rebuttal evidence supports a false positive;
- `NMC` (Needs More Context): the evidence is insufficient and the system
  refuses to force a binary decision.

The goal is not to have a model rescan an entire repository. It is to create a
traceable and reproducible relationship between alert, path, source slice,
evidence, and conclusion. Deterministic policy constrains every conclusion,
and the system never automatically dismisses an upstream CodeQL alert.

## 2. Implemented technical scope

The repository now contains a runnable `v0.2.0` prototype:

```text
Local Java project / existing SARIF
→ CodeQL scan or SARIF ingest
→ SARIF 2.1.0 normalization
→ bounded path / lexical-callable context
→ Evidence Registry
→ Analyst / Rebuttal / Judge
→ TP / FP / NMC policy
→ JSONL, HTML, and run manifest
```

The implemented stage includes:

1. `ProjectSpec`, source snapshots, and isolated run directories for separate
   experiment targets, with tool versions, configuration, and artifact
   SHA-256 values recorded.
2. Real CodeQL scanning and existing-SARIF ingest converging on the same
   normalization, context, and evidence pipeline.
3. A strict three-role Agent workflow. Every Claim must cite registered
   Evidence; conflicts or missing decisive evidence conservatively produce
   NMC.
4. Offline Fake/Replay models and a DeepSeek V4-Pro/Flash adapter. Both the
   project and model profiles must explicitly authorize remote use.
5. Environment, TPM2/systemd-creds, and pass/GPG credential backends. A
   selected backend fails closed and never silently falls back.
6. JSONL/HTML reports, event history, run manifests, wheel and source
   distributions, dependency inventory, and a CycloneDX SBOM.

## 3. Results from both environments

| Environment | Completed experiments | Main result |
| --- | --- | --- |
| Native Ubuntu server | Toolchain deployment, real CodeQL scan, TPM2 credential path, online DeepSeek smoke | Pinned uv 0.8.3, Java 17.0.19, and CodeQL 2.26.1. The Socket-based CWE-22 case produced one `java/path-injection` result with a complete eight-step path. All three DeepSeek V4-Pro calls succeeded in about 31.9 seconds and conservatively produced NMC with `auto_dismiss=false`. Exact commands, run IDs, and interpretation limits are checked into the delivery log. |
| Windows WSL2 (Ubuntu 22.04) | Real CodeQL scan, offline Replay, v0.2.0 release verification, online DeepSeek smoke | Python 3.12.11, uv 0.8.3, Java 17.0.19, and CodeQL 2.26.1. The real scan took about 29 seconds and produced four results: two path-injection results, one command-line-injection result, and one relative-path command result. It produced three paths, four complete contexts, eleven evidence items, and reached `CONTEXT_READY`. These details are supported by Git-ignored host-local artifacts, not portable repository evidence. |

Additional WSL observations:

- Seven retained runs of the six-case offline Replay share analysis identity
  `analysis-de8e383c…` and the same `3 TP / 2 FP / 1 NMC` distribution, with
  eighteen fixed-response calls per run. This demonstrates deterministic
  workflow behavior; the labels and Replay responses are synthetic and do not
  demonstrate model accuracy.
- The `v0.2.0` release summary records 249/249 full tests passing at 83.75%
  branch-aware coverage and 41 security tests passing. This review also ran
  `sha256sum --check` over all thirteen entries in the host-local
  `dist/release/0.2.0/SHA256SUMS`; all passed. The directory remains
  Git-ignored.
- The first online DeepSeek attempt failed closed with HTTP 401 at Analyst and
  recorded `MODEL_FAILED`. After credential correction, the second attempt
  completed all three roles in about 31.3 seconds, accepted all structured
  responses, produced NMC, and wrote JSONL/HTML reports. It ingested existing
  synthetic SARIF with `real_codeql=false`; it was not a vulnerability verdict
  following a real scan.

Both environments produced four CodeQL query results from the same six-case
Java project, supporting cross-environment consistency of the critical scan
and evidence-extraction path. They have not yet reinstalled from scratch and
run the entire command set under one identical clean-room protocol. The
defensible claim is therefore “dual-environment critical-path validation,”
not strict second-host full reproduction.

## 4. Stage findings

1. The prototype implements the blueprint's minimum v0.1 vertical slice. Its
   strengths are evidence constraints, conservative three-way classification,
   and end-to-end auditability—not model self-reported confidence.
2. Both real-model smokes conservatively returned NMC. The WSL run observed a
   dangerous sink and data-flow path but lacked evidence of entry-point
   controllability and exploitability, so it did not directly return TP. This
   is one model-behavior observation over synthetic input.
3. The main Ubuntu/WSL differences are credentials and base environment.
   Native Ubuntu can use TPM2/systemd-creds; WSL generally needs a
   process-scoped environment credential or separately installed pass/GPG.
   Bare `python3` in that WSL is 3.11, so Python 3.12 must be reached through
   `uv run` or the project environment.

## 5. Current limitations

- The six cases are a synthetic microbenchmark, not a human-labelled public
  project dataset. They cannot establish accuracy or generalization.
- Recorded real CodeQL scans stop at `CONTEXT_READY`; recorded online DeepSeek
  runs ingest existing SARIF. No accepted “real scan → real model → JUDGED”
  artifact has been retained.
- Formal CodeQL-only, single-call LLM, single-Agent, and three-Agent baselines
  and ablations have not been run.
- Provider token usage, pricing snapshots, and experiment cost are not
  persisted. Existing invocation records cannot reliably calculate tokens or
  cost.
- Java context is bounded and based on windows or lexical callable boundaries.
  Dynamic verification, calibrated confidence, and cross-project/time
  evaluation remain unimplemented.
- Host-local evidence under `artifacts/` and `dist/` is excluded from Git.
  Cross-host reproduction requires explicit packaging, hashing, transfer, and
  independent verification; local paths in this document are insufficient.

## 6. Executable next-stage plan

Run every command from the repository root. Never place a real API key in
chat, command arguments, YAML, `.env`, scripts, logs, Git, or run artifacts.

### 6.1 Establish the offline baseline on each host

```bash
uv sync --all-extras
make check
make security-test
make demo
uv run --offline evitriage doctor --json
make release-artifacts
make release-verify
```

Acceptance conditions:

- record host, commit, start/end time, exit code, and machine-readable summary
  for each command;
- `make demo` reaches `JUDGED`, produces `TP=3 / FP=2 / NMC=1`, and keeps every
  `auto_dismiss=false`;
- record Python, uv, Java/Javac, CodeQL, and Maven identities;
- run `make release-verify` independently on both hosts; never substitute one
  host's success for the other;
- the first `uv sync` may download locked dependencies. “Offline
  reproduction” begins only after dependencies and tools have been prepared.

### 6.2 Reproduce real CodeQL on the fixed six-case fixture

A real scan executes the fixture's Maven Wrapper as the current host user.
Scan only trusted source; isolate third-party targets in a VM, container, or
dedicated account first.

```bash
codeql version --format=terse
java -version
javac -version

uv run --offline evitriage project validate \
  --config configs/projects/gate-e-demo.yaml \
  --json

uv run --offline evitriage scan \
  --project-config configs/projects/gate-e-demo.yaml \
  --json
```

Acceptance requires exit code 0, `real_codeql=true`, and terminal state
`CONTEXT_READY`. With frozen source, queries, and tool versions, four results
and three paths are expected. If counts or hashes change, preserve and explain
the difference rather than editing the summary to force a match.

### 6.3 Complete an authorized real-scan-to-DeepSeek path

Before execution:

1. obtain explicit operator approval for source/evidence upload, provider
   terms, and expected cost;
2. configure credentials outside the repository using the
   [deployment guide](../deployment-guide.md#9-optional-remote-deepseek-triage)
   and inspect only non-secret state with `credentials status --json`;
3. implement and test non-secret measurement fields for at least per-role
   latency, provider token usage, pricing-snapshot identity, and failure class.
   Without those fields, report only total duration and do not claim a
   token/cost experiment.

For an approved process-scoped environment credential:

```bash
uv run --offline evitriage doctor --json
uv run evitriage credentials status --json

uv run evitriage triage \
  --project-config configs/projects/example-local-deepseek-v4.yaml \
  --scan \
  --llm-profile configs/llm/deepseek-v4-pro.yaml \
  --credential-provider environment \
  --json
```

Acceptance requires `real_codeql=true`, terminal state `JUDGED`, accepted
Analyst/Rebuttal/Judge calls, present reports, and
`auto_dismiss=false`. Repeat independently at least three times, preserve
failed runs, and never silently retry or fall back. This validates pipeline and
model behavior; it does not establish accuracy.

### 6.4 Entry gate for dataset and ablation experiments

There is no directly executable repository command for this stage. Before
running it, check in at least:

- a frozen dataset inventory with licenses, provenance, and hashes;
- a human-label protocol with dual review and disagreement handling;
- project-disjoint and chronological split manifests;
- versioned configurations for CodeQL-only, fixed-window single-call LLM,
  path-slice single-call LLM, and three-role Agent conditions;
- a machine-readable aggregator for Precision, Recall, F1, FP reduction, NMC
  rate, coverage-risk, latency, and cost.

## 7. Evidence

### Available from Git

- [v0.1 delivery evidence log](2026-07-27-v0.1.md)
- [v0.2.0 release notes](../releases/v0.2.0.md)
- [Reproducibility guide](../reproducibility.md)
- [Deployment guide](../deployment-guide.md)

### Git-ignored artifacts on the review host

These paths support local audit but are not available from another clone or a
GitHub page:

```text
artifacts/runs/20260723T070306673935Z-e8922e9b1b7b/run-manifest.json
artifacts/runs/20260723T152521860604Z-348f900c340c/metadata/error.json
artifacts/runs/20260723T152652636073Z-0c072858d1d1/run-manifest.json
dist/release/0.2.0/
```

Verify the host-local release closure with:

```bash
(cd dist/release/0.2.0 && sha256sum --check SHA256SUMS)
```
