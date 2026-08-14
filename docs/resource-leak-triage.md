# Resource-leak triage and existing-SARIF batch guide

[English](resource-leak-triage.md) | [简体中文](resource-leak-triage.zh-CN.md)

## Scope

The resource-leak path accepts normalized occurrences from these exact SARIF
rule IDs:

- `java/input-resource-leak`
- `java/output-resource-leak`
- `java/database-resource-leak`
- `java/unreleased-lock`

Classification uses `rule_id`, never a message or filename. Every other rule
uses the legacy security workflow, schema, prompt, policy, and canonical Replay
identity.

## Evidence and model contract

For each occurrence, the bounded Java extractor registers the complete
enclosing method when it can safely resolve it, acquisition/release and control
flow lexical candidates, `try`/`catch`/`finally`/TWR structure, and bounded
same-file one-hop callees. Every excerpt is provenance-bound and sent as
`untrusted_code_data`; repository comments cannot grant instructions or tools.
Candidates are observations, not verified Java semantics.

The versioned `resource-leak-1.0` sequence is:

1. Analyst establishes the strongest evidence-bound acquisition and feasible
   unreleased path without choosing the final label.
2. Rebuttal tests same-resource release coverage, ownership transfer, callee
   close behavior, lifecycle contracts, aliases, and path feasibility.
3. Judge selects a TP/FP/NMC candidate using only registered evidence and
   materialized claims.
4. Deterministic policy accepts TP only with successful acquisition and a
   feasible unreleased exit; accepts FP only with complete release coverage or
   a proved ownership/callee/lifecycle contract; otherwise emits NMC.

Each role may receive at most one schema repair. An invalid response, exhausted
Replay entry, authentication error, or transport failure is a run failure, not
NMC. `auto_dismiss` is always `false`.

## Manifest and preflight

An `existing-sarif-experiment-manifest` binds the experiment and each case:

- experiment ID, LLM Profile, separate aggregate/run artifact roots, and
  workspace root;
- case ID, source root and exact commit, SARIF path and SHA-256, expected count
  and query family, `triage` or `audit_only`, and ProjectSpec;
- optional historical target and deferred baseline path.

Private absolute paths belong only in ignored `private-*.yaml` files. Validate
all inputs without loading an LLM Profile or credential:

```bash
cd /path/to/EviTriage-QL
uv run evitriage experiment preflight \
  --manifest configs/projects/private-resource-experiment.yaml \
  --json

uv run evitriage experiment run \
  --manifest configs/projects/private-resource-experiment.yaml \
  --dry-run \
  --json
```

Global preflight rejects any source commit/dirty-state, SARIF SHA/count/family,
ProjectSpec source, or workspace/artifact-root mismatch before model or
credential access. Audit-only full-suite files are counted but never sent to a
model. A zero-result triage case is still a complete run with an empty decision
artifact and zero model calls.

## Offline Replay and authorized remote execution

Use a trusted read-only cache for deterministic offline execution:

```bash
uv run evitriage experiment run \
  --manifest configs/projects/private-resource-replay.yaml \
  --replay-cache /trusted/read-only/resource-replay \
  --json
```

Remote DeepSeek execution is opt-in and requires both the ProjectSpec and LLM
Profile to allow it. Configure credentials outside Git; never put a key in a
manifest, YAML, command argument, `.env`, log, or artifact. On WSL, pass/GPG is
the preferred persistent provider. The experiment runner is sequential and
uses bounded transient retries for network errors, 429, and 5xx; it never
retries 401/403.

## Outputs and failure semantics

Every triage case gets a distinct ordinary run beneath `run_artifact_root`.
After all cases, `artifact_root` contains:

```text
preflight.json
batch-manifest.resolved.json
summary.json
automatic-decisions.jsonl
historical-comparison.json
report.md
report.zh-CN.md
report.html
execution-summary.redacted.json
SHA256SUMS
runs/<run-id>/...
```

A failed case remains `failed` with a structured error code; successful sibling
decisions remain aggregated, while the experiment status is `incomplete`.
Model failures are never converted to NMC. Aggregate files are created without
overwrite, checksum-indexed, and owner-read-only.

## Blind baseline evaluation

Do not evaluate until every automatic decision and report is finalized:

```bash
uv run evitriage experiment evaluate \
  --manifest configs/projects/private-resource-experiment.yaml \
  --json
```

This command first requires the automatic JSONL to be read-only, then opens the
baseline and joins only by `(raw SARIF SHA-256, run_index, result_index)`.
Filename, message, and expected label are not matching keys. The output records
three-class counts/confusion/precision/recall/F1, agreement, determined/NMC
rates, and unmatched rows. The baseline is human evidence review, not
independently verified absolute ground truth; prior developer exposure makes
the comparison an engineering evaluation rather than an unbiased benchmark.

## Interpretation limits

The extractor is intentionally not a Java compiler or complete CFG/alias/
ownership analysis. Unknown third-party code, dynamic dispatch, generated
source, custom locks/leases, truncated methods, or conflicting evidence must
remain visible and normally force NMC. A model's confidence cannot override
these gaps. See [known limitations](../KNOWN_LIMITATIONS.md).
