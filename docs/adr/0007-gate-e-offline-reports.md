# ADR 0007: Generate evidence-closed offline reports before run finalization

- Status: Accepted
- Date: 2026-07-23
- Gate: E (first vertical slice)

## Context

Gate D persists normalized alerts, bounded context, an Evidence Registry,
ordered Agent outputs, and deterministic decisions, but those artifacts are
split across several files. Gate E needs independently usable JSONL for later
evaluation and an HTML view for human audit without weakening the closed
evidence boundary or reopening owner-read-only runs.

Generating reports after finalization would either leave them outside the run
manifest or require mutating an already sealed audit record. A report also
contains untrusted SARIF, repository, and model-authored text, so active HTML
content must be impossible.

## Decision

Fresh successful `triage` runs build reports immediately after the `JUDGED`
transition and before `RunJournal.complete()`.

For each exact raw SARIF `(run_index, result_index)` occurrence, a strict
`AlertReport` binds:

- operational run, project/config, snapshot/repository, input, tool, profile,
  and model provenance;
- one normalized alert and one content-addressed SliceArtifact;
- only Evidence Registry items for the same fingerprint and raw occurrence;
- Analyst/Rebuttal Claims, Judge candidate, deterministic FinalDecision, and
  invocation hashes;
- context history, explicit unperformed verification, unknowns, next actions,
  human-label absence, and conservative limitations.

Model validation rejects cross-alert joins, duplicate occurrences, unavailable
Claim evidence, dangling critical Claim/evidence IDs, or context history that
does not match the persisted slice. The JSONL renderer writes one canonical
object per alert. The self-contained HTML renderer escapes every interpolated
untrusted value. Neither renderer changes the decision, calibrates confidence,
performs verification, or gains alert-dismiss authority.

The two outputs are registered as `report` artifacts at
`reports/decisions.jsonl` and `reports/index.html`; finalization rechecks their
size/SHA-256 and applies owner-read-only permissions.

## Consequences

- A fresh offline Replay triage now closes the path through auditable report
  artifacts without network access or a real model.
- Each JSONL row is strict and independently usable, while HTML remains safe
  from script-shaped SARIF/source/model text.
- Report provenance is covered by the same manifest as input, evidence, model,
  and decision artifacts.
- JSONL/HTML can contain bounded selected source/evidence text and must be
  protected as source-confidential material; HTML escaping is not redaction.
- ADR 0008 subsequently added the first fixed single-NMC `make demo` path, and
  ADR 0009 added the three-label fixture plus direct scan-to-triage chaining.
  A standalone `report --run-id` command, prior-run continuation, and cross-run
  aggregation remain later work.
