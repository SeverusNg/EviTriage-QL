# ADR 0005: Bound Gate D to evidence-closed offline structured triage

- **Status:** Accepted; provider scope extended by ADR 0006
- **Date:** 2026-07-22
- **Decision owners:** EviTriage-QL contributors
- **Applies to:** Gate D and the v0.1 offline existing-SARIF triage path

## Context

Gate C-Extra established one real query-positive CodeQL path and a closed
Evidence Registry, but deliberately emitted no Claim or vulnerability verdict.
Gate D must now make TP/FP/NMC candidates reproducible without granting a model
repository, shell, network, or alert-management capabilities. The first slice
also needs to stay useful in CI without API keys or a paid provider.

The Gate C commands finalize at `CONTEXT_READY`; Gate D needs an auditable
offline path through the Agent states without weakening those completed-run
immutability rules. Report rendering and the demo remain separate Gate E work.

## Decision

1. `StructuredLLM` is a provider-neutral generic protocol. Gate D supplies only
   `FakeLLM` and read-only `ReplayLLM`; both use the same strict Pydantic response
   parsing, reject duplicate JSON keys/non-finite values/extra fields, and need
   no network or credential.
2. A canonical request SHA-256 covers the system prompt, JSON payload, response
   schema, Agent role, profile/model identity, temperature, output limit, and
   offline data policy. Replay resolves only `<request-sha256>.json` below one
   trusted cache root, bounds reads to 2 MiB, and refuses symlink entries.
3. Agent output uses `ClaimDraft`. Code—not the model—assigns the final stable
   Claim ID from canonical claim content and producer role. Every evidence
   reference must belong to the exact `(alert fingerprint, raw SARIF hash, run
   index, result index)` occurrence before a role output is accepted.
4. `TriageWorkflow` executes exactly Analyst, Rebuttal, then Judge. Each role
   receives one primary call and at most one schema/evidence repair call; one
   alert is capped at six calls and each request is capped at 1 MiB. A repair
   receives only a fixed error code, never untrusted raw model output.
5. Repository/SARIF excerpts remain under a JSON `untrusted_code_data` field.
   Every system prompt says that this content is inert data and grants no
   shell, filesystem, Git, network, secret, or dismissal capability. Judge sees
   only the selected evidence and candidate claims.
6. The deterministic policy treats the Judge label as a candidate. It returns
   NMC for empty critical evidence, critical unknown/unresolved claims, or
   conflicting high/decisive evidence. TP requires critical supported Analyst
   claims for source controllability, path feasibility, and dangerous sink
   semantics, each backed by matching medium-or-stronger evidence, or decisive
   successful verification. FP requires a critical Rebuttal claim marked
   rebutted and backed by decisive FP evidence; a high/decisive TP conflict
   forces NMC. `auto_dismiss` is a literal `false`.
7. Raw confidence is preserved for audit but cannot override a policy gate.
   Calibrated probabilities remain `null` until calibration exists.
8. `evitriage triage` accepts ProjectSpec, existing SARIF, a trusted offline
   profile, and a read-only Replay cache. It creates a fresh managed run, reuses
   the shared normalize/context/evidence implementation, writes strict Analyst,
   Rebuttal, and judged artifacts, and journals
   `ANALYZED → REBUTTED → JUDGED`. It never reopens or mutates a finalized Gate C
   run.
9. Each execution retains a unique operational manifest `run_id`. The domain
   bundle, context, registry, and invocation context use a content-derived
   `analysis_identity` over source-tree digest, raw-SARIF digest, commit, and
   normalizer version. Equivalent inputs can therefore address the same Replay
   entries without conflating their execution journals.
10. Persisted invocation records contain request/prompt/validated-response
    hashes, profile/model, role, attempt, and validation status—not raw prompts
    or copied Replay entries. A missing entry terminates in `MODEL_FAILED` with
    bounded request provenance. Reports and cache production remain outside
    this decision.

## Consequences

Fake fixtures can exercise TP, decisive-FP, conflict-NMC, and missing-decisive-
rebuttal downgrade behavior deterministically. The same three requests can be
materialized as request-hash cache entries and replayed to the identical claims,
decision, and invocation identities. Unknown evidence or claim IDs consume at
most the bounded repair attempt and then fail explicitly.

A CodeQL data-flow observation alone cannot pass the TP gate. This preserves
Gate C's rule that an upstream path is not by itself exploitability proof.

The policy is intentionally more conservative than a model. A plausible FP
candidate with only high evidence still becomes NMC under the current trusted
configuration's `fp_requires_decisive_rebuttal: true`. This can increase human
review volume but prevents unsupported automatic false-positive classification.

`scan` and `ingest-sarif` continue to produce immutable Gate C runs. Gate D's
separate existing-SARIF command reaches `JUDGED`; it does not yet resume a prior
run or chain directly from CodeQL scan output. Gate E remains responsible for
the offline input-to-report demo, JSONL/HTML publication, and convenient
end-to-end chaining.

## Security implications

Fake and Replay are adapters, not sandboxes for an arbitrary future provider.
Their interfaces grant no tools, and Replay performs only bounded no-follow
reads from its configured cache. A cache producer/operator remains responsible
for provenance and confidentiality of cache contents; Gate D does not write
cache entries or attest an external producer.

Prompt-injection defense here is structural and tested, but model behavior is
not itself a security boundary. Closed evidence/claim validation and the
deterministic policy remain authoritative even when untrusted source text asks
the role to ignore instructions, read secrets, run commands, or dismiss alerts.

## Validation

Acceptance requires strict generated schemas, a complete Fake TP/FP/NMC matrix,
full Replay of a three-role result, one-repair exhaustion tests, unknown
evidence rejection, prompt-injection containment assertions, request-hash
stability, Replay cache miss/symlink/duplicate-key tests, a CLI integration run
through every Gate D state with owner-read-only artifacts, and an auditable
`MODEL_FAILED` Replay miss. `make check` must remain green at the repository
coverage gate.
