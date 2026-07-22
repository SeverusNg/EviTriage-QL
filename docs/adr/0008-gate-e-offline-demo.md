# ADR 0008: Bind the offline demo to a fixed synthetic Replay bundle

- Status: Accepted
- Date: 2026-07-23
- Gate: E (deterministic NMC demo slice)

## Context

The integrated report path can finish a fresh existing-SARIF `triage` run, but
an operator still has to supply a Replay cache whose canonical request hashes
match the current source, SARIF, prompts, response schemas, and profile. Gate E
requires a one-command demonstration without CodeQL, network access, an API
key, or a real model. Silently generating responses during the demo would
weaken Replay and make the decision provenance ambiguous.

## Decision

The repository carries one Apache-2.0 synthetic NMC bundle under
`tests/fixtures/replay-bundles/gate-e-nmc-v0.1`. Its response files use the
ordinary canonical request SHA-256 filenames consumed by `ReplayLLM`; no demo-
specific model bypass or response parser exists.

The strict fixture manifest inventories:

- the raw ProjectSpec and SARIF identities and the source-tree identity;
- the canonical offline Replay profile digest;
- ordered Analyst, Rebuttal, and Judge request hashes;
- every response filename and content SHA-256;
- synthetic authorship, Apache-2.0 licensing, the expected NMC result, and
  explicit non-quality limitations.

`make demo` runs the normal `triage` CLI with `uv run --offline` and only those
checked-in inputs. It emits the CLI's one-line JSON summary and creates the
ordinary run-confined, hash-registered, owner-read-only artifacts. The NMC
response still passes strict schemas, exact evidence closure, and the
deterministic policy; it cannot set `auto_dismiss=true`.

Acceptance runs the Make target in a temporary isolated checkout with the
DeepSeek environment key removed. It validates the bundle manifest, proves the
public summary and JSONL parse strictly, compares the source tree before and
after, and rechecks every manifest artifact's size, SHA-256, and `0400` mode.

## Consequences

- A fresh environment with locked dependencies can execute
  `ingest → normalize → context → triage → report` with one command and no
  Java, CodeQL, credential, network request, or real model.
- Any change to request-shaping inputs causes an explicit Replay miss instead
  of accepting a stale response.
- The bundle is a deterministic workflow fixture. Its NMC decision is not a
  model output, vulnerability verdict, calibration result, or evidence about
  arbitrary code.
- ADR 0009 subsequently replaces the default demo with three TP/FP/NMC cases
  and adds direct scan-to-triage chaining. Prior-run continuation, a standalone
  report command, and a general Replay cache producer or external attestation
  format remain later work.
