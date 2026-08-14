# Apache RocketMQ resource-leak V2 experiment

[English](README.md) | [简体中文](README.zh-CN.md)

**Experiment date:** 2026-08-14
**Status:** completed live DeepSeek batch; post-freeze V1 comparison completed

This directory is the Git-safe evidence package for the Apache RocketMQ
resource-leak V2 experiment. It records immutable input identities, sanitized
outputs, run identities, aggregate hashes, the bilingual protocol, and the
bilingual result report.

## Contents

- [Protocol](protocol.md): experiment boundary, preflight, authorization, and
  execution procedure.
- [Result report](report.md): observed results, interpretation, limitations,
  and follow-up work.
- [Input manifest](inputs/experiment-manifest.json): source commits, exact
  frozen SARIF SHA-256 identities, query families, and result counts.
- [Result summary](outputs/result-summary.json): aggregate model/policy and
  post-freeze evaluation metrics.
- [Run index](outputs/run-index.json): successful run IDs and hashes for their
  decision and run-manifest artifacts.
- `SHA256SUMS`: integrity index for every tracked file in this package.

## What is intentionally excluded

The following stay in external or Git-ignored storage: RocketMQ source trees,
CodeQL databases, raw SARIF bytes, private ProjectSpecs/manifests, credentials,
EviTriage workspaces, source-bearing evidence, and raw remote-model
requests/responses. Their identities are recorded here without republishing
sensitive or bulky material.

The successful local aggregate was written under the ignored path
`artifacts/rocketmq-resource-leak-20260812-v2/attempt-2`. The files here are
sanitized summaries, not substitutes for the full owner-read-only audit
artifacts.

## Result at a glance

- 37 resource-alert occurrences completed in the final batch.
- 111 accepted calls: 37 Analyst, 37 Rebuttal, and 37 Judge.
- Final policy: 0 TP, 0 FP, 37 NMC; `auto_dismiss=false` throughout.
- Judge candidates: 1 TP, 25 FP, 11 NMC.
- Current revision: 26 occurrences (3 input, 1 output, 0 database, 22 lock),
  all finalized as NMC.
- Historical target: pre-fix NMC; post-fix occurrence absent, not “model FP.”
- V1 current baseline: 26 aligned, 3 agreements (11.54%), with V2 determined
  rate 0% and NMC rate 100%.

These results demonstrate a fail-closed automated audit loop and expose a
context-evidence ceiling. They are not an accuracy benchmark: V1 is human
review rather than independently verified ground truth, and developers had
already seen those cases.
