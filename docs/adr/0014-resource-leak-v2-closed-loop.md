# ADR 0014: Separate resource-leak triage and close existing-SARIF experiments

[English](0014-resource-leak-v2-closed-loop.md) | [简体中文](0014-resource-leak-v2-closed-loop.zh-CN.md)

- **Status:** Accepted for offline implementation; live RocketMQ evidence pending authorization
- **Date:** 2026-08-14
- **Applies to:** Java resource-leak workflow, policy, evidence, batch, and evaluation

## Context

The legacy Gate D path requires source/data-flow/sink evidence for security
vulnerabilities. Resource leaks instead require acquisition success, identity,
exit coverage, release, and ownership/lifecycle reasoning. Extending the legacy
claim enum would change its response schema and canonical Replay hashes. CodeQL
problem queries may also have no `codeFlows`, so the former path/function slice
did not necessarily place usable lifecycle source in the model payload.

The RocketMQ experiment additionally requires all frozen input identities to be
validated before any paid model call and requires V1 human review to remain
blind until automatic decisions are immutable.

## Decision

1. Dispatch only the four exact resource rule IDs to a separate versioned
   `resource-leak-1.0` workflow. Preserve the legacy schema and Replay identity.
2. Register complete bounded method source as untrusted evidence, lexical
   lifecycle/exit candidates, and bounded same-file one-hop callees. Record
   every parse/budget/source omission; do not upgrade lexical observations to
   verified semantics.
3. Use strict resource Analyst/Rebuttal/Judge outputs. Each role gets at most
   one repair and may cite only evidence for the exact SARIF occurrence.
4. Apply a separate fail-closed policy. TP requires successful acquisition and
   a feasible unreleased exit with no release/ownership conflict. FP requires
   complete release coverage or a proved ownership/callee/lifecycle contract.
   Unknown, partial, or conflicting critical facts force NMC.
5. Add a strict manifest runner for existing SARIF. Perform global commit,
   cleanliness, SHA, result-count/family, ProjectSpec, and root checks before
   profile/credential access; then run cases sequentially with separate runs.
   Preserve zero results and partial successes; never convert model failures to
   NMC or report an incomplete batch as complete.
6. Aggregate reports and historical before/after comparison first, checksum and
   freeze them, then allow a separate evaluator to open the V1 baseline and
   bind rows only by exact raw occurrence identity.
7. Keep target-specific paths in ignored manifests/ProjectSpecs. Do not add a
   RocketMQ exception to core logic and do not invoke `--scan` without a
   checked-in wrapper.

## Consequences

Resource requests have their own schema/prompt hashes and do not invalidate
legacy Replay fixtures. Model requests contain provenance-bound bounded source
and evidence but may still contain confidential repository text, so remote use
requires explicit authorization and credential separation.

The conservative policy will produce NMC when a compiler/CFG/alias proof,
third-party implementation, framework contract, or custom protocol is missing.
This is intentional. No `javap` adapter or online source acquisition is added.

Batch execution is sequential and has no checkpoint continuation. Successful
sibling cases remain auditable after a failure, while aggregate status remains
incomplete. The post-freeze baseline comparison is an engineering agreement
study, not an independent accuracy benchmark.

## Validation

Offline acceptance covers exact dispatch, legacy Replay stability, lifecycle
paths including TWR/finally/return/throw/break/continue and lock acquisition,
ownership and unknown-callee behavior, prompt injection, strict evidence IDs,
one repair, zero-result closure, preflight-before-model, model failure semantics,
path/symlink/HTML/secret boundaries, Fake/Replay end-to-end execution, and the
frozen RocketMQ dry-run. Live validation remains prohibited until the operator
explicitly authorizes the DeepSeek smoke and bounded full experiment.
