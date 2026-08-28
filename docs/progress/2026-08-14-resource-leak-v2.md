# Resource-leak V2 implementation and live experiment evidence

[English](2026-08-14-resource-leak-v2.md) | [简体中文](2026-08-14-resource-leak-v2.zh-CN.md)

**Date:** 2026-08-14  
**State:** authorized live closed loop complete; all 37 final decisions are conservative NMC

[Git-safe experiment package](../../experiments/rocketmq-resource-leak-20260812-v2/README.md)

## Implemented and verified

- Exact four-resource-family dispatch with unchanged legacy security identities.
- Separate strict resource Analyst/Rebuttal/Judge schemas and fail-closed policy.
- Bounded method/lifecycle/callee evidence, explicit gaps, and inert-source boundary.
- Manifest-wide preflight, sequential runs, zero-result closure, audit-only suites,
  immutable bilingual aggregation, history comparison, and post-freeze evaluation.
- Resource evidence arrays expose `minItems: 1`; one repair receives bounded
  field-level issues without weakening unknown-ID rejection.

The final post-live-fix checks were `make check` (exit 0, 285 passed, 81.62%
coverage), `make security-test` (exit 0, 41 passed), focused resource/Fake/
Replay/batch tests (exit 0, 34 passed), and preflight (exit 0, 37 alerts,
111–222 calls). Earlier required doctor, four ProjectSpec validations, ingest
smoke, `make demo`, dry-run, and `git diff --check` also exited 0.

## Authorized live execution

Credential status selected pass/GPG without exposing the key. Synthetic legacy
smoke run `20260814T060228810603Z-9e5fc3d0979b` completed three calls. The first
resource batch correctly ended `incomplete`: five non-empty cases exhausted one
Analyst repair with `MODEL_RESPONSE_INVALID`; JDBC zero-result completed and
redacted failure records were preserved. A post-fix one-alert resource smoke,
run `20260814T063250067970Z-79184cd88a3a`, completed three accepted calls.

The successful aggregate is
`artifacts/rocketmq-resource-leak-20260812-v2/attempt-2`.

| Case | Run ID | Alerts / calls | Final |
| --- | --- | ---: | --- |
| historical pre lock | `20260814T063819539272Z-38a0d7507184` | 6 / 18 | 6 NMC |
| historical post lock | `20260814T064412825418Z-8cbf3ce0c9ac` | 5 / 15 | 5 NMC |
| current input | `20260814T064907745727Z-7311b1478da2` | 3 / 9 | 3 NMC |
| current output | `20260814T065147952685Z-463aabc33e45` | 1 / 3 | 1 NMC |
| current database | `20260814T065258895366Z-e5e1b5aac419` | 0 / 0 | complete zero-result |
| current lock | `20260814T065300685754Z-87089c69c61b` | 22 / 66 | 22 NMC |

All 111 final invocations were accepted attempt 0: 37 per role, no repair or
failure. Judge candidates were 25 FP / 1 TP / 11 NMC. Policy finalized 37 NMC:
19 `unknown_or_unresolved`, 7 `resource_context_incomplete`, and 11
`judge_requested_nmc`; `auto_dismiss` remained false.

## Historical and baseline comparison

The pre-fix `sendHeartbeatToBroker` target was NMC with registered critical
evidence. The post-fix occurrence was absent, not model-FP; counts were 6→5 and
full suites 680→679. Decisions were immutable before evaluation and
`baseline_registered_as_model_evidence=false`.

All 26 current occurrences aligned. V1 was 5 TP / 18 FP / 3 NMC; V2 was
0 / 0 / 26. Agreement was 3/26 (11.54%), determined rate 0%, and NMC rate 100%.
Eleven historical occurrences intentionally lacked V1 rows. This is an
engineering comparison, not unbiased accuracy. The next capability boundary is
compiler-grade CFG/exception coverage, stronger alias identity, and local
callee/ownership summaries; custom CodeQL evidence queries may be warranted.
