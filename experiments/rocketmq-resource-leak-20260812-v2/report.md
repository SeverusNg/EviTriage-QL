# Apache RocketMQ resource-leak V2 result report

[English](report.md) | [简体中文](report.zh-CN.md)

## Scope

The experiment used unchanged CodeQL SARIF for four structured rule families:
`java/input-resource-leak`, `java/output-resource-leak`,
`java/database-resource-leak`, and `java/unreleased-lock`. EviTriage
collected bounded Java lifecycle evidence and invoked the resource-specific
Analyst → Rebuttal → Judge workflow before applying its conservative
deterministic policy. No manual evidence supplement or V1 label entered a model
request or policy decision.

The live provider profile was DeepSeek V4 Pro. The final batch used Resource
Schema/Prompt 1.0 and ran sequentially. The input manifest records exact source
commits and SARIF SHA-256 values.

## Population and execution

| Case | Mode | Alerts | Final TP | Final FP | Final NMC |
| --- | --- | ---: | ---: | ---: | ---: |
| Historical pre-fix lock | triage | 6 | 0 | 0 | 6 |
| Historical post-fix lock | triage | 5 | 0 | 0 | 5 |
| Current input resource | triage | 3 | 0 | 0 | 3 |
| Current output resource | triage | 1 | 0 | 0 | 1 |
| Current database resource | triage | 0 | 0 | 0 | 0 |
| Current lock | triage | 22 | 0 | 0 | 22 |
| **Total** |  | **37** | **0** | **0** | **37** |

The zero-result JDBC case still produced a complete audited run. Two full-suite
SARIF inputs were audit-only: historical totals were 680 before and 679 after
the fix. The current full suite had 1,939 results and was not sent to the model.

The successful batch made 111 accepted calls, exactly 37 per role, with no
schema repair, provider failure, or transport retry. Every final decision kept
`auto_dismiss=false`.

## Model candidates versus policy closure

Judge proposed 25 FP, 1 TP, and 11 NMC candidates. The deterministic policy
finalized all 37 as NMC:

- 19 had unknown or unresolved lifecycle/ownership obligations.
- 7 had incomplete resource context.
- 11 were already Judge NMC.

Across role outputs, recorded context-gap mentions included
`callee_behavior` 27, `lifecycle_contract` 13,
`acquisition_success` 10, `exception_path` 10,
`ownership_contract` 5, `resource_identity` 2,
`early_exit` 1, and `truncated_context` 1. Counts are diagnostic mentions,
not mutually exclusive alert categories.

This difference is intentional. A plausible model claim is insufficient for TP
or FP when acquisition success, all feasible exits, resource identity,
ownership transfer, callee behavior, or lifecycle coverage remains unresolved.

## Failed first attempt and recovery

The first resource batch correctly ended as `incomplete`: five non-empty
cases failed after the single allowed Analyst repair, while the zero-result
database case completed. The response model required non-empty
`evidence_ids` through cross-field validation, but that constraint was not
visible in the generated JSON Schema. The schema was tightened with
`minItems: 1`, repair feedback was made field-specific, and focused,
full-quality, and security tests passed before the successful rerun.

That failed attempt issued 10 invalid-response calls (initial plus one repair
for five cases). It did not convert failures into NMC or claim a completed
experiment.

## Historical fix comparison

For `MQClientInstance.sendHeartbeatToBroker`, the pre-fix lock occurrence was
automatically finalized as NMC. At the fixed commit, the corresponding CodeQL
occurrence was absent: the target rule count changed from 6 to 5 and the full
suite from 680 to 679. Alert disappearance is CodeQL comparison evidence, not
an FP model decision.

## Post-freeze V1 comparison

Evaluation opened the V1 human-review baseline only after V2 decisions were
finalized and owner-read-only. Alignment used
`(raw SARIF SHA-256, run_index, result_index)`; the baseline was never
registered as model evidence.

| Metric | Value |
| --- | ---: |
| Aligned current alerts | 26 |
| V1 labels | 5 TP / 18 FP / 3 NMC |
| V2 labels | 0 TP / 0 FP / 26 NMC |
| Agreements | 3 / 26 (11.54%) |
| Determined rate | 0% |
| NMC rate | 100% |
| Historical rows without V1 baseline | 11 |

The three-class confusion matrix has all five V1 TP and all eighteen V1 FP
mapped to V2 NMC, while all three V1 NMC remain NMC. Thus TP and FP
precision/recall/F1 are all zero; NMC precision is 0.1154, recall is 1.0, and
F1 is 0.2069.

This is an engineering comparison, not unbiased accuracy. V1 is a human
evidence-review baseline, not independently verified absolute ground truth,
and developers had already seen the V1 cases.

## Call accounting

The full live sequence comprised 127 logical provider calls:

- 3 accepted calls for the synthetic legacy smoke.
- 10 invalid-response calls in the incomplete first resource attempt.
- 3 accepted calls for the one-alert resource smoke.
- 111 accepted calls for the successful full batch.

Therefore 117 calls were accepted and 10 were rejected as invalid structured
responses. Five schema repairs occurred only in the failed attempt; the final
batch had zero repair. No 401, 403, 429, 5xx, or transport-retry event was
observed in the recorded runs.

## Conclusion and next step

V2 closes the orchestration and audit loop but does not yet determine the
RocketMQ population. The dominant limitation is insufficient evidence for
callee behavior, lifecycle/ownership contracts, acquisition conditions, and
exception-path release coverage. The next useful improvement is a bounded,
identity-recorded Java callee/bytecode summary and, where CodeQL's problem
query lacks path detail, narrowly scoped custom CodeQL extraction for resource
identity and release coverage. Policy thresholds should not be weakened merely
to increase TP/FP counts.
