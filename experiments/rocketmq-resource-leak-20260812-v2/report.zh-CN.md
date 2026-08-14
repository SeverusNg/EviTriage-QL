# Apache RocketMQ 资源泄露 V2 结果报告

[English](report.md) | [简体中文](report.zh-CN.md)

## 实验范围

实验使用未改写的 CodeQL SARIF，覆盖四个结构化规则族：
`java/input-resource-leak`、`java/output-resource-leak`、
`java/database-resource-leak` 和 `java/unreleased-lock`。EviTriage
收集有边界的 Java 生命周期证据，依次调用资源专用
Analyst → Rebuttal → Judge，然后执行保守的确定性策略。人工 evidence
supplement 和 V1 标签均未进入模型请求或策略决策。

真实 provider profile 为 DeepSeek V4 Pro。最终批次使用 Resource
Schema/Prompt 1.0 串行执行。输入清单记录了准确的源码 commit 和 SARIF
SHA-256。

## 告警集合与执行结果

| Case | 模式 | 告警数 | 最终 TP | 最终 FP | 最终 NMC |
| --- | --- | ---: | ---: | ---: | ---: |
| 历史修复前锁告警 | triage | 6 | 0 | 0 | 6 |
| 历史修复后锁告警 | triage | 5 | 0 | 0 | 5 |
| 当前输入资源 | triage | 3 | 0 | 0 | 3 |
| 当前输出资源 | triage | 1 | 0 | 0 | 1 |
| 当前数据库资源 | triage | 0 | 0 | 0 | 0 |
| 当前锁 | triage | 22 | 0 | 0 | 22 |
| **合计** |  | **37** | **0** | **0** | **37** |

JDBC 零结果 case 仍生成完整审计 run。两份完整 suite SARIF 仅作 audit：历史
修复前为 680，修复后为 679。当前完整 suite 有 1,939 条，没有送入模型。

成功批次共有 111 次 accepted 调用，三个角色各 37 次；没有 schema repair、
provider 失败或传输重试。全部最终决策均保持 `auto_dismiss=false`。

## 模型候选与策略闭环

Judge 候选为 25 FP、1 TP、11 NMC，但确定性策略最终输出 37 NMC：

- 19 条存在 unknown 或 unresolved 的生命周期/所有权义务；
- 7 条资源上下文不完整；
- 11 条原本就是 Judge NMC。

三个角色输出记录的 context gap 提及次数包括：
`callee_behavior` 27、`lifecycle_contract` 13、
`acquisition_success` 10、`exception_path` 10、
`ownership_contract` 5、`resource_identity` 2、
`early_exit` 1、`truncated_context` 1。这些是诊断性提及次数，不是互斥的
告警分类。

这种差异是有意设计的。当资源获取成功条件、全部可行退出、资源身份、所有权
转移、callee 行为或生命周期覆盖仍未确定时，合理的模型主张不足以直接形成
TP 或 FP。

## 第一次失败尝试与修复

第一次资源 batch 正确结束为 `incomplete`：五个非空 case 在唯一允许的
Analyst repair 后失败，数据库零结果 case 正常完成。响应模型通过跨字段校验
要求 `evidence_ids` 非空，但这一约束没有体现在生成的 JSON Schema 中。
随后用 `minItems: 1` 收紧 schema，并将 repair 反馈改成具体字段信息；focused、
完整质量和安全测试均通过后才执行成功重跑。

该失败尝试产生 10 次 invalid-response 调用（五个 case 各一次初始调用和一次
repair）。系统没有把失败伪装成 NMC，也没有声称实验已完成。

## 历史修复比较

对于 `MQClientInstance.sendHeartbeatToBroker`，修复前锁告警自动决策为 NMC。
在修复 commit 上，对应 CodeQL occurrence 已不存在：目标规则数量由 6 变为 5，
完整 suite 由 680 变为 679。告警消失是 CodeQL 比较证据，不是模型判定 FP。

## 决策固化后的 V1 比较

只有 V2 决策最终化并成为 owner-read-only 后，评估才打开 V1 人工复核基线。
对齐键为 `(raw SARIF SHA-256, run_index, result_index)`；基线从未注册为模型
证据。

| 指标 | 数值 |
| --- | ---: |
| 对齐的当前告警 | 26 |
| V1 标签 | 5 TP / 18 FP / 3 NMC |
| V2 标签 | 0 TP / 0 FP / 26 NMC |
| 一致数量 | 3 / 26（11.54%） |
| Determined rate | 0% |
| NMC rate | 100% |
| 没有 V1 基线行的历史告警 | 11 |

三分类 confusion matrix 中，V1 的 5 个 TP 和 18 个 FP 全部映射到 V2 NMC，
V1 的 3 个 NMC 仍为 NMC。因此 TP、FP 的 precision/recall/F1 均为 0；
NMC precision 为 0.1154、recall 为 1.0、F1 为 0.2069。

这只是工程比较，不是无偏准确率。V1 是人工证据复核基线，不是独立验证的绝对
ground truth，且开发者已经看过 V1 案例。

## 调用统计

完整真实调用过程共有 127 次逻辑 provider 调用：

- 合成 legacy smoke：3 次 accepted；
- 第一次未完成资源尝试：10 次 invalid response；
- 单告警资源 smoke：3 次 accepted；
- 成功完整批次：111 次 accepted。

因此 accepted 共 117 次，因结构化响应无效而拒绝 10 次。5 次 schema repair
只发生在第一次失败尝试；最终批次 repair 为 0。记录中没有出现 401、403、
429、5xx 或传输重试事件。

## 结论与下一步

V2 已打通编排和审计闭环，但尚不能确定 RocketMQ 告警集合的 TP/FP。主要限制
是 callee 行为、生命周期/所有权契约、获取条件和异常路径释放覆盖证据不足。
下一步最有价值的是增加有边界、带输入身份的 Java callee/字节码摘要；当 CodeQL
problem query 缺少路径细节时，再增加范围狭窄的自定义 CodeQL 提取，补充资源
身份和释放覆盖。不能仅为增加 TP/FP 数量而降低策略阈值。
