# Apache RocketMQ 资源泄露 V2 实验

[English](README.md) | [简体中文](README.zh-CN.md)

**实验日期：** 2026-08-14
**状态：** 真实 DeepSeek 批次与决策固化后的 V1 比较均已完成

本目录是 Apache RocketMQ 资源泄露 V2 实验可安全提交到 Git 的证据包。它记录
不可变输入身份、脱敏输出、run 身份、聚合哈希、双语协议和双语结果报告。

## 目录内容

- [实验协议](protocol.zh-CN.md)：实验边界、preflight、授权点和执行步骤。
- [结果报告](report.zh-CN.md)：实际结果、解释、限制和后续工作。
- [输入清单](inputs/experiment-manifest.json)：源码 commit、冻结 SARIF 的准确
  SHA-256 身份、查询族和结果数。
- [结果摘要](outputs/result-summary.json)：聚合模型/策略结果与固化后评估指标。
- [Run 索引](outputs/run-index.json)：成功 run ID，以及决策和 run manifest 哈希。
- `SHA256SUMS`：本实验包所有受跟踪文件的完整性索引。

## 有意不纳入 Git 的内容

RocketMQ 源码树、CodeQL 数据库、原始 SARIF 字节、私有 ProjectSpec/manifest、
凭据、EviTriage workspace、含源码的 evidence，以及远程模型原始请求/响应继续
保留在外部或 Git 忽略目录。本目录只记录它们的身份，不重新发布敏感或大型材料。

成功聚合产物位于被忽略的
`artifacts/rocketmq-resource-leak-20260812-v2/attempt-2`。本目录文件是脱敏摘要，
不能替代本地 owner-read-only 的完整审计产物。

## 结果概览

- 最终批次完成 37 条资源告警 occurrence。
- 111 次 accepted 调用：Analyst、Rebuttal、Judge 各 37 次。
- 最终策略：0 TP、0 FP、37 NMC；全部 `auto_dismiss=false`。
- Judge 候选：1 TP、25 FP、11 NMC。
- 当前版本共 26 条（input 3、output 1、database 0、lock 22），最终均为 NMC。
- 历史目标：修复前为 NMC；修复后 occurrence 消失，不是“模型判 FP”。
- V1 当前基线：26 条对齐，3 条一致（11.54%）；V2 determined rate 为 0%，
  NMC rate 为 100%。

这些结果证明保守失败的自动审计闭环可以运行，也揭示了上下文证据上限。它不是
准确率基准：V1 是人工复核而非独立验证的绝对 ground truth，且开发者此前已经
看过这些案例。
