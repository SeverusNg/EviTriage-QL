# Apache RocketMQ 资源泄露实验（2026-08-12）

[English](README.md) | [简体中文](README.zh-CN.md)

本目录是第一次 Apache RocketMQ 真实项目资源泄露实验的、可供评审且适合进入 Git 的证据包。实验使用 CodeQL 2.26.1 与 EviTriage-QL 0.2.0。

本目录有意**不包含** RocketMQ 源码、CodeQL 数据库、原始 SARIF、Maven 构建产物、EviTriage 工作区、模型请求/响应或凭据。这些输入和运行产物继续保存在 Git 之外。本证据包记录它们的身份、位置、哈希、数量、命令、退出码和人工复核结论，以便 EviTriage 具备资源泄露专项自动研判能力后，复用完全相同的冻结输入开展第二次实验。

## 目录内容

- [report.md](report.md)：完整英文实验报告，包括历史回归验证、当前版本扫描、EviTriage 兼容性结论与证据化分析。
- [report.zh-CN.md](report.zh-CN.md)：语义对齐的简体中文报告。
- [experiment-manifest.json](experiment-manifest.json)：机器可读的仓库、工具、构建、数据库、SARIF 与 EviTriage 运行清单。
- [alert-triage.jsonl](alert-triage.jsonl)：当前版本 26 条资源泄露告警的逐条 TP/FP/NMC 结论和简要证据。这些标签来自人工证据复核，不是模型输出。
- `SHA256SUMS`：九份冻结外部 SARIF 输入和原始本机报告的 SHA-256 身份。

## 已确认结果摘要

- 历史修复前版本产生 6 条 `java/unreleased-lock` 告警，修复后版本产生 5 条。消失的告警准确定位 `MQClientInstance.sendHeartbeatToBroker`；提交 `a6c5604b6cb6fce255fe9e0e6e860f94d37c2050` 将风险操作移入 `try/finally` 后，同一告警消失。
- 当前 RocketMQ 版本在四个指定查询下共得到 26 条告警：输入资源 3 条、输出资源 1 条、数据库资源 0 条、锁 22 条。
- 人工证据复核结果为 TP 5 条、FP 18 条、NMC 3 条。它可作为后续比较基线，但不是独立验证过的绝对 ground truth。
- EviTriage 成功接收并构建了四份 code-quality SARIF 的上下文。离线研判随后如实停在 `MODEL_FAILED`，错误为 `MODEL_REPLAY_MISS`：仓库内 Replay 缓存没有资源泄露响应，未授权远程模型，因此没有产生任何自动 TP/FP/NMC 标签。
- 当前 EviTriage 的提示词和 schema 面向安全漏洞利用，缺少资源获取、释放覆盖与所有权转移等明确 claim。必须先补足这部分代码能力，再用冻结 SARIF 开展实验 V2，才能形成自动闭环。

## 外部证据保留位置

以下路径只存在于实验主机，均位于仓库外或受 Git 忽略保护：

| 用途 | 本机路径 | 保留规则 |
|---|---|---|
| RocketMQ 镜像/当前源码 | `/home/nigeriacrop/code/third-party/rocketmq` | 始终置于 EviTriage Git 之外 |
| 冻结实验根目录：worktree、Maven、CodeQL 数据库、SARIF、日志 | `/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812` | 作为只读 V1 证据保留 |
| EviTriage ingest/triage 运行与原始中文报告 | `/home/nigeriacrop/code/EviTriage-QL/artifacts/rocketmq-resource-leak-20260812` | Git 已忽略；不要删除 |
| EviTriage 源码快照/工作区 | `/home/nigeriacrop/code/EviTriage-QL/workspaces` | Git 已忽略；保留报告引用的 run ID |
| 私有本地 ProjectSpec | `/home/nigeriacrop/code/EviTriage-QL/configs/projects/private-rocketmq-resource-leak.yaml` | Git 已忽略；不得公开私有 provider 设置 |

原始本机报告 SHA-256 为 `4282758d08a0cb583c217f5a64247d4b3b1da59d5939b6b9e37403725dfecfd9`。原始 SARIF 的身份记录在 `SHA256SUMS` 和 `experiment-manifest.json` 中。

## 实验 V2 复用约定

不要覆盖 V1 证据。在实现资源专项 claims、证据收集、Replay fixture/真实 provider 授权与判定策略后：

1. 新建独立的 V2 artifact/workspace 根目录；
2. 用本证据包的 SHA-256 清单核对每一份复用 SARIF；
3. 对不变的 SARIF 与不变的 RocketMQ 快照运行 EviTriage；
4. 用新 run ID 保存 V2 的模型输入、输出、策略决策、日志与报告；
5. 将自动标签与 `alert-triage.jsonl` 比较，但继续把后者称为“人工复核基线”，不能包装成无争议的绝对真值。

V1 实验没有修改目标源码、伪造 SARIF、放宽判定策略，也没有创建 GitHub Issue 或上游 PR。
