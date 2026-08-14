# 资源泄露研判与 existing-SARIF 批处理指南

[English](resource-leak-triage.md) | [简体中文](resource-leak-triage.zh-CN.md)

## 范围

资源泄露路径接收以下精确 SARIF rule ID 的归一化 occurrence：

- `java/input-resource-leak`
- `java/output-resource-leak`
- `java/database-resource-leak`
- `java/unreleased-lock`

分类只使用 `rule_id`，绝不解析 message 或文件名。其他 rule 继续使用 legacy
security 工作流、schema、Prompt、policy 和 canonical Replay 身份。

## 证据与模型契约

对每条 occurrence，受限 Java 提取器会在安全解析成功时注册完整 enclosing
method、获取/释放与控制流词法候选、`try`/`catch`/`finally`/TWR 结构，以及
受限的同文件一跳 callee。每段摘录都绑定 provenance，并作为
`untrusted_code_data` 发送；仓库注释不能授予指令或工具。词法候选是观察，
不是已经验证的 Java 语义。

版本化 `resource-leak-1.0` 顺序如下：

1. Analyst 建立最强的证据绑定获取与可行未释放路径，不直接选择最终标签。
2. Rebuttal 检查同一资源释放覆盖、所有权转移、callee 关闭行为、生命周期
   契约、别名与路径可行性。
3. Judge 只能使用已注册证据和物化 claims 提出 TP/FP/NMC 候选。
4. 确定性策略仅在获取成功且存在可行未释放退出时接受 TP；仅在全路径释放
   覆盖或已证明的所有权/callee/生命周期契约存在时接受 FP；其他情况为 NMC。

每个角色最多一次 schema repair。无效响应、Replay 条目耗尽、认证错误或传输
失败都是运行失败，不是 NMC。`auto_dismiss` 始终为 `false`。

## Manifest 与 preflight

`existing-sarif-experiment-manifest` 绑定实验及每个 case：

- 实验 ID、LLM Profile、分离的聚合/run artifact 根和 workspace 根；
- case ID、源码根与精确 commit、SARIF 路径与 SHA-256、预期计数与查询族、
  `triage` 或 `audit_only`、ProjectSpec；
- 可选历史目标和延后基线路径。

私有绝对路径只能放入被忽略的 `private-*.yaml`。下列命令不会加载 LLM Profile
或凭据：

```bash
cd /path/to/EviTriage-QL
uv run evitriage experiment preflight \
  --manifest configs/projects/private-resource-experiment.yaml \
  --json

uv run evitriage experiment run \
  --manifest configs/projects/private-resource-experiment.yaml \
  --dry-run \
  --json
```

全局 preflight 会在访问模型或凭据前拒绝任何 source commit/dirty 状态、SARIF
SHA/计数/查询族、ProjectSpec source 或 workspace/artifact 根不一致。audit-only
完整 suite 只计数，绝不会送入模型。零结果 triage case 仍是完整 run，拥有空
decision artifact，模型调用数为零。

## 离线 Replay 与获授权的远程执行

确定性离线运行使用可信只读 cache：

```bash
uv run evitriage experiment run \
  --manifest configs/projects/private-resource-replay.yaml \
  --replay-cache /trusted/read-only/resource-replay \
  --json
```

远程 DeepSeek 必须显式启用，ProjectSpec 与 LLM Profile 都要允许。凭据必须在
Git 外配置；绝不能把 Key 放入 manifest、YAML、命令参数、`.env`、日志或产物。
WSL 的首选持久方案是 pass/GPG。实验运行器顺序调用；网络错误、429 和 5xx
采用有限瞬时重试，401/403 永不重试。

## 输出与失败语义

每个 triage case 都在 `run_artifact_root` 下获得独立普通 run。全部 case 完成后，
`artifact_root` 包含：

```text
preflight.json
batch-manifest.resolved.json
summary.json
automatic-decisions.jsonl
historical-comparison.json
report.md
report.zh-CN.md
report.html
execution-summary.redacted.json
SHA256SUMS
runs/<run-id>/...
```

失败 case 保持 `failed` 和结构化错误码；成功 sibling 的决策仍被聚合，但实验
状态为 `incomplete`。模型失败绝不转换为 NMC。聚合文件禁止覆盖、带 checksum
索引，并设为 owner-read-only。

## 盲评基线评估

只有全部自动决策和报告固化后才能评估：

```bash
uv run evitriage experiment evaluate \
  --manifest configs/projects/private-resource-experiment.yaml \
  --json
```

命令先要求自动 JSONL 只读，之后才打开基线，并且只按
`(raw SARIF SHA-256, run_index, result_index)` 连接。文件名、message 和预期标签
都不是匹配键。输出包含三分类计数/confusion/precision/recall/F1、agreement、
determined/NMC rate 及未匹配行。该基线是人工证据复核，不是独立验证的绝对
ground truth；开发者事先接触过案例，因此比较属于工程评估，不是无偏基准。

## 解释边界

提取器有意不是 Java 编译器或完整 CFG/别名/所有权分析。未知第三方代码、动态
分派、生成源码、自定义锁/租约、截断方法或冲突证据必须保持可见，并通常强制
NMC。模型置信度不能覆盖这些缺口。参见[已知限制](../KNOWN_LIMITATIONS.zh-CN.md)。
