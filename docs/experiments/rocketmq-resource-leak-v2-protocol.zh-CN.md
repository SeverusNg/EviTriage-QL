# Apache RocketMQ 资源泄露 V2 实验协议

[English](rocketmq-resource-leak-v2-protocol.md) | [简体中文](rocketmq-resource-leak-v2-protocol.zh-CN.md)

**协议日期：** 2026-08-14  
**状态：** 已完成经授权的真实 DeepSeek batch 和固化后 V1 比较

## 目标与盲评边界

V2 使用资源专用 Analyst、Rebuttal、Judge 和确定性 TP/FP/NMC 策略，自动研判
CodeQL input/output/database/lock 资源告警。人工 evidence supplement 或标签绝不
进入模型请求或决策。

V1 `alert-triage.jsonl` 是人工证据复核，不是独立验证的绝对 ground truth。
只有全部 V2 自动决策和报告成为 owner-read-only 后，`experiment evaluate` 才能
打开它；对齐只使用 `(raw SARIF SHA-256, run_index, result_index)`。开发者已接触
V1，故最终比较是工程比较，不是无偏基准。

## 冻结源码身份

| 版本 | Commit |
| --- | --- |
| 历史修复前 | `04711367b7378115ed0c8e656aea88dab2a050da` |
| 历史修复 | `a6c5604b6cb6fce255fe9e0e6e860f94d37c2050` |
| V1 当前版本 | `e3458616d207ee636b1762f0f8dcf788a590d59d` |

任何模型或凭据访问前，三个 worktree 必须匹配 commit 且为 clean。历史目标是
`java/unreleased-lock`，文件
`client/src/main/java/org/apache/rocketmq/client/impl/factory/MQClientInstance.java`，
方法 `sendHeartbeatToBroker`。

## 冻结 SARIF 身份

| 文件 | SHA-256 | 模式 / 数量 |
| --- | --- | --- |
| `pre-unreleased-lock.sarif` | `b226de0d01f682c38f37335a55f6496ec8902a8530d784b5772fac1864b2069e` | triage / 6 |
| `post-unreleased-lock.sarif` | `a10bd1d24be5046d11683be74d7cd11abb187e5e4b098d709dbf75dd7c683193` | triage / 5 |
| `pre-security-and-quality.sarif` | `a42993f6a345ea67a3529972e9bba19a5dc262cbee75ddb6a6d18657728546ec` | audit / 680 |
| `post-security-and-quality.sarif` | `69be7987a11fe7aad703673f736b321a5385280b7c8b51c9370e090eb57c3446` | audit / 679 |
| `current-input.sarif` | `5d899cf425a0b2713426d3e685fcb12881c8cd94ade1c1c4fe3ce7832ebd8788` | triage / 3 |
| `current-output.sarif` | `3604c6c1c7d13316caa1a09f290b8957f0a041265bf5e6e6cbd05f355238b7f8` | triage / 1 |
| `current-database.sarif` | `5b8ad61ccc5fb911cb637b551d5197ea2518df73a817e2a7995c1b81c98c1908` | triage / 0 |
| `current-lock.sarif` | `9601a9b7a6304cecb26fe6f119d8c8b8fec5f54684d05d564756eb150e0bb493` | triage / 22 |
| `current-security-and-quality.sarif` | `6b1b74611978ecf919d5dafb3242c8300134e9940dfaab1442a11c4464a7d79b` | audit / 1939 |

原始字节绝不改写或拆分；每条 occurrence 保留 SARIF SHA-256、run index、result
index。完整 suite 仅用于 audit：验证数量和历史消失，不进入模型。

实际研判共 37 条：历史 pre 6、历史 post 5、当前 26（input 3、output 1、
database 0、lock 22）。每条正常 3 次、每角色最多一次 repair，因此完整实验为
111–222 次调用；独立 smoke 为 3–6 次。

## 离线验收

在仓库根运行：

```bash
uv run evitriage experiment preflight \
  --manifest configs/projects/private-rocketmq-resource-leak-v2-manifest.yaml \
  --json
uv run evitriage experiment run \
  --manifest configs/projects/private-rocketmq-resource-leak-v2-manifest.yaml \
  --dry-run \
  --json
```

私有 manifest 和三个 ProjectSpec 被 Git 忽略，不得提交主机绝对路径。实验有意
使用 existing SARIF：RocketMQ 没有已检入 Maven Wrapper，因此不得让
EviTriage `--scan` 绕过 wrapper-only 边界。离线验收还要求
`uv sync --all-extras`、`make check`、`make security-test`、`make demo`、doctor、
四份 ProjectSpec validate、ingest smoke、资源专项测试、Replay 端到端和
`git diff --check`。

## 强制授权边界

全部离线检查通过后，必须在加载凭据或第一次连接 DeepSeek 前停止。WSL 首选
持久凭据方案是 pass/GPG：

```bash
pass init <operator-GPG-key-id>
uv run evitriage credentials set-deepseek --provider pass
uv run evitriage credentials status --json
```

操作员只能在自己的 WSL 终端通过隐藏双重提示输入 Key。绝不能把 Key 放入
聊天、YAML、`.env`、参数、日志、产物或 Git；一次性环境变量未必传递给代理
的独立进程。

## 授权后执行与输出

明确授权后先检查非秘密凭据状态，再执行 3–6 次调用的合成 smoke，检查脱敏和
产物，最后顺序运行 111–222 次完整批次。401/403 不重试；429、5xx 和瞬时网络
失败只有有限重试。任何 case 失败都会使实验 incomplete，直到成功重跑。

隔离的 V2 聚合根包含 `preflight.json`、resolved manifest、逐 run 目录、
`automatic-decisions.jsonl`、`historical-comparison.json`、summary、中英 Markdown、
转义 HTML、脱敏 execution summary 和 `SHA256SUMS`。只有这些固化后，
`experiment evaluate` 才可创建 `evaluation-v1-baseline.json` 并更新校验索引。

历史报告必须区分两件事：修复前目标有模型/策略决策，修复后对应 CodeQL
occurrence 已消失；“消失”不是模型判 FP。完整 suite 为 680→679。当前评估把
26 个自动决策与 V1 5 TP / 18 FP / 3 NMC 复核逐条比较，报告匹配、不匹配、NMC
和对齐缺口，但不把 agreement 称为“准确率”。


## 2026-08-14 实际执行结果

第一次资源 batch 正确保持 `incomplete`：五个非空 case 在允许的一次 Analyst
repair 后失败，因为非空证据引用未显式进入 JSON Schema。JDBC 零结果正常完成，
失败 run 保留脱敏调用元数据。Resource Schema 1.0 用 `minItems: 1` 收紧；34 个
focused test、`make check`、`make security-test` 通过，单条 RocketMQ 资源 smoke
以三次 accepted 调用完成。

成功聚合根为 `artifacts/rocketmq-resource-leak-20260812-v2/attempt-2`。37 条全部
完成，共 111 次 accepted、零 repair、零失败。Judge 候选为 25 FP / 1 TP /
11 NMC；19 条有 unknown/unresolved obligation、7 条资源 context 不完整、11 条
本身为 Judge NMC，因此策略最终输出 37 NMC。历史目标修复前为 NMC，修复后
occurrence 消失；专项计数 6→5，完整 suite 680→679。

只有自动决策 owner-read-only 后评估才打开 V1。26 条当前告警全部对齐：V1 为
5 TP / 18 FP / 3 NMC，V2 为 0 / 0 / 26，一致 3/26（11.54%），determined rate
0%，NMC rate 100%。11 条历史告警按设计没有 V1 行。这是保守闭环的工程证据，
不是无偏准确率。
