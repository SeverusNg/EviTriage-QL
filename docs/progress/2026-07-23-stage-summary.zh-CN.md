# EviTriage-QL 阶段工作总结

[English](2026-07-23-stage-summary.md) | [简体中文](2026-07-23-stage-summary.zh-CN.md)

**汇报日期：** 2026 年 7 月 23 日  
**可执行性复核：** 2026 年 7 月 24 日  
**汇报主题：** Ubuntu 服务器与 Windows WSL2 双环境实验进展

> 本文是带证据边界的阶段性交接，不是当前能力的替代规范。判断可用功能时，
> 以 CLI、严格 schema、测试、[README](../../README.zh-CN.md)和
> [已知限制](../../KNOWN_LIMITATIONS.zh-CN.md)为准。

## 零、可执行性结论

**总体结论：有条件可执行。** 离线验收、发布闭包校验和固定夹具上的真实
CodeQL 扫描均有明确命令；DeepSeek 和双主机实验仍依赖外部环境、操作者授权
及尚未补齐的计量/自动化工作。

| 范围 | 判断 | 前提或缺口 |
| --- | --- | --- |
| 离线质量门禁和六案例 Replay | 可直接执行 | 依赖已同步；`make demo` 不需要网络或 API Key |
| 本机历史工件复核 | 当前复核主机可执行，但不可移植 | `artifacts/` 和 `dist/` 被 Git 忽略，其他 clone 不会得到这些文件 |
| 固定 Java 夹具真实 CodeQL 扫描 | 有条件可执行 | CodeQL 2.26.1、JDK 17、Maven 3.9.9 离线缓存；会执行可信夹具的构建代码 |
| DeepSeek `triage --scan` | 仅显式授权后执行 | 会上传有界源码/证据并产生网络请求和费用；必须使用仓库外安全凭据 |
| 双主机严格 clean-room 复现 | 尚未形成单命令流程 | 缺统一脚本、同一输入包和两端机器可读结果汇总 |
| token、成本和时延统计 | 仅时延可从时间戳推导 | 当前 invocation schema 不保存 provider token usage 或成本；正式实验前要先实现计量 |
| 公开数据集与消融实验 | 目前是研究计划，不是可运行入口 | 缺冻结数据集、许可/来源清单、标签协议、实验配置和汇总器 |

本次复核作了以下修正：

- 将文档迁入 `docs/progress/`，补齐中英文版本和语言切换；
- 修复原先多写一层 `EviTriage-QL/` 的相对链接；
- 把已检入的发布/进度证据与本机 Git 忽略工件分开；
- 为离线验收、真实扫描和获准的远程全链路补充命令、风险和验收条件；
- 明确“重复三次并统计 token/成本”在增加计量字段前不能完整执行。

## 一、项目目标

EviTriage-QL 面向 CodeQL 静态分析告警的二次研判。系统保留 CodeQL 提供的
source-to-sink 路径，在此基础上提取有限源码上下文和可定位证据，再由
Analyst、Rebuttal、Judge 三个角色依次进行分析、反证和裁决，最终输出：

- `TP`：证据支持真实漏洞；
- `FP`：存在决定性反证；
- `NMC`（Needs More Context）：证据不足，暂不强制二分类。

项目的重点不是让大模型重新扫描整个仓库，而是建立“告警—路径—源码切片—
证据—结论”之间可追溯、可复现的关系。所有结论均受确定性策略约束，系统
不会自动关闭原始 CodeQL 告警。

## 二、目前完成的技术工作

目前已形成 `v0.2.0` 可运行原型，核心流程为：

```text
本地 Java 项目 / 既有 SARIF
→ CodeQL 扫描或 SARIF 导入
→ SARIF 2.1.0 规范化
→ 有界路径/词法函数上下文提取
→ Evidence Registry
→ Analyst / Rebuttal / Judge
→ TP / FP / NMC 策略
→ JSONL、HTML 报告与运行 manifest
```

阶段性实现包括：

1. 使用 `ProjectSpec`、源码快照和独立运行目录隔离不同实验对象，并记录工具
   版本、配置及产物 SHA-256。
2. 实现真实 CodeQL 扫描与既有 SARIF 导入，两类输入共用同一规范化、上下文
   和证据流水线。
3. 实现严格的三角色 Agent 工作流；每项 Claim 必须引用已注册 Evidence，
   证据冲突或缺失时保守降级为 NMC。
4. 实现离线 Fake/Replay 模型与 DeepSeek V4-Pro/Flash 适配器。远程模型
   必须由项目配置和模型配置双重显式授权。
5. 针对凭据安全实现 environment、TPM2/systemd-creds 和 pass/GPG 三类
   后端；选择后加载失败即终止，不静默回退。
6. 完成 JSONL/HTML 报告、事件日志、运行 manifest、wheel、源码包、依赖
   清单和 CycloneDX SBOM 等发布产物。

## 三、双环境实验结果

| 环境 | 已完成实验 | 主要结果 |
| --- | --- | --- |
| 原生 Ubuntu 服务器 | 工具链部署、真实 CodeQL 扫描、TPM2 凭据、DeepSeek 在线冒烟 | 固定使用 `uv 0.8.3`、Java 17.0.19、CodeQL 2.26.1。Socket 型 CWE-22 实例产生 1 条 `java/path-injection` 告警和完整 8 步路径。DeepSeek V4-Pro 的 Analyst/Rebuttal/Judge 三次调用全部成功，约 31.9 秒完成，最终保守输出 NMC，且 `auto_dismiss=false`。详细命令、run ID 和解释边界已检入交付日志。 |
| Windows WSL2（Ubuntu 22.04） | 真实 CodeQL 扫描、离线 Replay、v0.2.0 发布验证、DeepSeek 在线冒烟 | 项目环境为 Python 3.12.11、`uv 0.8.3`、Java 17.0.19、CodeQL 2.26.1。真实扫描约 29 秒，得到 4 条结果：2 条路径注入、1 条命令行注入、1 条相对路径命令告警；形成 3 条路径、4 个完整上下文和 11 项证据，并到达 `CONTEXT_READY`。这些明细由本机 Git 忽略工件支持，不是可移植的仓库证据。 |

WSL 侧还完成了以下验证：

- 六案例离线 Replay 在当前工作区保留 7 次运行，均得到同一分析身份
  `analysis-de8e383c…` 和一致的 `3 TP / 2 FP / 1 NMC` 分布；每次包含
  18 次固定响应调用。该结果说明离线工作流具有稳定性，但案例标签和 Replay
  响应是合成测试数据，不代表真实模型准确率。
- `v0.2.0` 发布摘要记录全量测试 249/249 通过、分支覆盖率 83.75%，安全
  专项测试 41 项通过。本次复核又对本机 `dist/release/0.2.0/SHA256SUMS`
  的 13 个条目执行 `sha256sum --check`，全部通过；该目录仍是 Git 忽略
  工件。
- DeepSeek 在线实验第一次因 HTTP 401 在 Analyst 阶段以 `MODEL_FAILED`
  终止，错误被审计且没有静默回退；修正凭据后，第二次实验约 31.3 秒完成
  三角色调用，三次响应均通过结构化校验，最终输出 NMC 并生成 JSONL/HTML
  报告。该次运行使用既有合成 SARIF，`real_codeql=false`，并非真实扫描后
  的漏洞结论。

两套环境对同一六案例 Java 工程的真实 CodeQL 扫描均得到 4 条查询结果，
说明关键扫描和证据提取链路已具备跨环境一致性。由于两侧尚未按完全相同的
clean-room 协议重装并执行全部命令，因此目前更准确的表述是“完成了双环境
关键链路验证”，还不能声称完成了严格的第二主机全量复现。

## 四、阶段性认识

1. 当前原型已经把蓝图中的 `v0.1` 最小范围落实为可执行纵向闭环，核心优势
   是证据约束、保守三分类和全链路审计，而不是模型自报置信度。
2. 两次真实模型冒烟均保守输出 NMC；其中 WSL 运行显示，虽然存在危险 sink
   和数据流路径，但入口可控性与实际可利用性证据不足，因此没有直接判为
   TP。这只是合成输入上的一次模型行为观察。
3. Ubuntu 服务器与 WSL 的主要差异集中在凭据和基础环境。服务器可使用
   TPM2/systemd-creds；WSL 通常需要单进程环境变量或另行安装 pass/GPG。
   WSL 的裸 `python3` 为 3.11，因此必须通过 `uv run` 或项目虚拟环境使用
   Python 3.12。

## 五、当前限制

- 当前六案例属于合成微型基准，尚未形成公开项目上的人工标注数据集，也
  不能据此计算模型准确率或泛化能力。
- 已记录的真实 CodeQL 扫描停在 `CONTEXT_READY`；已记录的 DeepSeek 在线
  实验使用既有 SARIF。尚未保存一次“真实扫描 → 真实模型 → JUDGED”的
  验收工件。
- 尚未开展 CodeQL-only、单次 LLM、单 Agent、三 Agent 等正式对照和消融
  实验。
- 当前实现没有持久化 provider token usage、计费价格快照或实验成本，不能
  从现有 invocation 记录可靠计算 token 与费用。
- 当前 Java 上下文提取以有界窗口和词法 callable 边界为主；动态验证、
  置信度校准、跨项目/跨时间评测仍待实现。
- `artifacts/` 与 `dist/` 中的本机证据不进入 Git。跨主机复现必须显式打包、
  哈希、传输并独立验证，不能依赖本文中的本地路径。

## 六、下一阶段的可执行计划

所有命令均从仓库根目录执行。不要把真实 API Key 写入聊天、命令参数、
YAML、`.env`、脚本、日志、Git 或运行工件。

### 6.1 建立每台主机的离线基线

```bash
uv sync --all-extras
make check
make security-test
make demo
uv run --offline evitriage doctor --json
make release-artifacts
make release-verify
```

验收条件：

- 每条命令记录主机、commit、开始/结束时间、退出码和机器可读摘要；
- `make demo` 到达 `JUDGED`，输出 `TP=3 / FP=2 / NMC=1`，所有
  `auto_dismiss=false`；
- 记录 Python、uv、Java/Javac、CodeQL 和 Maven 身份；
- 两端独立执行 `make release-verify`，不得把一端的成功代替另一端；
- 首次 `uv sync` 可能下载锁定依赖；“离线复现”只从依赖和工具已经准备完成
  后开始计算。

### 6.2 在固定六案例夹具上复现真实 CodeQL

真实扫描会以当前宿主用户执行夹具的 Maven Wrapper。只扫描可信源码；对
第三方目标必须先提供 VM、容器或独立账号级隔离。

```bash
codeql version --format=terse
java -version
javac -version

uv run --offline evitriage project validate \
  --config configs/projects/gate-e-demo.yaml \
  --json

uv run --offline evitriage scan \
  --project-config configs/projects/gate-e-demo.yaml \
  --json
```

验收条件：退出码为 0、`real_codeql=true`、终态为 `CONTEXT_READY`；在固定
源码/查询/工具版本下预期 4 条结果和 3 条路径。若数量或哈希变化，应保存并
解释差异，不得修改摘要来强行匹配旧结果。

### 6.3 完成获准的真实扫描到 DeepSeek 全链路

执行前必须：

1. 由操作者明确批准目标源码/证据上传、提供方条款和预计费用；
2. 通过[部署指南](../deployment-guide.zh-CN.md#9-可选-deepseek-远程研判)
   在仓库外配置凭据，并用 `credentials status --json` 只检查非秘密状态；
3. 先实现并测试非秘密计量字段（至少单角色时延、provider token usage、
   定价快照 ID 和失败类别），否则只能报告总时延，不能声称完成 token/成本
   实验。

以一次性环境凭据为例，获准后执行：

```bash
uv run --offline evitriage doctor --json
uv run evitriage credentials status --json

uv run evitriage triage \
  --project-config configs/projects/example-local-deepseek-v4.yaml \
  --scan \
  --llm-profile configs/llm/deepseek-v4-pro.yaml \
  --credential-provider environment \
  --json
```

验收条件：`real_codeql=true`、终态 `JUDGED`、Analyst/Rebuttal/Judge 三次
调用均为 accepted、报告存在且 `auto_dismiss=false`。独立重复至少 3 次，
保存失败 run，不静默重试或回退。该实验验证管线和模型行为，不提供准确率
结论。

### 6.4 数据集与消融实验的启动门

这部分尚无可直接执行的仓库命令。开始运行前至少要提交：

- 带许可证和来源哈希的冻结数据清单；
- 人工标签规范、双人复核/分歧处理流程；
- project-disjoint 与 chronological split 清单；
- CodeQL-only、固定窗口单次 LLM、路径切片单次 LLM、三角色 Agent 的
  版本化配置；
- Precision、Recall、F1、FP reduction、NMC rate、coverage-risk、时延和
  成本的机器可读汇总器。

## 七、核验材料

### 可随 Git 获取

- [v0.1 交付证据日志](2026-07-27-v0.1.md)
- [v0.2.0 发布说明](../releases/v0.2.0.md)
- [复现指南](../reproducibility.md)
- [部署指南](../deployment-guide.zh-CN.md)

### 当前复核主机上的 Git 忽略工件

以下路径可用于本机审计，但不会随 clone 或 GitHub 页面提供：

```text
artifacts/runs/20260723T070306673935Z-e8922e9b1b7b/run-manifest.json
artifacts/runs/20260723T152521860604Z-348f900c340c/metadata/error.json
artifacts/runs/20260723T152652636073Z-0c072858d1d1/run-manifest.json
dist/release/0.2.0/
```

本机发布闭包复验命令：

```bash
(cd dist/release/0.2.0 && sha256sum --check SHA256SUMS)
```
