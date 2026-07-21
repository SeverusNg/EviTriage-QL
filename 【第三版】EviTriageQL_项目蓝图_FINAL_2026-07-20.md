# EviTriage-QL 最终项目蓝图

**文档版本**：Final 1.0（2026-07-20，Asia/Tokyo）  
**项目全称**：EviTriage-QL：基于 CodeQL 路径证据与大模型 Agent 的可审计漏洞告警二次筛选系统  
**英文题目**：EviTriage-QL: Evidence-Grounded LLM-Agent Triage for CodeQL Alerts  
**项目类型**：软件工程 / 程序分析 / 大模型系统 / 软件安全交叉科研项目  
**首个工程节点**：2026-07-27 发布 `v0.1.0` 可运行纵向闭环  
**科研 PoC 节点**：2026-10-12 前形成可复现实验与论文初稿  
**首发语言**：Java；Kotlin、Python、JavaScript/TypeScript 后续扩展  
**首发 CWE**：CWE-22、CWE-78；随后加入 CWE-89、CWE-79；CWE-918 作为路径可行性扩展案例  
**参考工具链锁定**：Python `3.12`、uv `0.8.3`、CodeQL CLI `2.26.1`；具体 CLI/query pack/model pack 版本必须进入每次运行的 manifest

> 本文档中的“目标软件”不是写死在系统中的某一个项目。系统通过 `ProjectSpec` 接收本地目录、固定 Git commit、数据集样本或既有 SARIF；正式科研实验则冻结项目、commit、构建环境和工具版本，以保证可复现。

> **工程环境持久性要求**：Gate 与发布验收依赖的工具必须安装在持久化的用户级或系统级目录，并能在全新 login shell 的 `PATH` 中发现。`/tmp` 或其他自动清理目录中的 bootstrap 只能用于临时解阻，不能作为已部署、clean-room 复现或交付证据。工具安装必须记录来源、固定版本、完整性校验、安装路径、验证命令和真实退出码；升级必须同步更新版本门禁、锁文件验证、文档与进度证据。

---

## 1. 一句话定位

CodeQL 负责高召回地发现候选漏洞并提供 source-to-sink 路径骨架；LLM Agent 不重新“扫描整仓”，而是围绕每条 CodeQL 告警构建证据、寻找反证、请求补充上下文，并输出：

- `True Positive`：存在足够证据支持真实漏洞；
- `False Positive`：存在决定性反证支持误报；
- `Needs More Context`：证据不足，不得强行二分类。

系统的核心不是“让模型看更多代码”，而是建立一条可复现、可校准、可审计的告警判真证据链。

---

## 2. 研究问题、假设与边界

### 2.1 正式任务定义

给定：

- 仓库快照 `R@commit`；
- 固定版本的 CodeQL CLI、query packs 与 model packs；
- CodeQL 输出的 SARIF 告警及 `codeFlows`；
- 从仓库中按需提取的程序切片、配置、测试和框架上下文；

输出：

```text
label ∈ {TP, FP, NMC}
calibrated_confidence
structured_evidence_graph
reasoning_summary
unknowns
recommended_next_actions
optional_fix_guidance
```

### 2.2 推荐研究问题

- **RQ1：有效性**——证据约束的 LLM Agent 是否能在保持 CodeQL 真阳性召回的前提下，显著减少误报？
- **RQ2：上下文**——固定代码窗口、CodeQL 路径切片、分级自适应切片，哪种上下文策略最有效？
- **RQ3：Agent 架构**——单次 LLM、单 Agent 工具调用、分析/反证/裁决三角色，哪种组合提供最佳精度—成本平衡？
- **RQ4：不确定性**——允许 `Needs More Context` 并进行置信度校准，是否能降低高风险误判？
- **RQ5：选择性验证**——仅对高风险或低置信告警执行测试生成/沙箱验证，能否用较小额外成本提升判真质量？
- **RQ6：泛化**——方案能否跨项目、跨时间、跨 CWE 泛化，而非记忆公开 CVE 或相似代码？

### 2.3 可检验假设

- H1：路径切片比“告警点附近固定 N 行代码”具有更高的告警级 F1 和更低 token 成本。
- H2：反证 Agent 能显著降低“把 CodeQL 描述复述成 TP 结论”的偏差。
- H3：三分类选择性预测在相同自动化覆盖率下，比强制二分类具有更低的 false-negative risk。
- H4：基于证据覆盖、Agent 分歧和验证结果训练的校准器，比模型自报 confidence 更可靠。
- H5：选择性验证能提升高危/低置信样本的准确率，同时避免对全部告警执行昂贵动态分析。

### 2.4 明确非目标

第一篇工作不应同时承担以下目标：

- 不训练一个新的基础大模型；
- 不让 LLM 替代 CodeQL 的仓库级数据流分析；
- 不承诺自动关闭 GitHub Code Scanning 原始告警；
- 不自动攻击真实在线服务；
- 不一次覆盖所有语言、框架和 CWE；
- 不把修复生成作为主贡献；修复建议仅是附属输出；
- 不把 CVE 描述、修复补丁或 PoV 直接泄露给主实验中的判真 Agent。

---

## 3. 你已有背景与本项目知识的对应关系

你做过编译优化和大模型系统迁移，这对本项目非常有帮助。

| 你熟悉的概念 | 本项目中的对应物 |
|---|---|
| 编译器 IR | CodeQL database 中的 AST、类型、控制流、调用和数据流事实 |
| 数据流分析 | taint propagation：不可信数据如何从 source 流向 sink |
| transfer function / kill-gen | sanitizer、guard、编码与验证逻辑对污点的阻断或转换 |
| CFG / call graph | 路径可达性、跨过程 source-to-sink 链路 |
| context sensitivity | 同一函数在不同调用上下文中的不同安全语义 |
| program slicing | 为每条告警提取“最小充分上下文” |
| 保守静态分析 | 为避免漏报而过近似，因此天然产生误报 |
| 优化 pass pipeline | 扫描、归一化、切片、Agent、验证、裁决的状态机流水线 |
| 系统迁移的兼容层 | LLM provider adapter、CodeQL 版本适配、数据 schema 版本化 |

最关键的新知识不是“怎么让 LLM 读代码”，而是：如何定义安全告警的测试 oracle、如何获得可信标签、如何控制漏报、如何保证开源项目能被稳定构建和复现。

---

## 4. 软件测试与软件安全的必要入门

### 4.1 普通软件测试

- **单元测试**：验证一个函数或模块；本项目用于 SARIF 解析、切片、状态机、评分器。
- **集成测试**：验证多个模块协作；例如 CodeQL 扫描结果能否被解析并送入 Agent。
- **端到端测试**：从仓库输入到最终报告完整执行。
- **回归测试**：代码修改后确保已有行为没有退化；CodeQL 自定义 query 也必须有 query test。
- **测试 oracle**：决定“正确结果是什么”的依据。安全告警判真中，这是最难、最昂贵的部分。
- **fixture / golden file**：固定输入和预期输出；适合 SARIF、切片、Agent 结构化输出。
- **flaky test**：结果不稳定的测试；LLM 调用天然具有波动，需要 replay、缓存和多次重复实验。

### 4.2 软件安全测试

- **SAST**：不运行目标程序，分析源代码/中间表示。CodeQL 属于这一类。
- **DAST**：把目标作为运行中的黑盒，从外部发请求观察漏洞。
- **IAST**：运行程序时结合内部插桩观察数据流。
- **Fuzzing**：大量生成或变异输入寻找崩溃/异常行为。
- **SCA**：分析第三方依赖和已知漏洞，不等于源代码漏洞检测。
- **Symbolic Execution**：用符号值探索路径条件，精确但成本高。

本项目的基本组合是：SAST 粗筛 + LLM 证据判真 + 少量动态/符号验证。

### 4.3 安全术语

- **CWE**：弱点类型，例如路径遍历、命令注入；是“问题类别”。
- **CVE**：某个具体产品/版本中的已公开漏洞；是“漏洞实例”。
- **CVSS**：漏洞严重度评分，不是漏洞真实性评分。
- **Source**：攻击者可控或不可信数据的入口。
- **Sink**：危险操作，例如命令执行、SQL 执行、文件读取。
- **Sanitizer**：在特定上下文中有效的清洗或校验逻辑。
- **TP / FP / FN / TN**：真阳性、假阳性、假阴性、真阴性。

在安全场景中，减少 FP 很重要，但错误地把 TP 判成 FP 通常更危险。因此系统必须允许 abstention，也就是 `Needs More Context`。

---

## 5. 开源软件科研的必要知识

### 5.1 系统目标可替换，实验对象必须冻结

系统不是针对某一个固定软件编写。目标软件由 `ProjectSpec` 注入，主程序不得出现特定仓库名、绝对路径、构建命令或漏洞标签的硬编码。一次运行可以面向：

- 本地源码目录；
- 固定 Git URL + 完整 commit SHA；
- 数据集 adapter 返回的样本；
- 已有 SARIF + 与之匹配的源码快照。

但正式实验对象必须由以下信息唯一定位：

```text
repository URL/local snapshot digest
+ full commit SHA/dirty patch digest
+ submodule state
+ build toolchain and command
+ dependency state
+ CodeQL CLI/query pack/model pack versions
+ ProjectSpec/config/prompt/schema digests
```

因此要同时遵守两条原则：

1. **架构可扩展**：换软件只新增或替换 `configs/projects/<project_id>.yaml`，不修改核心代码；
2. **实验可复现**：论文中的每个项目和版本必须固定，不能只写“在某开源项目上测试”。

### 5.2 构建系统

Java 项目常见 Maven、Gradle 和各自 wrapper。历史漏洞项目可能依赖 JDK 8/11/17/21、旧插件、停用仓库或本地生成代码。因此要为每个样本保存 `build_manifest.yaml`，记录：

- JDK 与发行版；
- 构建命令；
- Maven/Gradle 版本；
- 环境变量；
- 是否允许网络下载依赖；
- 构建超时；
- 已知补丁或镜像源调整；
- 成功构建日志摘要。

### 5.3 许可证与合规

- 只把有明确许可证的仓库纳入公开发布数据集；
- 记录仓库许可证、数据集许可证和依赖许可证；
- 不把“代码可访问”误认为“可任意重新分发”；
- 公布数据时优先保存 commit、定位信息和生成脚本，而不是重新打包全部源码；
- 为项目本身生成 SPDX/CycloneDX SBOM，并保存依赖清单。

### 5.4 负责任披露

若在当前版本开源项目中发现疑似新漏洞：

1. 不直接在论文、Issue 或公开日志中泄露利用细节；
2. 私下联系维护者或安全响应渠道；
3. 保存发现时间、版本、证据、沟通记录；
4. 等待修复或协调披露后再公开。

---

## 6. 总体系统架构

```text
┌──────────────────────────────────────────────────────────────┐
│                       Experiment Control                      │
│ ProjectSpec / version pin / seeds / manifest / replay cache │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ 1. Project, Workspace, Repository & Build Plane              │
│ ProjectSpec → snapshot → isolated build → CodeQL DB → SARIF  │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ 2. Evidence Extraction Plane                                 │
│ SARIF normalize → paths → AST/function ranges → adaptive     │
│ slice → config/test/framework context → evidence registry    │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ 3. Reasoning Plane                                            │
│ Analyst Agent → Rebuttal Agent → Judge Agent                 │
│ all claims must reference immutable evidence IDs             │
└──────────────────────────────┬───────────────────────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ deterministic policy   │
                  │ confidence/calibration │
                  └───────┬────────┬───────┘
                          │        │
                  high confidence  uncertain/high risk
                          │        │
                          │  ┌─────▼──────────────────────────┐
                          │  │ 4. Selective Verification      │
                          │  │ tests / harness / constraints  │
                          │  │ sandbox, no external network   │
                          │  └────────────┬───────────────────┘
                          │               │
┌─────────────────────────▼───────────────▼────────────────────┐
│ 5. Decision & Publication Plane                              │
│ TP / FP / NMC + evidence graph + report + human review       │
│ JSON/HTML/CSV + optional GitHub PR note; never auto-dismiss  │
└──────────────────────────────────────────────────────────────┘
```

---

## 7. 模块职责与推荐技术栈

### 7.1 技术栈

- **主语言**：Python 3.12；类型检查与研究编排更方便。
- **包管理**：`pyproject.toml` + `uv.lock`。
- **CLI**：Typer。
- **schema**：Pydantic v2 + JSON Schema。
- **数据库**：SQLite 用于单机复现实验；PostgreSQL 用于团队/平台模式。
- **迁移**：SQLAlchemy + Alembic。
- **AST/函数边界**：Tree-sitter；高阶调用图/数据流事实优先由 CodeQL helper queries 提供。
- **报告**：Jinja2 HTML + JSONL/CSV。
- **测试**：pytest、Hypothesis、pytest-cov。
- **静态质量**：Ruff、mypy strict。
- **容器**：Debian/Ubuntu glibc 基础镜像，不使用 Alpine。
- **CodeQL**：配置中固定 CLI、query pack、model pack 版本；参考可复现实验基线使用 `2.26.1`，但所有版本均由 manifest 控制。
- **LLM**：provider-neutral adapter；必须支持 fake/replay client 和严格 JSON Schema 输出。

### 7.2 核心模块

| 模块 | 职责 | 关键输出 |
|---|---|---|
| `project_registry` | 校验/解析 ProjectSpec，目标软件注册与切换 | `ResolvedProjectSpec` |
| `workspace_manager` | 快照、构建副本、CodeQL DB、run 目录与安全清理 | `RunWorkspace` |
| `repo_manager` | local/git/dataset acquisition、commit 校验、submodule、源码快照 | `RepositorySnapshot` |
| `build_adapter` | Maven/Gradle/JDK 环境与构建日志 | `BuildResult` |
| `codeql_runner` | database create/analyze、版本与 pack 固定 | SARIF、日志、DB metadata |
| `sarif_normalizer` | 解析 rules/results/locations/codeFlows/fingerprints | `NormalizedAlert` |
| `path_extractor` | source、sink、步骤、相关位置、路径摘要 | `DataFlowPath` |
| `slice_builder` | 函数级/路径级切片，条件、sanitizer、调用邻域 | `SliceArtifact` |
| `context_resolver` | 配置、权限、框架、测试、依赖摘要 | `ContextBundle` |
| `evidence_registry` | 不可变证据 ID、哈希、来源和定位 | `EvidenceItem[]` |
| `llm_adapter` | Fake/Replay 与真实 HTTP API 的统一结构化调用 | `ModelInvocation` |
| `agent_orchestrator` | 分析、反证、裁决；状态机与重试 | `AgentRun[]` |
| `decision_policy` | schema 校验、证据门控、升级策略 | `ProvisionalDecision` |
| `verifier` | 沙箱内测试/PoV/约束验证 | `VerificationResult` |
| `calibrator` | validation set 上训练校准器 | `CalibratedDecision` |
| `review_service` | 人工标注、冲突仲裁、审计历史 | `HumanLabel` |
| `reporter` | JSONL、CSV、HTML、论文指标 | 报告和实验表格 |
| `github_adapter` | 可选 PR/check 注释 | 并行结论，不关闭原告警 |

### 7.3 不建议在第一版引入的组件

- 大型向量数据库；
- 自由对话式多 Agent 框架；
- 复杂微服务拆分；
- Kafka/Celery 等分布式设施；
- 全仓 embedding；
- 自动修复 PR；
- 自动 dismiss CodeQL 告警。

第一版应是一个可复现的模块化单体，所有模块通过清晰接口解耦。

---

## 8. 状态机设计

两种输入路径在 `NORMALIZED` 前汇合：

```text
CREATED
  → PROJECT_VALIDATED
  → WORKSPACE_READY
  → SOURCE_READY
      ├─ scan branch:
      │    → BUILD_READY → CODEQL_DB_READY → SCANNED
      └─ ingest branch:
           → SARIF_INGESTED
  → NORMALIZED
  → CONTEXT_READY
  → ANALYZED
  → REBUTTED
  → JUDGED
      ├─→ PUBLISHED
      ├─→ REVIEW_REQUIRED
      └─→ ESCALATION_PLANNED
              → VERIFIED
              → REJUDGED
              → PUBLISHED / REVIEW_REQUIRED
```

错误状态：

```text
PROJECT_INVALID
WORKSPACE_FAILED
SOURCE_FAILED
BUILD_FAILED
CODEQL_FAILED
INVALID_SARIF
CONTEXT_INCOMPLETE
MODEL_FAILED
VERIFICATION_FAILED
POLICY_REJECTED
```

每次状态迁移必须写入 append-only event log，包含 ProjectSpec/snapshot identity、输入 hash、输出 hash、工具版本、时间、异常和重试次数。状态机必须支持幂等恢复；`scan` 与 `ingest-sarif` 不得维护两套下游逻辑。

---

## 9. 证据契约：整个项目最重要的设计

### 9.1 EvidenceItem

```json
{
  "evidence_id": "ev_01J...",
  "type": "source_control|data_flow|sink_semantics|guard|sanitizer|config|permission|test|verification|rebuttal",
  "polarity": "supports_tp|supports_fp|neutral",
  "strength": "low|medium|high|decisive",
  "origin": "codeql|repository|build|test|verifier|human",
  "location": {
    "path": "src/main/java/...",
    "start_line": 42,
    "end_line": 47
  },
  "excerpt": "...",
  "artifact_sha256": "...",
  "extractor": "sarif-normalizer@1",
  "summary": "HTTP request parameter is attacker controlled"
}
```

### 9.2 Claim

```json
{
  "claim_id": "cl_01J...",
  "kind": "source_controllable|path_feasible|sanitizer_effective|sink_dangerous|exploit_succeeds",
  "statement": "...",
  "status": "supported|rebutted|unresolved",
  "evidence_ids": ["ev_..."],
  "produced_by": "analyst|rebuttal|judge"
}
```

### 9.3 决策门控规则

- Agent 不能在最终结论中引用不存在的证据 ID；
- 不能把代码注释、README 或变量名中的自然语言当成事实；
- 路径事实只能来自 CodeQL、AST/CFG 工具或验证器；
- 没有明确证据时必须标 `unresolved`；
- FP 必须有至少一个“决定性反证”，不能仅凭“看起来安全”；
- 有高强度 TP 证据和高强度 FP 证据冲突时，必须进入 NMC/人工复核；
- exploit/PoV 成功可作为强 TP 证据，但 PoV 失败不能单独证明 FP；
- 模型自报 confidence 不直接作为最终概率。

---

## 10. Agent 架构

### 10.1 Analyst Agent

目标：构建“为什么这可能是真漏洞”的最强证据链。

固定检查项：

1. CodeQL query 与 CWE 的准确语义；
2. source 是否攻击者可控；
3. source→sink 路径是否完整；
4. guard/path condition 是否允许执行；
5. sanitizer 在当前输出上下文是否有效；
6. sink 是否真实危险；
7. 权限、配置和部署条件；
8. 可行攻击输入；
9. 缺失信息。

### 10.2 Rebuttal Agent

目标：寻找足以推翻 TP 的具体反证，而不是泛泛“质疑”。

候选反证：

- source 实际为常量、可信配置或受强认证限制；
- 路径不可达；
- 路径中的值已被不可逆地约束；
- sanitizer 对当前 sink 上下文确实完备；
- sink 只是日志、模拟或不可执行代码；
- 运行时配置使危险路径不存在；
- CodeQL 模型把 wrapper/summary 建模错误；
- 同一值在传播中被覆盖或重新绑定。

### 10.3 Judge Agent

Judge 只能使用 Analyst、Rebuttal 和 evidence registry 中已有事实，不能自行引入新事实。输出严格 JSON：

```json
{
  "label": "TP|FP|NMC",
  "raw_confidence": 0.0,
  "critical_claim_ids": [],
  "critical_evidence_ids": [],
  "unknowns": [],
  "reasoning_summary": "...",
  "next_actions": [],
  "fix_guidance": []
}
```

### 10.4 为什么不采用自由辩论

多 Agent 的价值应来自“不同结构化任务和不同工件”，而不是多个模型自由聊天。自由辩论难以复现、成本高，而且可能共享同一错误前提。

---

## 11. 上下文构造策略

### 11.1 Level 0：告警元数据

- query ID、CWE、severity、query help；
- primary location；
- SARIF message；
- fingerprint；
- source/sink/path steps。

### 11.2 Level 1：默认路径切片

- 每个 path step 所在完整函数；
- source/sink 所在类和方法签名；
- 路径上的赋值、参数传递、返回值；
- 直接 guard 条件；
- sanitizer 定义；
- 路径前后一层 caller/callee；
- 相关配置键和测试名称。

### 11.3 Level 2：按需扩展

仅在 NMC、unresolved call、unknown sanitizer、动态分派、反射、框架隐式绑定等情况下增加：

- 再上一层入口点；
- overload/override 实现；
- 依赖库模型；
- 框架路由和权限注解；
- 集成测试；
- deployment 配置。

### 11.4 Level 3：验证上下文

- 生成最小测试 harness；
- 运行时依赖；
- 约束和候选 payload；
- 沙箱执行日志。

不得把整个仓库默认放入模型上下文。

---

## 12. 选择性验证

第一版只实现 Java 沙箱测试插件，不把完整符号执行作为必需项。

### 12.1 触发条件

- CodeQL security severity 高；
- Analyst 与 Rebuttal 明显分歧；
- sanitizer 语义不明确；
- 路径跨文件/跨模块且超过阈值；
- NMC 且补充代码上下文无法解决；
- 有现成 PoV/JUnit；
- 该告警被选入论文重点样本。

### 12.2 沙箱要求

- 容器只读挂载源代码；
- 默认禁用外网；
- CPU、内存、进程数和超时限制；
- 非 root 用户；
- 禁止访问宿主 Docker socket；
- 仅执行 allowlist 构建/测试命令；
- 保存 stdout/stderr、退出码和工件 hash；
- 不向真实远程服务发送 payload。

### 12.3 结果解释

- PoV 成功：强 TP 证据；
- PoV 编译失败：验证失败，不改变标签；
- PoV 未触发：可能是 harness 不完整，不能单独作为 FP；
- 证明某 guard 恒为假或 sanitizer 单测覆盖关键编码：可作为强 FP 证据。

---

## 13. 目标软件可替换的目录、工作区与工件架构

### 13.1 设计原则

必须把三类对象严格分开：

1. **EviTriage-QL 自身代码**：版本控制并接受 CI；
2. **待测软件源码/构建副本**：放在 `workspaces/`，默认不提交；
3. **扫描、切片、模型与报告工件**：放在 `artifacts/`，由 run manifest 串联。

固定微型样例只能放在 `tests/fixtures/`，用于回归和演示；真实开源软件不得复制进 `src/` 或写死在 Agent prompt 中。正式数据集只提交 manifest、adapter 和复现脚本，原则上不重新分发第三方源码。

### 13.2 最终推荐目录

```text
evitriage-ql/
├── README.md
├── AGENTS.md
├── LICENSE
├── CITATION.cff
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── KNOWN_LIMITATIONS.md
├── pyproject.toml
├── uv.lock
├── Makefile
├── docker-compose.yml
├── .env.example
├── .gitignore
├── .github/workflows/
│   ├── ci.yml
│   ├── codeql-query-tests.yml
│   └── benchmark-smoke.yml
├── configs/
│   ├── system/
│   │   ├── v0.1.yaml
│   │   └── paper.yaml
│   ├── projects/                    # 一个目标软件一个 ProjectSpec
│   │   ├── example-local.yaml
│   │   └── example-git.yaml
│   ├── llm-profiles/
│   │   ├── replay.yaml
│   │   ├── local-openai-compatible.example.yaml
│   │   └── remote-openai-compatible.example.yaml
│   └── datasets/
├── schemas/
│   ├── project-spec.schema.json
│   ├── run-manifest.schema.json
│   ├── alert-bundle.schema.json
│   ├── evidence.schema.json
│   └── decision.schema.json
├── src/evitriage/
│   ├── cli.py
│   ├── config.py
│   ├── errors.py
│   ├── domain/
│   ├── projects/                    # ProjectSpec、registry、validation
│   ├── workspace/                   # WorkspaceManager、locks、cleanup
│   ├── repo/
│   ├── build/
│   ├── codeql/
│   ├── sarif/
│   ├── slicing/
│   ├── context/
│   ├── evidence/
│   ├── llm/
│   ├── agents/
│   ├── workflow/
│   ├── verification/
│   ├── calibration/
│   ├── evaluation/
│   ├── reporting/
│   ├── storage/
│   └── integrations/github/
├── prompts/
│   ├── analyst.md
│   ├── rebuttal.md
│   ├── judge.md
│   └── prompt-schema-version.txt
├── codeql/
│   ├── qlpacks/
│   ├── suites/
│   ├── helper-queries/
│   ├── models/
│   └── tests/
├── datasets/
│   ├── manifests/
│   ├── adapters/
│   └── README.md
├── experiments/
│   ├── protocols/
│   ├── runs/                        # 只保存小型汇总/索引，不复制大工件
│   └── notebooks/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   ├── golden/
│   ├── security/
│   └── fixtures/
│       ├── java-microbench/         # 唯一可提交的固定待测软件
│       └── sarif/
├── workspaces/                      # 默认写入 .gitignore
│   ├── sources/                     # 不可变源码快照或 Git checkout
│   ├── build-copies/                # 每个 run 的可写、可丢弃构建副本
│   ├── codeql-databases/
│   ├── temporary/
│   └── locks/
├── artifacts/                       # 默认写入 .gitignore
│   ├── objects/sha256/              # 内容寻址、去重的原始工件
│   └── runs/<run_id>/
│       ├── run-manifest.yaml
│       ├── project-spec.resolved.yaml
│       ├── input/
│       ├── build/
│       ├── codeql/
│       ├── normalized/
│       ├── context/
│       ├── evidence/
│       ├── llm/
│       ├── decisions/
│       ├── reports/
│       └── logs/
├── docs/
│   ├── architecture.md
│   ├── project-spec.md
│   ├── labeling-guide.md
│   ├── reproducibility.md
│   ├── threat-model.md
│   ├── progress/
│   └── adr/
└── scripts/
    ├── bootstrap_codeql.sh
    ├── export_sbom.sh
    └── reproduce_paper.sh
```

`workspaces/`、`artifacts/`、本地 `.env`、模型缓存和私有项目配置必须默认进入 `.gitignore`。只有脱敏、体积受控、许可证允许的示例报告可以提交到 `docs/examples/`。

### 13.3 `ProjectSpec`：替换目标软件的唯一入口

推荐 Schema：

```yaml
schema_version: "1.0"

project:
  id: example-project
  display_name: Example Project
  language: java
  license_hint: Apache-2.0        # 仅作记录，不作法律判断

source:
  type: local                    # local | git | dataset
  path: /data/projects/example-project
  snapshot_mode: copy            # copy | git-worktree；正式实验禁止 in-place
  require_clean_git: true
  # Git 输入改为：
  # type: git
  # url: https://github.com/org/example-project.git
  # commit: 0123456789abcdef0123456789abcdef01234567
  # submodules: false

build:
  adapter: maven                 # maven | gradle | explicit
  jdk: "17"
  working_directory: "."
  command: ["./mvnw", "-q", "-DskipTests", "package"]
  timeout_seconds: 1800
  network_policy: disabled

codeql:
  cli_version: "2.26.1"
  language: java-kotlin
  query_suites: ["security-extended"]
  query_packs: []
  model_packs: []
  include_query_help: true

analysis:
  target_cwes: ["CWE-22", "CWE-78"]
  context_policy: path_function_slice
  workflow: evidence_three_agent
  llm_profile: replay-v0.1

security:
  source_upload_policy: offline_only
  allow_build_network: false
  allow_submodules: false
  allow_generated_shell: false

storage:
  workspace_root: workspaces
  artifact_root: artifacts
```

规则：

- `project.id` 只能使用安全 slug；
- `source.type=git` 必须指定完整 commit SHA，正式实验不得使用浮动 branch/tag；
- 本地目录若存在未提交修改，要记录 `git diff` digest 和 source tree hash；主实验默认拒绝 dirty tree；
- 配置解析后生成 `project-spec.resolved.yaml`，其中环境变量已解析但 secret 必须脱敏；
- 同一个 `ProjectSpec` 在相同工具链下应产生稳定的 repository snapshot identity。

### 13.4 Workspace 生命周期与隔离

一次运行的标准流程：

```text
ProjectSpec validate
→ acquire source snapshot
→ create isolated writable build copy
→ allocate CodeQL DB and artifact directories
→ scan/ingest
→ normalize/context/evidence/triage/report
→ finalize immutable manifest
→ cleanup temporary build copy according to retention policy
```

- 不修改用户原始目录；
- 每个 run 使用独立 `run_id`，不得共享可写 build 目录；
- 对源码、SARIF、切片、prompt、响应和报告计算 SHA-256；
- 使用文件锁避免同一 workspace 被并发破坏；
- 路径必须经过 canonicalization，拒绝 `..`、越界 symlink 和绝对路径注入；
- 删除操作只能作用于当前 run 的受管目录；
- `artifacts/runs/<run_id>/run-manifest.yaml` 是完整审计入口。

### 13.5 目标来源与可扩展性边界

| 输入方式 | `v0.1.0` | 后续版本 | 说明 |
|---|---:|---:|---|
| 本地 Java 项目目录 | 必须 | 保留 | 首版主要入口；通过 snapshot 隔离原目录 |
| 既有 SARIF + 本地源码 | 必须 | 保留 | 离线演示和外部 CodeQL 结果接入 |
| Git URL + 固定 commit | Schema 支持，执行可延期 | `V0.2` 必须 | 不能使用浮动主分支做正式实验 |
| 数据集 adapter | 仅 microbench manifest | `V0.5` 扩展 | OWASP/Vul4J/CWE-Bench-Java 等 |
| 任意语言/构建系统 | 不承诺 | 插件式扩展 | 通过 LanguageAdapter/BuildAdapter 增加 |

换软件时只新增配置并运行：

```bash
uv run evitriage project validate \
  --config configs/projects/project-a.yaml

uv run evitriage scan \
  --project-config configs/projects/project-a.yaml
```

把配置替换为 `project-b.yaml` 即可切换目标；核心 pipeline、Agent 和报告逻辑不应改变。

### 13.6 BuildAdapter 最小接口

```python
class BuildAdapter(Protocol):
    def detect(self, snapshot: RepositorySnapshot) -> bool: ...
    def prepare(self, spec: BuildSpec, workspace: RunWorkspace) -> BuildPlan: ...
    def execute(self, plan: BuildPlan) -> BuildResult: ...
    def verify(self, result: BuildResult) -> None: ...
```

`v0.1.0` 强制 Maven wrapper；Gradle 和 explicit command 可作为 P1。EviTriage-QL 自己启动 subprocess 时使用参数数组并禁止 `shell=True`。CodeQL 的 `database create --command` 本身接收构建命令字符串，因此必须由已验证的 `BuildPlan.argv` 使用平台安全 quoting 生成，禁止拼接模型输出、仓库文本或未验证用户片段。保存 timeout、退出码、stdout/stderr、JDK/Maven/Gradle 版本和环境摘要。

---

## 14. 测试对象与数据集设计

### 14.1 Tier A：自建微型基准

建议 64—96 个 Java case：

- 4 个 CWE；
- 每个 CWE 至少覆盖：直接 TP、跨函数 TP、有效 sanitizer FP、无效 sanitizer TP、不可达 FP、可信 source FP、配置依赖 NMC、动态调用 NMC；
- 每个 case 同时提供 vulnerable 和 fixed 版本；
- 具有明确 JUnit 或 HTTP-level oracle。

用途：开发、单元/集成回归、快速 ablation；不能作为论文唯一证据。

### 14.2 Tier B：受控公开基准

- **OWASP Benchmark**：主要用于 SAST TP/FP 过滤和工具对比；
- **CodeQL query tests**：用于规则和 model pack 正确性；
- 可选 Juliet 子集：用于特定 CWE 大规模回归。

### 14.3 Tier C：真实可复现漏洞

- **Vul4J**：真实 Java 漏洞、human patch、PoV；
- **CWE-Bench-Java**：仓库级真实漏洞和修复版本；
- 固定 release/commit，避免不同版本的样本数和元数据发生漂移。

### 14.4 Tier D：真实告警人工标注集

从 3—5 个可重复构建的 Java 开源仓库中抽取 CodeQL 告警：

- 每个仓库固定 commit；
- 选择 Maven/Gradle、Web/API/文件处理相关项目；
- 只对目标 CWE 抽样；
- 两名独立标注者 + 第三人仲裁；
- 保留 evidence、uncertainty reason 和时间成本。

不要把“没有公开 CVE”当作 TN。真实仓库的负样本必须来自人工审计或决定性反证。

### 14.5 后续内部数据

在公开基准稳定后，再接入 1—3 个内部仓库，用于评估预训练污染较低的真实泛化。

---

## 15. 标签规范

### 15.1 TP

必须满足：

- source 可控；
- 路径存在且可行；
- sink 具有安全影响；
- sanitizer/guard 不足；
- 或 PoV/测试明确触发。

### 15.2 FP

必须存在决定性反证，例如：

- source 不可控；
- 路径不可达；
- 值在到达 sink 前被严格限定；
- sanitizer 对当前上下文被代码/测试证明有效；
- sink 不执行危险行为。

### 15.3 NMC

以下情况均为 NMC：

- 缺失部署配置；
- 无法解析动态调用；
- sanitizer 依赖外部库/运行时语义；
- 权限或入口可达性未知；
- Agent 证据冲突；
- 验证环境失败。

### 15.4 标注过程

- 标注者看完整仓库，但模型主实验只能看协议允许的上下文；
- 两名标注者独立标注；
- 记录 Cohen's kappa；
- 分歧由第三人仲裁；
- 标注者不得只依据 CodeQL message；
- 每个标签必须绑定证据位置和理由。

---

## 16. 评测协议

### 16.1 基线

- B0：CodeQL 原始告警，不二次过滤；
- B1：CodeQL + severity/CWE/路径长度等规则；
- B2：CodeQL + 单次 LLM + 告警点固定窗口；
- B3：CodeQL + 单次 LLM + 路径切片；
- B4：CodeQL + 工具型单 Agent；
- B5：CodeQL + Analyst/Rebuttal/Judge；
- B6：B5 + 自适应上下文；
- B7：B6 + 选择性验证 + 校准。

若能稳定复现，可加入 IRIS 等相关系统；不能把不可复现结果当强基线。

### 16.2 数据切分

- project-disjoint；
- chronological；
- vulnerable/fixed pair 必须在同一 split；
- 同 CVE 多版本不得跨 split；
- 使用 token/AST 相似度检测近重复；
- final test 在 prompt、阈值、校准器冻结后才运行。

### 16.3 主指标

- TP Precision、Recall、F1；
- FP reduction；
- false-negative rate；
- `Precision at fixed TP recall`；
- 选择性分类的 coverage-risk curve；
- NMC rate；
- Brier score、ECE；
- token、成本、时延、上下文大小；
- 人工复核时间节省。

推荐主终点：

```text
在真阳性召回不低于预设安全门槛时，最大化可自动消除的 FP 比例。
```

### 16.4 统计分析

- 对告警级指标做 bootstrap 95% CI；
- 配对分类结果使用 McNemar 检验；
- token/时延使用非参数检验；
- 每个随机型 LLM 配置至少重复 3 次；
- 同时报告 mean、std、median 和失败率；
- 不只报告最佳一次结果。

### 16.5 消融实验

- 去除 CodeQL path；
- 固定窗口替代切片；
- 去除 Rebuttal Agent；
- 去除框架/配置上下文；
- 去除 NMC，强制二分类；
- 去除 evidence ID 约束；
- 去除自适应扩展；
- 去除动态验证；
- 去除校准器；
- 不同模型/温度/上下文预算。

### 16.6 鲁棒性实验

- 变量和函数重命名；
- 格式化与注释变化；
- 插入无关死代码；
- 路径步骤轻微重排；
- 在代码注释中加入 prompt injection；
- 缺失配置或故意错误测试；
- SARIF 多路径、重复告警、路径缺失。

---

## 17. 项目自身的测试策略

### 17.1 单元测试

- SARIF 2.1.0 解析；
- `codeFlows` 与 location 映射；
- fingerprint 稳定性；
- 路径去重；
- slice token budget；
- evidence ID/hash；
- schema validation；
- 状态机非法迁移；
- decision policy；
- calibration feature extraction；
- redaction 和 path safety。

### 17.2 Property-based tests

- 任意合法/部分缺失 SARIF 不应使解析器崩溃；
- 任意行列范围都必须被规范化或明确拒绝；
- evidence 引用不得悬空；
- 相同输入 hash 必须命中相同 replay 结果；
- 状态机不能跳过关键状态。

### 17.3 集成测试

- 小型 Maven repo → CodeQL DB → SARIF → slice；
- fake LLM → Analyst/Rebuttal/Judge → report；
- NMC → context expansion → rejudge；
- sandbox test → verification evidence；
- SQLite/Postgres 双后端；
- GitHub adapter 使用 mock server。

### 17.4 端到端测试

- 微型 CWE-22 TP/FP；
- OWASP Benchmark 小子集；
- Vul4J 单个可复现 case；
- 构建失败和 CodeQL 超时；
- prompt injection 安全用例。

### 17.5 CodeQL query tests

自定义 helper query、query suite 和 model pack 都使用 `codeql test run` 建立正例/反例回归。

---

## 18. 以 2026-07-27 `V0.1.0` 为锚点的推进计划

### 18.1 当前基线与计划口径

截至 **2026 年 7 月 20 日**，按当前已经提供的材料，可以确认已经具备：

- CodeQL + LLM 两阶段方案调研；
- 项目研究定位、总体架构、标签体系和评测框架；
- 面向 Codex 的项目级构建提示词初稿。

代码仓库中的实际实现进度仍应以可运行命令、测试结果和 commit 为准。因此，下面的计划按“工程实现从纵向骨架开始”制定；已经完成的模块可以直接跳过，但不得跳过对应验收门。

### 18.2 7 月 27 日首版的定义

`V0.1.0` 定义为 **科研原型的第一条可审计纵向闭环**，不是完整论文系统。它必须展示核心研究思想已经被落实为可执行软件：

```text
Java 微型样例或固定 SARIF
→ CodeQL/SARIF 接入
→ codeFlows 归一化
→ 路径相关代码上下文
→ Evidence Registry
→ Analyst / Rebuttal / Judge 最小工作流
→ 确定性证据门控
→ TP / FP / NMC
→ JSON + HTML 报告
```

首版应同时提供两条运行路径：

1. **离线稳定路径**：使用 golden SARIF、fake/replay LLM，在 CI 和任何无密钥环境中完整运行；
2. **真实工具路径**：在本地已安装 CodeQL 的环境中，对至少一个小型 Java Maven fixture 执行真实扫描并进入同一后续流水线。

首版不以大规模准确率或论文结论为目标，而以“核心接口正确、证据链成立、工作流可复现、后续可扩展”为目标。

### 18.3 首版范围冻结

| 优先级 | 7 月 27 日前的范围 | 处理原则 |
|---|---|---|
| **P0：必须完成** | Python 工程骨架、CLI/config/errors；`ProjectSpec`、`WorkspaceManager` 和本地项目切换；最小 SQLite/run manifest；本地 Java fixture；CodeQL runner 与 `ingest-sarif` 双入口；SARIF 2.1.0 `rules/results/codeFlows` 归一化；路径函数切片；Evidence/Claim schema；Analyst/Rebuttal/Judge 最小工作流；Fake/Replay LLM；确定性 TP/FP/NMC 门控；JSONL/HTML 报告；测试与 README | 任一 P0 未过验收，不发布 `v0.1.0` |
| **P1：完成 P0 后再做** | 真实 API 模型 provider adapter；远程 Git 仓库 checkout；完整 Gradle/explicit build adapter；多路径去重；更多微型 case；token/成本/时延统计 | 可以进入 `v0.1.1` 或 `v0.2.0`，不得挤占 P0 |
| **P2：首版明确延期** | 自适应上下文、符号/动态验证、校准器、OWASP/Vul4J/CWE-Bench-Java 全量 adapter、PostgreSQL、GitHub App/PR 回写、模型包自动生成、大规模实验 | 进入 7 月 28 日后的科研迭代 |

首版只承诺：

- 语言：Java；
- CWE：以 CWE-22、CWE-78 的微型样例为主；
- 上下文：Level 0 + Level 1 路径函数切片；
- 决策：TP / FP / NMC；
- 模型运行：fake/replay 必须稳定，真实模型调用为可选增强；
- 输出：本地文件，不自动关闭或修改任何原始 CodeQL 告警。

### 18.4 7 月 20 日—7 月 27 日逐日推进

| 日期 | 当日目标 | 关键工作 | 日终验收门 |
|---|---|---|---|
| **7 月 20 日（周一）** | 冻结范围并建立可替换目标的软件底座 | 建立仓库结构、`ProjectSpec` Schema、`configs/projects/`、`WorkspaceManager`、`.gitignore`、`pyproject.toml`、`Makefile`、错误类型、日志、ADR、`CHANGELOG.md`、进度表；实现 `project validate` 与 `doctor`；建立 Ruff、mypy、pytest CI | 两个不同本地 fixture 的 ProjectSpec 均可验证并分配独立 workspace；`uv sync`、`make check`、`uv run evitriage doctor --json` 可运行；P0/P1/P2 冻结 |
| **7 月 21 日（周二）** | 打通 CodeQL/SARIF 输入层 | 实现本地仓库快照、CodeQL 命令封装、超时和结构化错误；实现 `scan` 与 `ingest-sarif`；解析 runs、rules、results、locations、relatedLocations、codeFlows、fingerprints；建立 golden SARIF | golden SARIF 可稳定生成 `NormalizedAlert`；有 CodeQL 环境时完成一次真实 Java fixture smoke scan；无 CodeQL 时明确报告环境缺口而不伪造成功 |
| **7 月 22 日（周三）** | 构建路径上下文与证据 | 实现 path step 顺序、source/sink 标识、路径 fingerprint、Java 函数范围/路径函数切片、token 估算、Evidence Registry、artifact hash 和悬空引用检查 | 每条 fixture 告警都能生成 `SliceArtifact` 和稳定 evidence IDs；source、sink、path step 可从报告反查到源码位置 |
| **7 月 23 日（周四）** | 完成最小二次筛选核心 | 实现 StructuredLLM protocol、FakeLLM、ReplayLLM、严格 JSON Schema；加入 Analyst、Rebuttal、Judge；实现 Claim 校验和确定性 policy | fake/replay 对 TP、FP、NMC 三类 fixture 给出结构化结果；未知 evidence ID、冲突证据或缺失关键证据不能被判为高置信 FP |
| **7 月 24 日（周五）** | 完成端到端演示 | 串联 `ingest/scan → normalize → context → triage → report`；实现 JSONL、run manifest、HTML 报告；提供 `make demo` | 无网络、无真实模型时，一条命令可完成完整演示；报告包含 commit/tool/config、路径、claims、evidence、label、unknowns 和限制 |
| **7 月 25 日（周六）** | 做质量、安全和回归加固 | 补齐单元、golden、集成、E2E 和安全测试；覆盖 prompt injection、恶意 URI、symlink/path escape、HTML escape、shell metacharacter；完善日志脱敏 | P0 核心模块覆盖率不低于 80%；Ruff、mypy、pytest 全通过；所有不可信文本在 HTML 和 prompt 中被安全处理 |
| **7 月 26 日（周日）** | 形成 Release Candidate | 在干净环境进行重装与复现；运行真实 CodeQL smoke；整理 README 五分钟 quickstart、架构图、已知限制、示例结果；冻结 schema/prompt 版本 | 形成 `v0.1.0-rc1`；从空目录按 README 可运行 `make demo`；不存在 P0 blocker；所有已知问题进入 issue/limitations |
| **7 月 27 日（周一）** | 发布首版 | 只修阻塞问题，不新增功能；生成 release notes、source archive、示例报告、manifest、测试摘要；打 tag | 发布 `v0.1.0`；演示命令、测试结果和已知限制均可复核；首版证据链可由第三方重放 |

### 18.5 `V0.1.0` Definition of Done

#### 功能验收

- `make check` 通过；
- `uv run evitriage doctor --json` 能报告 Python、CodeQL、Java 和配置状态；
- 至少两个不同本地 `ProjectSpec` 可通过同一 CLI 运行，证明目标软件没有硬编码；
- 用户原始源码目录不被修改，workspace/artifact 路径彼此隔离；
- `make demo` 在无真实 LLM、无网络的条件下完成全流程；
- `evitriage ingest-sarif` 能读取至少单路径、多路径、无 `codeFlows` 三类 SARIF；
- 在至少一个开发环境中完成真实 CodeQL → SARIF 的 Java fixture smoke run；
- 至少包含 6 个微型 case：CWE-22 TP/FP/NMC、CWE-78 TP/FP、prompt-injection 安全 case；
- 所有 FinalDecision 引用的 claim/evidence ID 均存在；
- FP 需要决定性反证，无法满足时必须输出 NMC；
- JSONL 与 HTML 报告均可生成，HTML 对不可信内容做转义。

#### 工程质量验收

- Ruff、mypy strict、pytest 通过；
- P0 核心模块覆盖率不低于 80%，schema/policy/security 模块优先达到更高覆盖；
- CI 不调用付费模型，不依赖真实 API key；
- 外部工具失败返回结构化错误，不使用伪造结果；
- 不使用 `shell=True`，不执行模型自由生成的命令；
- 运行产物包含 tool/config/prompt/schema 版本和 SHA-256 hash。

#### 科研与审计验收

- 提供至少一份 TP、一份 FP、一份 NMC 的完整案例报告；
- 明确记录首版未实现项，禁止把微型 case 结果宣传为泛化性能；
- 主实验输入中不存在 CVE 描述、补丁或 PoV 泄漏；
- 保存演示 run manifest、原始 SARIF、normalized alert、slice、evidence、decision 和报告；
- 发布 `CHANGELOG.md`、`KNOWN_LIMITATIONS.md` 和复现命令。

### 18.6 保交付降级策略

为了确保 7 月 27 日确实有版本，按以下顺序降级，而不是牺牲证据正确性：

1. **不得裁掉**：SARIF 归一化、Evidence/Claim schema、TP/FP/NMC、确定性 policy、fake/replay、离线 E2E、测试、版本 manifest；
2. **首先延期**：GitHub 回写、PostgreSQL、远程仓库管理、完整 Gradle 适配、复杂 UI；
3. **其次延期**：真实模型 provider、adaptive slice、多轮自动补上下文、动态验证、校准；
4. **绝不采用**：把缺失实现替换为假数据、把模型输出直接作为最终结论、为了按期发布而自动把 NMC 归为 FP。

关键时间门：

- **7 月 23 日晚**若真实 CodeQL 环境仍阻塞：保留真实 runner 与明确错误，主演示转为 golden SARIF；真实扫描继续作为 7 月 26 日手工 smoke gate；
- **7 月 24 日晚**若真实模型适配不稳定：从首版移除，保留 provider-neutral 接口，使用 fake/replay 完成科研可复现闭环；
- **7 月 25 日 12:00 后**进入 feature freeze，只允许测试、文档、阻塞修复和删除不稳定功能；
- **7 月 26 日晚**若某 P1 功能破坏 clean-room reproduction：直接从 release branch 移除。

### 18.7 7 月 27 日后的 12 周科研路线

| 时间 | 版本门 | 重点交付 |
|---|---|---|
| **7 月 28 日—8 月 10 日** | `V0.2` | 远程 checkout、Maven/Gradle/JDK build adapter、真实 CodeQL 稳定性、更多 SARIF 变体、8—16 个微型 case |
| **8 月 11 日—8 月 24 日** | `V0.3` | Tree-sitter/CodeQL helper query 驱动的高保真切片、guard/sanitizer/caller/callee、NMC context planner |
| **8 月 25 日—9 月 7 日** | `V0.4` | 真实模型 adapter、三 Agent 重复性与成本记录、prompt injection 加固、单 Agent/三 Agent 基线 |
| **9 月 8 日—9 月 21 日** | `V0.5` | Java sandbox verifier、OWASP/Vul4J/CWE-Bench-Java adapter 小规模接入、选择性验证策略 |
| **9 月 22 日—10 月 5 日** | `V0.6` | 人工标签流程、project-disjoint/chronological split、指标、bootstrap、校准与主要消融 |
| **10 月 6 日—10 月 12 日** | `V1.0 Research PoC` | 完整主实验、案例研究、复现脚本、论文表格、artifact README 和论文初稿 |

每个版本门都必须以前一版本可重放为前提；科研功能不得破坏 `V0.1.0` 的离线演示路径。

---

## 19. 6—12 个月扩展

1. Java/Kotlin 框架 model packs；
2. Python Web 框架；
3. JavaScript/TypeScript 动态调用边与 library summaries；
4. 主动学习：选择最有信息量的 NMC 供人工标注；
5. 组织级历史 triage memory；
6. 更强 path feasibility / symbolic execution；
7. 跨模型、跨语言的 calibration；
8. GitHub App/PR 工作流；
9. 自有真实告警数据集与 benchmark；
10. 新漏洞负责任披露流程。

---

## 20. 大致使用方法

### 20.0 `v0.1.0` 离线发布路径

```bash
uv sync --all-extras
make check
uv run evitriage doctor --json
make demo
```

`make demo` 使用仓库内 Java microbench、golden SARIF 和 Replay/Fake LLM，不需要网络、API key 或真实模型。

### 20.1 校验并扫描一个本地目标软件

先创建 `configs/projects/my-project.yaml`，再执行：

```bash
uv run evitriage project validate \
  --config configs/projects/my-project.yaml

uv run evitriage scan \
  --project-config configs/projects/my-project.yaml
```

系统应打印 `run_id`，并把所有结果写入 `artifacts/runs/<run_id>/`。换软件只需替换配置文件：

```bash
uv run evitriage scan \
  --project-config configs/projects/another-project.yaml
```

`--repo-path` 可以作为首版便捷参数，但内部必须立即转换为临时 `ProjectSpec`，不得形成第二套执行逻辑。

### 20.2 接入已有 CodeQL SARIF

```bash
uv run evitriage ingest-sarif \
  --project-config configs/projects/my-project.yaml \
  --sarif /data/results/codeql.sarif
```

然后运行：

```bash
uv run evitriage context build --run-id <RUN_ID> --policy path-function-slice
uv run evitriage triage --run-id <RUN_ID> --llm-profile replay-v0.1
uv run evitriage report --run-id <RUN_ID> --formats jsonl,html
```

### 20.3 Git 仓库输入（`V0.2` 执行能力）

```bash
uv run evitriage scan \
  --project-config configs/projects/example-git.yaml
```

`example-git.yaml` 必须包含完整 commit SHA。正式实验禁止使用 `main`、`master` 或浮动 tag。

### 20.4 调用真实大模型 API（`V0.4` 正式进入发布门）

运行时大模型不是 Codex。Codex只负责构建项目；EviTriage-QL 通过 `StructuredLLM` provider adapter 调用模型服务。

远程或本地模型都可以使用 HTTP API：

```bash
export EVITRIAGE_LLM_BASE_URL='https://provider.example/v1'
export EVITRIAGE_LLM_API_KEY='***'
export EVITRIAGE_LLM_MODEL='model-name'

uv run evitriage triage \
  --run-id <RUN_ID> \
  --llm-profile remote-openai-compatible
```

连接本地 vLLM/SGLang/Ollama 等兼容端点时，将 `base_url` 指向本机服务，并把数据策略设为 `local_only`。真实模型通常按告警顺序执行 Analyst、Rebuttal、Judge 三次主调用；每个角色最多允许一次 Schema 修复重试。所有请求按 prompt + payload + schema + model 计算 hash 并缓存。

### 20.5 选择性验证（`V0.5`）

```bash
uv run evitriage verify \
  --run-id <RUN_ID> \
  --only escalated \
  --sandbox docker
```

### 20.6 生成报告与运行论文协议

```bash
uv run evitriage report \
  --run-id <RUN_ID> \
  --formats jsonl,csv,html

uv run evitriage benchmark \
  --protocol experiments/protocols/paper-v1.yaml
```

---

## 21. 配置、模型 API 与数据治理

### 21.1 首版系统配置 `configs/system/v0.1.yaml`

```yaml
schema_version: "1.0"

codeql:
  required_cli_version: "2.26.1"
  include_query_help: true
  timeout_seconds: 1800

context:
  policy: path_function_slice
  maximum_token_budget: 24000
  include_tests: false
  include_config: false

agents:
  workflow: evidence_three_agent
  llm_profile: replay-v0.1
  temperature: 0
  maximum_schema_repairs_per_agent: 1
  maximum_model_calls_per_alert: 6
  require_evidence_ids: true
  allow_repository_instructions: false

policy:
  labels: [TP, FP, NMC]
  auto_dismiss: false
  fp_requires_decisive_rebuttal: true
  conflict_or_missing_evidence: NMC

verification:
  enabled: false

reproducibility:
  cache_llm_responses: true
  persist_prompts: true
  persist_tool_versions: true
  seed: 20260720
```

### 21.2 本地与 Git `ProjectSpec`

本地目标：

```yaml
schema_version: "1.0"
project: {id: local-demo, display_name: Local Demo, language: java}
source:
  type: local
  path: tests/fixtures/java-microbench/cwe22-direct-tp
  snapshot_mode: copy
  require_clean_git: false
build:
  adapter: maven
  jdk: "17"
  command: ["./mvnw", "-q", "-DskipTests", "package"]
  timeout_seconds: 600
codeql:
  cli_version: "2.26.1"
  language: java-kotlin
  query_suites: ["security-extended"]
analysis:
  target_cwes: ["CWE-22"]
  context_policy: path_function_slice
  workflow: evidence_three_agent
  llm_profile: replay-v0.1
```

Git 目标：

```yaml
schema_version: "1.0"
project: {id: public-project-a, display_name: Public Project A, language: java}
source:
  type: git
  url: https://github.com/org/project.git
  commit: 0123456789abcdef0123456789abcdef01234567
  submodules: false
build:
  adapter: gradle
  jdk: "17"
  command: ["./gradlew", "build", "-x", "test"]
  timeout_seconds: 1800
codeql:
  cli_version: "2.26.1"
  language: java-kotlin
  query_suites: ["security-extended"]
analysis:
  target_cwes: ["CWE-22", "CWE-78"]
  context_policy: adaptive_slice
  workflow: evidence_three_agent
  llm_profile: remote-openai-compatible
```

### 21.3 LLM profile

离线回放：

```yaml
id: replay-v0.1
provider: replay
cache_dir: tests/fixtures/llm-replay
network: disabled
data_policy: offline_only
```

远程 API：

```yaml
id: remote-openai-compatible
provider: openai_compatible
base_url_env: EVITRIAGE_LLM_BASE_URL
api_key_env: EVITRIAGE_LLM_API_KEY
model_env: EVITRIAGE_LLM_MODEL
temperature: 0
timeout_seconds: 120
maximum_retries: 2
maximum_concurrency: 2
data_policy: remote_slice_only
persist_raw_response: false
```

本地 API：

```yaml
id: local-openai-compatible
provider: openai_compatible
base_url: http://127.0.0.1:8000/v1
api_key_env: EVITRIAGE_LOCAL_LLM_KEY
model: local-model
data_policy: local_only
```

### 21.4 大模型调用边界

- `v0.1.0` 发布门只要求 Fake/Replay；真实 API adapter 是 P1，`V0.4` 起进入正式实验门；
- 远程 API 默认只发送结构化告警、路径切片和 evidence 摘要，不发送整仓；
- 私有源码必须由组织策略明确允许，默认 `offline_only` 或 `local_only`；
- API key 只从环境或 secret manager 读取，不能进入 YAML、日志、manifest 或报告；
- 模型输出只产生候选 claims，不获得 shell、Git、文件写入或网络工具权限；
- 每次调用保存 model id、prompt/schema hash、request hash、token、时延和错误；
- Replay 以 request hash 命中，保证相同实验可离线重跑；
- 模型厂商变更不应影响 domain、workflow 和 evaluation 层。

### 21.5 配置版本与迁移

每次增加字段都提升 schema version。配置必须严格校验未知字段；破坏性变化提供显式 migration，不允许静默采用默认值改变实验语义。

---

## 22. 安全威胁模型

分析对象本身是不可信输入，必须防御：

- 源码注释或 README 中的 prompt injection；
- 恶意构建脚本；
- 依赖安装脚本；
- 符号链接越界；
- 路径遍历式工件名；
- 超大文件和压缩炸弹；
- 构建时访问云凭据；
- LLM 把代码中的文字当系统指令；
- Agent 生成危险 shell 命令；
- 报告泄露 API key/源码秘密；
- 未经授权把私有源码或整仓上下文发送给远程模型 API；
- 目标项目配置覆盖系统级模型 endpoint、secret 或工具权限。

控制：

- 代码片段以明确数据边界包装；
- ProjectSpec 不得定义模型 endpoint、API key 或系统 prompt；这些只能来自受信任的系统/LLM profile；
- 远程模型调用执行数据策略检查，默认只允许发送最小路径切片；
- 源码中的自然语言永不提升为指令；
- 工具调用 allowlist；
- subprocess 禁止 `shell=True`；
- 沙箱无宿主凭据；
- 网络默认关闭；
- 日志和 prompt 做 secret redaction；
- 报告前做路径和 HTML escaping；
- 所有自动动作只读，发布/关闭告警需人工审批。

---

## 23. 研究成功门槛

以下是工程门槛，不是预先宣称的实验结果：

- 公开测试对象构建/扫描成功率达到协议设定值；
- 100% 最终 claim 能追溯到合法 evidence ID；
- 0 个未经证据门控的自动 FP；
- 主实验在固定 TP recall 门槛下实现有意义的 FP reduction；
- NMC 被作为正式 abstention 报告，而非隐藏；
- 至少完成 project-disjoint + chronological 切分；
- 核心结果有 bootstrap CI；
- 一键复现实验脚本能够在干净环境执行；
- prompt injection 测试不允许源码改变系统目标或调用任意工具。

---

## 24. 最有价值的论文贡献组合

建议把论文主贡献控制为三项：

1. **Evidence Contract**：每个告警判断必须绑定可定位、可哈希、可回放的结构化证据；
2. **Uncertainty-Aware Adaptive Triage**：TP/FP/NMC + 自适应上下文 + 置信度校准；
3. **Selective Verification**：根据分歧、风险与证据缺口，仅验证少数关键告警。

数据集与工程系统作为 artifact contribution，而不是同时宣称过多算法创新。

---

## 25. 最终建议

从 Java 的 CWE-22 和 CWE-78 开始，先把“CodeQL → SARIF → 路径切片 → evidence registry → 三 Agent → TP/FP/NMC → 报告”闭环做到可靠；第 8 周以前不要急于做复杂符号执行。你的编译优化背景会让你在数据流、程序切片和路径条件部分具备优势，而真正需要补齐的是安全标注规范、开源构建复现和实验防泄漏。
