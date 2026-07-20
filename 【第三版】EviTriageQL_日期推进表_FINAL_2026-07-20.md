# EviTriage-QL 最终日期推进表

**文档版本**：Final 1.0（2026-07-20，Asia/Tokyo）  
**冲刺周期**：2026-07-20—2026-07-27  
**首版发布**：2026-07-27，tag `v0.1.0`  
**首版定位**：可替换目标软件的 CodeQL/SARIF → 路径上下文 → Evidence → 三 Agent → TP/FP/NMC → 报告纵向闭环

> 当前只确认调研、蓝图、Codex master prompt 和本推进表已经完成。工程代码、测试、真实 CodeQL 运行和发布状态尚未核验，必须以 commit、命令和工件为准。

---

## 1. 首版唯一目标

```text
ProjectSpec 指向本地 Java fixture 或既有 SARIF
→ 隔离 workspace
→ CodeQL scan / SARIF ingest
→ normalize codeFlows
→ path-function context
→ Evidence Registry
→ Analyst / Rebuttal / Judge（Fake/Replay）
→ deterministic TP / FP / NMC policy
→ JSONL + HTML + run manifest
```

`v0.1.0` 必须证明：

1. 目标软件不是固定的——至少两个不同 `ProjectSpec` 通过同一 pipeline；
2. 证据链真实可追溯——所有 claim 引用合法 evidence；
3. 离线可复现——无网络、无 API key、无真实模型运行 `make demo`；
4. 真实入口存在——至少一个开发环境完成 CodeQL Java smoke；
5. 安全失败优先——缺少反证不判 FP，冲突或缺上下文返回 NMC。

---

## 2. 当前基线

| 工作项 | 截至 2026-07-20 的可信状态 | 证据/下一动作 |
|---|---|---|
| 方向调研 | 完成 | 已有 CodeQL + LLM 调研文档 |
| 最终项目蓝图 | 完成 | `EviTriageQL_项目蓝图_FINAL_2026-07-20.md` |
| Codex master prompt | 完成 | `EviTriageQL_Codex_完整构建提示词_FINAL_2026-07-20.md` |
| 最终推进表 | 完成 | 本文档 |
| 工程仓库与 CI | 未核验 | Gate A 首先执行 `make check` |
| ProjectSpec/Workspace | 未核验 | Gate A 必须完成 |
| CodeQL/SARIF | 未核验 | Gate B |
| Context/Evidence | 未核验 | Gate C |
| Agent/Policy | 未核验 | Gate D |
| E2E/Report | 未核验 | Gate E |
| RC/Release | 未开始 | 7/26、7/27 |

状态只允许：`未开始`、`进行中`、`阻塞`、`完成`、`取消/延期`。没有可执行证据时不得标记完成。

---

## 3. 每日 Gate 与关键路径

| 日期 | Gate | 当日唯一主目标 | 必须交付 | 日终验收 | 失败时降级 |
|---|---|---|---|---|---|
| **7/20 周一** | A | 可替换目标的软件工程底座 | package/CLI/config/errors/logging/SQLite；`ProjectSpec` Schema；`configs/projects/`；`WorkspaceManager`；`.gitignore`；CI；`doctor`；ADR/进度表 | 两个本地 fixture 配置通过 `project validate`；分配不同 workspace；原目录未修改；`uv sync && make check && doctor --json` | 不做远程 Git、Gradle、真实模型；只保留 Maven/local P0 |
| **7/21 周二** | B | CodeQL/SARIF 输入闭环 | Maven fixture；CodeQL command builder/runner；`scan`、`ingest-sarif`；SARIF runs/rules/results/locations/codeFlows/fingerprint；golden fixtures | golden SARIF 稳定输出 `NormalizedAlert`；单/多/无路径均测试；真实 CodeQL 可用时完成 smoke，不可用则明确报错 | 主 demo 使用 golden SARIF；不得伪造真实扫描 |
| **7/22 周三** | C | 路径上下文与证据契约 | ordered path；source/sink；path fingerprint；Java path-function slice；token estimate；Evidence/Claim Schema；artifact hash；悬空引用校验 | 每个 fixture 生成 `SliceArtifact`；source/sink/path 可定位；非法 evidence ID 被拒绝 | 使用 fixture 可验证的函数边界实现并声明限制；不得退化为整仓投喂 |
| **7/23 周四** | D | 二次筛选核心 | `StructuredLLM`；Fake/Replay；Analyst/Rebuttal/Judge；严格 JSON；deterministic policy | TP/FP/NMC 各一条 E2E；无决定性反证不得 FP；冲突/缺证据为 NMC | 不接真实 API；三角色顺序执行，不做自由辩论 |
| **7/24 周五** | E | 纵向闭环和报告 | `scan/ingest → normalize → context → triage → report`；JSONL/HTML；run manifest；`make demo` | 无网络、无 key 完成 demo；报告含 project/commit/tool/path/claims/evidence/unknowns；可 replay | 删除不稳定 P1；保留最小纵向链路 |
| **7/25 周六** | F | 质量、安全、文档冻结 | unit/golden/integration/E2E/security；prompt injection；malicious path/URI；symlink；HTML escaping；secret redaction；README/limitations | Ruff、mypy、pytest 全过；P0 核心覆盖率 ≥80%；**12:00 JST 后 feature freeze** | 删除 P1 功能补 P0 测试；带失败测试不得发布 |
| **7/26 周日** | G-RC | 干净环境复现与 RC | clean-room install；真实 CodeQL smoke；版本、schema、prompt、config lock；示例报告；release notes | `v0.1.0-rc1`；按 README 从空目录复现；无 P0 blocker | 移除破坏复现的可选功能；记录 limitation |
| **7/27 周一** | G-Release | 发布 `v0.1.0` | blocker 修复；最终回归；tag；source archive；示例 artifacts；测试摘要；后续 backlog | Release Checklist 全通过；第三方可重放证据链；不新增功能 | 未满足 P0 则不冒充发布；发布候选或明确延期记录 |

关键依赖：`A → B → C → D → E → F → G`。任何 Gate 未通过，后续只能做不依赖该 Gate 的文档/测试准备，不得跳过核心状态宣称全链路完成。

---

## 4. P0 工作分解

### A. 工程、ProjectSpec 与 Workspace

- [ ] `pyproject.toml`、`uv.lock`、Makefile；
- [ ] config schema、错误层次、结构化日志；
- [ ] `ProjectSpec`/`ProjectRegistry`；
- [ ] local source snapshot，正式实验 clean-tree 检查；
- [ ] `WorkspaceManager`：sources/build-copies/codeql-db/temp/locks；
- [ ] `artifacts/runs/<run_id>` 标准布局；
- [ ] canonicalization、越界拒绝、安全 cleanup；
- [ ] SQLite 最小 run/alert/evidence/decision 表；
- [ ] tool/config/prompt/schema manifest；
- [ ] `project validate`、`doctor`、CI；
- [ ] 两个不同项目配置切换测试。

### B. CodeQL/SARIF

- [ ] Java Maven/JDK 17 fixture；
- [ ] CodeQL `2.26.1` 版本检查和安全 command builder；
- [ ] timeout、退出码、stdout/stderr artifact；
- [ ] `scan` 与 `ingest-sarif`；
- [ ] rules/results/locations/relatedLocations；
- [ ] codeFlows/threadFlows；
- [ ] partialFingerprints；
- [ ] 单路径、多路径、无路径、恶意 URI fixtures。

### C. Context/Evidence

- [ ] source/sink/path step；
- [ ] stable alert/path fingerprint；
- [ ] Java path-function slice；
- [ ] token estimate 与 omitted reasons；
- [ ] EvidenceItem/Claim/FinalDecision Schema；
- [ ] stable evidence id、artifact SHA-256；
- [ ] dangling-reference validator；
- [ ] evidence graph JSON/DOT 最小输出。

### D. LLM/Agent/Policy

- [ ] `StructuredLLM` protocol；
- [ ] FakeLLM；
- [ ] ReplayLLM；
- [ ] request hash/cache；
- [ ] Analyst；
- [ ] Rebuttal；
- [ ] Judge；
- [ ] 每角色最多一次 schema repair；
- [ ] deterministic TP/FP/NMC policy；
- [ ] no decisive rebuttal → not FP；
- [ ] conflict/unresolved → NMC；
- [ ] 真实 API adapter 仅 P1，不阻塞首版。

### E. Report/Test/Security

- [ ] `alerts.jsonl`、`evidence.jsonl`、`decisions.jsonl`；
- [ ] `report.html`、`run-manifest.yaml`；
- [ ] CWE-22 TP/FP/NMC；
- [ ] CWE-78 TP/FP；
- [ ] prompt-injection case；
- [ ] original source unchanged test；
- [ ] workspace/path/symlink escape；
- [ ] HTML escaping、secret redaction；
- [ ] offline `make demo`；
- [ ] README、CHANGELOG、KNOWN_LIMITATIONS。

---

## 5. 每日收尾记录模板

```markdown
## YYYY-MM-DD（JST）

### 已完成
- [任务 ID / commit / PR] 工作项

### 可执行证据
- 命令：
- 退出码：
- 测试数与覆盖率：
- 工件路径：
- 关键 hash：

### 未完成/阻塞
- 问题：
- 影响 Gate：
- 真实原因：
- 已采用降级：
- 下一次决策点：

### 明日唯一主目标
- ...
```

禁止使用“完成 80%”代替可验证状态。

---

## 6. `v0.1.0` Release Checklist

### 功能

- [ ] 两个不同本地 ProjectSpec 通过同一 pipeline；
- [ ] 用户原始源码目录未修改；
- [ ] `project validate`、`doctor`、`scan`、`ingest-sarif`、`context build`、`triage`、`report` 有帮助和错误码；
- [ ] offline `make demo` 完成；
- [ ] 至少一个真实 CodeQL Java smoke 有日志，或明确记录外部环境阻塞；
- [ ] TP/FP/NMC 三类完整报告；
- [ ] 所有 claim/evidence 引用有效；
- [ ] 无决定性反证时无法输出 FP。

### 工程质量与安全

- [ ] Ruff、mypy strict、pytest 全过；
- [ ] P0 核心覆盖率 ≥80%；
- [ ] SARIF、policy、evidence、workspace、安全模块重点覆盖；
- [ ] EviTriage-QL subprocess 不使用 `shell=True`；CodeQL `--command` 仅从已验证 BuildPlan 安全序列化；
- [ ] 模型无 shell/Git/network/write 权限；
- [ ] prompt injection 不改变系统目标；
- [ ] path/URI/symlink/HTML/secret 测试通过；
- [ ] CI 无 API key、无付费模型、无公网依赖（除明确缓存安装步骤）。

### 可复现与科研

- [ ] CodeQL CLI/query/model pack 版本固定；
- [ ] ProjectSpec/config/prompt/schema/tool digests 入 manifest；
- [ ] 原始 SARIF、normalized alert、slice、evidence、decision、report 可关联；
- [ ] 相同 replay 输入产生相同结构化结果；
- [ ] README 五分钟 quickstart；
- [ ] CHANGELOG、KNOWN_LIMITATIONS、release notes；
- [ ] 不把微型 case 结果宣传为真实项目泛化性能；
- [ ] tag `v0.1.0`。

---

## 7. 风险触发与强制降级

| 风险 | 触发点 | 必须处理 | 禁止做法 |
|---|---|---|---|
| ProjectSpec/Workspace 未稳定 | 7/20 晚 | 只支持 local + copy snapshot；去掉 remote/复杂缓存 | 直接扫描并修改用户原目录 |
| CodeQL 安装或数据库创建阻塞 | 7/21 晚 | 主 demo 使用 golden SARIF；保留 runner/真实错误；7/26 手工 smoke | 伪造真实扫描成功 |
| 函数切片阻塞 | 7/22 晚 | 对 fixture 实现可验证函数范围并明确 limitation | 默认整仓输入模型却称为切片 |
| Agent 输出不稳定 | 7/23 晚 | 强 Schema、一次 repair、Replay 主演示、policy 门控 | 人工改模型结果或放松证据约束 |
| 真实模型 API 不可用 | 任意时间 | 不影响首版；保留接口，延期到 V0.4 | 把 API key/公网模型设为 CI 条件 |
| 测试不足 | 7/25 12:00 | feature freeze，删除 P1，集中补测试 | 带失败测试发布 |
| Clean-room 失败 | 7/26 晚 | 删除破坏性可选功能，保留 P0 | 只在开发机演示并宣称可复现 |

不可裁剪：ProjectSpec/隔离 workspace、SARIF normalize、Evidence/Claim Schema、TP/FP/NMC、deterministic policy、Fake/Replay、离线 E2E、测试和 manifest。

---

## 8. 7 月 27 日后的版本门

| 时间 | 版本 | 重点交付 | 进入条件 |
|---|---|---|---|
| 7/28—8/10 | `v0.2.0` | Git 固定 commit checkout；Maven/Gradle/JDK adapters；真实 CodeQL 多仓 smoke；更多 SARIF/microbench | v0.1 可离线重放 |
| 8/11—8/24 | `v0.3.0` | Tree-sitter/helper query 高保真切片；guard/sanitizer/caller/callee；NMC context planner | SARIF/证据接口稳定 |
| 8/25—9/7 | `v0.4.0` | 真实 HTTP 模型 API；本地/远程 profile；单 LLM/单 Agent/三 Agent 基线；成本与重复性 | 数据策略和 Replay 完整 |
| 9/8—9/21 | `v0.5.0` | Java sandbox verifier；OWASP/Vul4J/CWE-Bench-Java 小规模 adapter；选择性验证 | Agent/Policy 基线可评估 |
| 9/22—10/5 | `v0.6.0` | 双人标注；project-disjoint/chronological split；metrics/bootstrap/McNemar；校准与消融 | 数据切分冻结 |
| 10/6—10/12 | `v1.0.0-research` | 主实验、案例研究、复现脚本、论文表格、artifact README、论文初稿 | 所有主要 Gate 可重放 |

---

## 9. 发布日决策规则

2026-07-27 只允许：

- 修复 P0 blocker；
- 补充测试、文档、release notes；
- 删除不稳定的 P1；
- 执行最终验收和打 tag。

不得在发布日加入真实模型 API、自适应上下文、动态验证、GitHub 回写或新语言。若 P0 未满足，应诚实保留 `rc` 或记录延期原因，不得用假数据或手工修改结果制造“已完成”。
