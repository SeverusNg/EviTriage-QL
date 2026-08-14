# 变更日志

[English](CHANGELOG.md) | [简体中文](CHANGELOG.zh-CN.md)

本文件记录项目的重要变更，格式遵循
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，正式版本遵循
[语义化版本](https://semver.org/)。英文文件保留历史逐条原始记录；本文件对
当前变更逐项翻译，并按相同版本和类别完整保留历史版本的能力与安全边界。

## [未发布]

### 新增

- 按四个精确 Java 资源泄露 rule ID 分派，并增加独立严格的
  `resource-leak-1.0` Analyst/Rebuttal/Judge 契约。
- 增加受限 Java 生命周期证据：完整 enclosing method、获取/释放/退出候选、
  同文件一跳 callee 和显式 omission；仓库文本始终是不可信惰性数据。
- 增加保守资源 TP/FP/NMC 策略，并覆盖 TWR、`finally`、提前退出、多资源顺序
  close 失败、锁、所有权转移、未知 callee/框架、Prompt injection、schema
  repair 和证据 ID 的测试。
- 增加严格 manifest 驱动的 existing-SARIF `preflight`/`run`/`evaluate`、逐 case
  run 隔离、零结果闭合、历史前后比较、中英聚合报告和固化后 V1 基线评估。
- 在 `experiments/` 下增加可安全提交的 RocketMQ V2 实验包，包含冻结输入
  身份、脱敏结果/run 索引、双语报告和目录级 SHA-256 校验；含源码的原始产物
  继续保持 Git 忽略。

### 变更

- 资源 rule 使用独立模型和工作流，保持 legacy security schema 与 canonical
  Replay 身份不变。
- DeepSeek 传输对网络错误、429 和 5xx 使用有限重试；401/403 永不重试。
- batch 失败保持结构化失败并使实验 incomplete；已成功 sibling 决策仍进入
  聚合，绝不被伪造的 NMC 替换。
- 在资源 JSON Schema 中显式暴露非空证据引用，并把有界字段级校验问题传给
  唯一一次 repair；该修复没有放宽证据闭合，也没有改变 legacy 请求身份。

### 安全

- preflight 在解析凭据前验证全部 source commit/clean 状态、SARIF hash/计数、
  查询族、ProjectSpec 和输出根。
- V1 人工标签只能由独立评估命令在自动决策不可变后打开，绝不发送给模型。
- 私有目标路径、源码、SARIF、凭据、真实模型流量、workspace 和 artifact
  继续排除在 Git 外。

## [0.2.0] - 2026-07-23

### 新增

- 通过 `EnvironmentCredentialProvider`、`SystemdCredentialProvider`、
  `PassCredentialProvider` 和 `CredentialResolver` 增加 provider-neutral
  DeepSeek 凭据发现与加载。
- 增加 `triage --credential-provider environment|systemd-creds|pass|auto`、固定
  auto 优先级、非秘密逐 provider JSON status 和隐藏双重提示的 pass/GPG 录入。

### 变更

- 凭据选择移出 `DeepSeekLLM`；adapter 只接收已验证的内存 Key，并只负责固定
  官方 HTTPS 请求边界。
- 保留 TPM2/systemd 固定路径和旧录入行为，同时把 pass 记录为 WSL 持久方案、
  environment 记录为单进程方案。

### 安全

- pass 只使用固定 `evitriage/deepseek-api-key` entry、严格 ASCII 路径、经过
  ownership/mode 验证的可执行文件、固定 argv、有界输出/超时、stdin 录入和
  基于 pwd 的最小子进程环境；不传递 extension、proxy、token 或 API Key。
- auto 在任何已配置 provider 数据畸形、权限不安全或加载/解密失败后停止。
  测试使用注入 runner 和模拟 HTTPS，验证 Key 不进入 argv、环境、status、
  exception、log 或文件。

## [0.1.0] - 2026-07-23

### 变更

- 离线 demo 扩展为固定六案例矩阵：CWE-22 TP/FP/NMC、CWE-78 TP/FP 和 Prompt
  injection，共 18 次 identity-bound Replay 调用且不自动关闭告警；Maven fixture
  使用自身 Maven 3.9.9/SHA 固定 wrapper，真实 CodeQL 扫描结果与六条合成决策
  fixture 严格分离。
- Git/source-distribution secret scan、版本/CITATION、确定性请求前脱敏、
  `uv 0.8.3` 可执行版本门、持久工具部署、Java/CodeQL 环境证据和
  `security-extended` bundle suite 映射得到加固。
- SARIF 边界要求非空 run 的 `columnKind`，支持精确 `%SRCROOT%` 约定和
  `endLine=startLine` 默认；Java 词法 callable 不再把 `try` 控制头当作声明。
- 缺失 DeepSeek 凭据测试与操作员持久 store 隔离；一次经授权 TPM2 DeepSeek
  smoke 接受三角色响应并对合成 fixture 保守输出 NMC。这是 live path 证据，
  不是质量基准。

### 新增

- Gate A 工程基础：Python package/CLI、严格本地 ProjectSpec、受管 workspace、
  `doctor --json`、SQLite migration、Ruff/mypy/pytest/coverage/CI、初始架构/
  安全/进展/限制文档。
- Gate B 输入闭合：`scan`、`ingest-sarif`、`normalize` 共用确定性 normalizer；
  固定版本 CodeQL runner、Maven Wrapper-only argv、相同 JDK 校验、timeout、
  结构化失败、hash 日志；真实 CodeQL 2.26.1/Java 17 零结果 smoke；严格 SARIF
  2.1.0 子集、Golden fixtures、raw occurrence 身份、run journal/manifest、
  wrapper/query pack pin 和失败产物。
- Gate C 上下文/证据：Level 0 元数据、受限 `fixed_window` 与 Java
  `path_function_slice`、每告警 SliceArtifact、坐标/token/omission、严格
  Evidence Registry/Claim、Graphviz 与转义导航、共享 `CONTEXT_READY` 流水线；
  Gate C-Extra 原创 Socket-to-path CWE-22 案例产生一条真实八步
  `java/path-injection` 并以只读 artifact 固化。
- Gate D 模型/策略：provider-neutral `StructuredLLM`、有序 Fake/Replay、严格
  Claim/Analyst/Rebuttal/Judge/FinalDecision/invocation/stage/TriageResult schema；
  每角色最多一次 repair、每告警最多六次调用、exact occurrence 证据闭合、
  content-derived Claim/analysis ID、保守 TP/FP/NMC、`auto_dismiss=false`、
  MODEL_FAILED/POLICY_REJECTED 终态和 existing-SARIF `triage` CLI。
- 可选 DeepSeek V4-Pro/Flash 官方 HTTPS adapter、显式 remote policy、无凭据
  Profile、commit-eligible secret scanner，以及 Linux TPM2/systemd 隐藏录入和
  内存解密管道；environment 仅作单进程 fallback。
- Gate E 报告/演示：每条告警严格 JSONL 和自包含转义 HTML、AlertReport/
  TriageReportBundle schema、reports artifact 与完整 provenance、固定合成 NMC
  Replay、无需 CodeQL/Key/网络/真实模型的 `make demo`、隔离 checkout E2E、
  identity-bound EvidenceSupplement，以及三案例 TP/FP/NMC 后扩展到六案例闭合；
  `triage --scan` 也通过受控 runner 走到报告。
- Gate F/G：可直接选择的 `security`/`golden`/`e2e` 测试与
  `make security-test`，攻击类别矩阵、请求前与 provider 边界脱敏；严格六案例
  manifest/Java 17 compile、release assembler、reviewed JSONL/HTML/run manifest、
  真实 full/security pytest summary、wheel/sdist/依赖清单/CycloneDX SBOM、
  prompt/schema/version freeze、`release-manifest.json` 和 `SHA256SUMS` 验证。

### 安全

- repository/SARIF/model 文本只作为 `untrusted_code_data`；凭据形状在进入
  Fake/Replay/remote 请求前脱敏，DeepSeek HTTPS body 再检查一次。Prompt
  injection、恶意 URI、path/symlink escape、HTML escape、shell metacharacter、
  secret redaction 均有回归测试，subprocess 始终 `shell=False`。
- 本地源码只读且与 writable run 区隔离；workspace owner-only、content-addressed、
  copy-only、复制前复核、资源有界，并只凭 ownership descriptor 清理。Gradle/
  explicit shell、空 allowlist、parent traversal、root symlink 和 source collision
  均 fail closed。
- SARIF no-follow/有界读取，拒绝远程/UNC/traversal/symlink URI；已有源码独立
  SHA 校验，缺失源码明确 unknown；raw bytes 原样复制，run/result index 与重复
  occurrence/path 全保留。外部工具使用固定 argv、最小 env、长度限制与脱敏，
  缺工具/版本错/timeout/非零/畸形输出均是失败而非假成功。
- finalization 重开并复核每个 artifact 的 size/hash，再设 `0400`。上下文只读
  snapshot-relative regular UTF-8 文件，binary/oversize/coordinate/digest/budget
  问题显式 omission；坐标遵循 SARIF UTF-16 或 Unicode code point，BOM 不偏移。
- 模型只能引用 exact occurrence 的注册 evidence/claim；未知 ID 最多一次 repair。
  EvidenceSupplement no-follow、有界、严格绑定且不能直接设置 label。Replay cache
  只读 no-follow；DeepSeek 固定 `api.deepseek.com:443` Bearer header、丢弃错误 body，
  并要求 ProjectSpec/Profile 双重 remote policy。HTML 转义所有不可信文本，报告
  hash 注册、只读且不能启用自动 dismiss。

### 尚未实现或验证

- v0.1 之后仍缺少独立 `report --run-id`、通用可信 Replay writer/producer
  attestation、prior-run continuation 和新的真实 CodeQL scan-to-`JUDGED` artifact。
- DeepSeek V4 之外的 provider、remote Git/dataset、Gradle/其他语言、adaptive
  context、选择性 verification、calibration、广泛实验、PostgreSQL/GitHub 告警
  集成以及独立准确率证据均不在该版本内。
