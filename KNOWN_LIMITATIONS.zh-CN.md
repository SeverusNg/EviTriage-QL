# 已知限制

[English](KNOWN_LIMITATIONS.md) | [简体中文](KNOWN_LIMITATIONS.zh-CN.md)

本文描述的是 **Gate F 加固离线 P0 纵向路径上的 v0.1.0 Gate G 版本**：
集成报告、两种全新研判输入、确定性的六案例离线矩阵、可单独选择的攻击类别
套件，以及已验证的 wheel/sdist/SBOM/示例/测试发布证据。以下条目是有意的
范围边界或尚未解决的验证缺口，不应据此推断完整的 v0.1 研究工作流已经存在。

## 功能边界

- 只能物化本地 ProjectSpec 目标。schema 为向前兼容保留了带类型的 Git/
  dataset 身份，但远程 checkout、数据集获取和 submodule 物化均不可用。
- 本地快照只支持 `snapshot_mode: copy`；Git worktree、硬链接及其他获取/
  物化策略均被拒绝。
- `require_clean_git` 只作为配置元数据校验；本地输入路径不会调用 Git 或
  计算 dirty patch 摘要，而以完整源码树 SHA-256 标识本地快照。
- Gate B 扫描只支持使用已检入 `./mvnw` 或 `./mvnw.cmd` 的 Maven 适配器。
  该显式配置且经过校验的 wrapper 是唯一会执行的仓库脚本；裸机 Maven、
  Gradle、显式适配器及任意/未配置脚本均被拒绝。两个示例通过 Maven Wrapper
  3.3.4 声明 Maven 3.9.9，并以 `--offline` 运行。
- wrapper 缓存为空时可能需要一次性下载 Maven 分发包。离线 Golden SARIF
  路径不会执行该 bootstrap，离线真实扫描前必须另行准备。
- Maven 3.9.9 及其校验和是 wrapper properties 的声明值，不是观察到的
  运行时工具身份。Gate B 不运行 `mvnw --version`，不哈希既有缓存分发包，
  也不证明缓存符合声明校验和；缓存完整性是外部供应链前置条件。
- 最初的 Gate B CodeQL CLI `2.26.1`/Java 17 冒烟产生了含 120 个规则描述符、
  零结果的有效 SARIF。Gate C-Extra 又对 SHA 绑定的 Socket 案例执行独立
  真实扫描，产生一条 `java/path-injection`、完整八步路径及完整上下文并
  到达 `CONTEXT_READY`。这些特定环境运行只验证 runner/query/pipeline
  组合，不是 EviTriage 分类、可利用性证明、任意仓库证据或洁净环境复现。
  Golden SARIF 是独立合成输入，不是任一运行的捕获输出。
- 内置 `security-extended` 简写目前只映射 v0.1 `java-kotlin` 路径。新增
  CodeQL 语言需要显式且经过测试的 bundle-suite 映射，不能猜 pack 或文件名。
- SARIF 解析器只归一化受支持的 SARIF 2.1.0 子集：runs、driver rules、
  results、artifacts、URI bases、物理/关联位置、code/thread flows、
  fingerprints 和 properties。未知扩展字段会忽略；非空结果 run 缺少
  `columnKind`、列单位不支持或结果没有可解析物理源码位置时会拒绝而非猜测。
  精确且不区分大小写的 `%SRCROOT%` 约定映射到已校验快照根，其他未声明 URI
  base 被拒绝；有 `endColumn` 而无 `endLine` 时使用 SARIF 同行默认值。
- `ingest-sarif` 需要选定本地源码树，以便相对于已校验快照根解释源码 URI。
  Gate B 不证明所选源码版本生成了该 SARIF，也不要求所有引用文件存在；
  它不是无源码 SARIF 查看器，源码/SARIF 对应关系仍由操作者提供来源证明。
- Gate C 的 Java callable 边界查找器是无依赖词法提取器，不是 AST/CFG 或
  编译器分析。它能处理检入夹具并忽略注释/字符串中的大括号，但复杂 Java
  语法可能以 `function_boundary_unresolved` 回退固定窗口；不会推断缺失
  CodeQL 边或语义可达性。
- Gate C 只接受最大 1 MiB 的有界普通 UTF-8 源文件。token 估算为 UTF-8
  字节数除以四，不是提供方 tokenizer；默认每告警预算为估算 24,000 token。
- Level 1 尚不包含 caller/callee 扩展、AST 解析 guard、sanitizer 定义、
  配置/测试摘要、override、框架绑定或动态分派。词法匹配的 guard/sanitizer
  行明确只是中性候选；`adaptive_slice` 返回 `FEATURE_NOT_AVAILABLE`。
- 源码缺失、二进制、过大、被修改、越界或超预算时，会生成带哈希和遗漏项的
  `partial` SliceArtifact；不会让告警消失，也不会伪造源码。上下文提取按
  run 声明的 UTF-16 code unit 或 Unicode code point 单位检查现有位置，
  缺失文件保持未知。开头 UTF-8 BOM 不进入坐标/摘录文本，但仍计入原始产物
  摘要。不会推断视觉列或 tab 展开，因为 SARIF 列是计量单位，不是渲染偏移。
- Evidence Registry 和 Claim schema 强制产物/证据引用，但 Gate C 只生成
  证据，不生成 claim。DOT 图和转义源码映射 HTML 是导航产物，不是漏洞报告。
- 有界 Python 核心已实现 `FakeLLM`、只读 `ReplayLLM`、严格 Agent/决策
  schema、有序 Analyst/Rebuttal/Judge 工作流及确定性策略。Replay 消费
  可信 `<request-sha256>.json`。仓库只提供固定合成、带 SHA-256 清单的
  演示包（含 TP/FP/NMC），不提供通用缓存写入器、外部生产方证明、token
  用量或延迟测量。
- 可选 DeepSeek 适配器只支持固定官方 `api.deepseek.com:443` Chat
  Completions 端点上的 `deepseek-v4-pro` 和 `deepseek-v4-flash`。独立凭据
  解析器接受单进程 `DEEPSEEK_API_KEY`、固定 TPM2/systemd 加密存储或固定
  `evitriage/deepseek-api-key` pass/GPG 条目。自动发现顺序为 environment、
  systemd-creds、pass；任一已选提供方校验/解密失败都会停止。远程使用仍
  要求 LLM Profile 和 ProjectSpec 同时精确声明 `remote_llm_allowed`。
  检入验收测试只使用模拟 HTTPS。另行授权的 2026-07-23 在线冒烟验证了
  TPM2 凭据路径、当时账号/模型访问、三个已接受角色响应以及一个合成夹具的
  `JUDGED` 运行；未记录 token/账单，未测试重试/限流/错误，未证明持续
  可用性，也未基准测试输出质量和准确率。
- 原生 Linux 可使用 `systemd-creds`、可用 TPM2 设备及 `/dev/tpmrm0`
  操作者权限；前置条件、root 所有工具、私有 ownership 或 `0600`/`0400`
  密文权限缺失时录入会失败关闭。WSL 和原生 Linux 也可使用标准 pass/GPG，
  但操作者须初始化 `~/.password-store` 并维护受口令保护的 GPG 私钥。
  没有 macOS/Windows keychain、Vault 或云 secret manager 适配器。
- `triage` 接受既有 SARIF 或新 CodeQL 扫描二选一并搭配可信 LLM profile，
  分配新运行、复用 Gate B/C 路径并持久化
  `ANALYZED → REBUTTED → JUDGED`。扫描形式有受控 runner 集成覆盖，但不
  声称存在全新真实 CodeQL scan-to-`JUDGED` 产物。它不能按 `run_id` 继续
  已最终化 Gate C 运行；独立 `scan`/`ingest-sarif` 仍如实停止于
  `CONTEXT_READY`。
- 可选补充证据是可信操作者/测试 assertion，不是独立验证事实或人工标签。
  严格输入绑定项目、快照、SARIF 和精确出现位置，经保留及哈希注册，且不能
  直接设置 Claim 或标签。这能暴露来源并防止意外跨运行使用，却不能证明
  生产方 assertion 为真；验证沙箱和人工审阅证明尚未实现。
- 合成 Gate D 测试覆盖 TP、决定性 FP、冲突 NMC 和缺少决定性反驳时降级。
  它们是策略/适配器测试证据，不是 Java 夹具或早先 CodeQL 结果的漏洞结论。
- 成功的新 `triage` 会在最终化前写入并注册 `reports/decisions.jsonl` 和
  `reports/index.html`。没有独立 `report --run-id`、跨运行聚合、CSV/
  Markdown 导出，也不能向已最终化 Gate C/D 运行附加报告。任何组件都不会
  自动关闭上游告警；`FinalDecision.auto_dismiss` 在结构上固定为 `false`。
- 报告 JSONL 有意包含可重放审计所需的有界 SliceArtifact 和证据，可能带
  源码摘录，必须采用与源码快照相同的保密控制。HTML 转义不可信内容以阻止
  活跃标记，但转义不是内容脱敏，也不授权发布敏感代码。
- 工作流 payload 和 DeepSeek 提供方边界都会应用凭据模式脱敏，但这不是
  通用秘密分类器，可能漏掉新型或无标签格式。本地源码、SARIF、slice、
  evidence 和 JSONL 产物有意不改写，仍受被分析源码的保密要求约束。
- `make demo` 无需 Java、CodeQL、API 密钥、网络或真实模型即可完成六个
  既有 SARIF 案例，输出三 TP、两 FP、一 NMC。CWE-22 TP/FP/NMC、CWE-78
  TP/FP、提示词注入证据补充和 Replay 响应均为合成测试 oracle，不是独立
  验证的漏洞标签或准确率数据。验证沙箱、校准、基准数据集、论文统计、
  PostgreSQL 和 GitHub 告警集成仍属后续里程碑。

## 运行边界

- `make release-artifacts` 创建并哈希闭合 wheel、sdist、all-extras 依赖
  清单、CycloneDX 1.5 SBOM、六案例摘要、经审阅示例 JSONL/HTML/run
  manifest 以及机器可读完整/安全 pytest 摘要。它不签名或发布、不证明
  构建主机，也不审计依赖许可证/漏洞。SBOM 第三方组件数据和 sdist 哈希
  来自 `uv.lock`；只声明本项目自身 Apache-2.0 许可证。
- 一次在新目录中的源码分发包洁净运行已通过离线缓存安装、`make check` 和
  `make demo`。这是同主机复现，不是第二主机/容器结果。首次离线尝试如实
  因缓存缺少 mypy wheel 失败；常规锁定网络同步填充后，第二个新目录离线
  安装。首次 sdist `make check` 也暴露并修复了仅 Git 环境的秘密扫描阻塞。
- `pyproject.toml` 强制 `uv 0.8.3`，但仓库不 vendoring uv 可执行文件或
  安装器。操作者必须将固定版本安装在持久位置、验证上游完整性并暴露到
  login-shell `PATH`；临时 bootstrap 不算洁净环境证据。升级 uv 必须同时
  更新 pin、lock、文档和证据。
- SQLite 仍是刻意最小化的本地元数据后端。Gate C 审计产物和工作流状态按
  运行存于文件；归一化告警和事件尚未在 SQLite 中事务性索引。
- 每次运行的 `workflow-events.jsonl` 仅追加；`run-manifest.json` 是经校验
  状态转换后重写的当前摘要，不能解释为仅追加数据库日志。最终化会复验
  所有注册产物大小/摘要，并把产物及审计文件设为仅所有者可读。
- CLI 始终分配新运行，不接受调用方提供的 run ID 或幂等键。`RunJournal`
  拒绝既有审计文件而非续接，因此未实现崩溃恢复、完成状态重放和单运行
  多进程续接。
- 归一化/domain `run_id` 是基于源码快照、原始 SARIF、commit 和归一化器
  版本的内容派生 `analysis_identity`；manifest `run_id` 是不同的操作执行
  标识。Replay 哈希要跨新运行稳定就需要该区分，但调用方不得把分析身份
  当作仅追加执行记录。
- 仅所有者可读权限和内容哈希能检测意外修改，但不是防篡改账本：文件所有者
  或 root 可改权限并重写产物。研究留存应把完成运行复制到独立控制、内容
  寻址的归档。
- 已裁决 manifest 覆盖输入、归一化、上下文、证据、模型阶段、决策和报告
  产物哈希。调用记录保留提示词/请求/响应哈希以及 provider profile/model
  身份，但不保留原始提示词、原始 Replay 条目或 token/延迟观察。manifest
  不证明 Replay 条目由谁生成。
- DeepSeek 运行会把选定证据 payload（含有界源码摘录）发送给外部提供方。
  TLS 和显式上传策略可减少意外泄露，但无法对 DeepSeek 保密，也不能消除
  提供方留存/司法辖区风险。策略或合同禁止上传的源码不得使用远程 profile。
- API 密钥不会进入模型消息或运行产物，提供方错误 body 会丢弃；但它仍会
  短暂存在于进程内存和出站 Authorization header，environment 模式还会
  暴露于该进程环境。TPM2 只保护离机密文，不防已授权同用户进程；pass 用
  GPG 保护存储条目，但 gpg-agent 可能缓存已解锁私钥能力供同用户进程使用。
  root 检查、运行时入侵、shell tracing、GPG agent 或提供方入侵不在本
  仓库保护边界内；不声称“绝对安全”。
- Secret Service/Python keyring 不是 WSL、CI、SSH 或无头环境的可靠默认
  方案，因为桌面 D-Bus 会话和已解锁 keyring 可能不存在。这不表示 pass/
  GPG 普遍更强；它只是当前跨 WSL/Linux 的实现选择，也有自身密钥和 agent
  管理要求。
- 可提交文件秘密扫描能识别 DeepSeek assignment、常见 `sk-...` token 和
  私钥块，但模式扫描不能证明不存在所有凭据格式；仍需人工审阅及提供方侧
  密钥轮换/撤销。
- 公共 Pydantic 记录禁止顶层字段重新赋值，但 fingerprints、properties、
  tool versions 等嵌套 mapping 是普通可变 Python dict。调用方不能把进程
  内对象视为深度不可变；序列化产物加 SHA-256 才是当前复现边界。
- runner 以同一主机用户直接执行仓库 `mvnw`。受管路径、wrapper 校验、
  参数向量执行和超时不构成操作系统沙箱。没有 container/cgroup CPU、内存、
  进程数配额；`network_policy: disabled` 尚不是 OS 强制网络 namespace；
  超时不保证终止全部后代进程。当前 `capture_output` 还可能在写入有界脱敏
  产物前把无限目标 stdout/stderr 保留在内存。提供外部隔离和资源控制前，
  只能扫描可信夹具/仓库。
- 子进程环境白名单排除 API/GitHub/SSH/proxy 环境变量，但为工具运行保留
  `HOME` 等平台变量。没有文件系统沙箱时，目标构建仍可读取主机用户可访问
  文件，如 Maven settings 或主目录凭据。真实扫描应使用一次性、外部隔离
  的执行账户和 home。
- 诊断只证明工具可发现；单元/集成 double 只证明 runner 行为。两者都不能
  证明外部 CodeQL 可成功分析任意仓库。
- 尚未实现 dry-run/build-plan 命令。会记录 query suite 和 pack 参数，
  可选 query/model pack 要求精确语义版本 pin，但本地解析 pack 的 lock/
  content 摘要及 CodeQL database 元数据清单尚不足以构成完整研究来源。
- 会独立计算快照中被引用普通文件的 SHA-256，并拒绝冲突 SARIF 声明。
  缺失引用文件仍允许，且无已验证归一化摘要。Gate C 只检查能安全打开的
  源文件坐标；缺失文件保持未知/未验证区别。
- SARIF 输入上限 128 MiB，归一化上限 100,000 个结果和 100,000 个路径
  step，源码快照另有条目/深度/字节限制。超大型生产分析可能需要显式调整
  策略。
- 示例夹具只展示配置切换、隔离和预期 CWE-22/CWE-78 source 模式，不是
  代表性漏洞基准。Gate D 集成 NMC 来自合成 Replay 响应，不是外部验证标签。
- Gate C-Extra 只覆盖一个真实查询阳性的 CWE-22 路径。已完成的六案例发布
  矩阵使用合成 Golden SARIF、测试观察和 Replay 响应；两者都不能证明对
  公开或真实项目基准的泛化。
- 不应推断存在托管 CI 结果、第二主机洁净结果或合并的洁净环境真实工具复现。
  带日期进度日志记录了一次同主机 sdist check/demo 和一次独立全新真实
  CodeQL 冒烟的实际命令、退出码、版本和产物哈希。

## 安全与研究解释

- `license_hint` 是操作者提供的元数据，不是法律建议或自动许可证验证。
  Maven Wrapper 启动器保留自身 Apache-2.0 来源；CodeQL 和 Maven 分发包
  仍为外部工具。
- ProjectSpec 校验成功只表示配置满足当前信任边界约束；归一化成功只表示
  SARIF 事实被确定性表达。两者都不说明目标安全或告警可利用。
- 稳定的告警/路径 fingerprint 标识归一化内容和出现位置，不是跨任意仓库
  版本的漏洞身份。
- 本软件是预发布研究基础设施。不得把它作为漏洞披露、告警关闭或生产风险
  接受的唯一依据。

只有在同一变更中加入相应能力的有效实现、测试和复现证据后，才能移除这些
限制。
