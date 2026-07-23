# EviTriage-QL 部署与运行攻略

[English](deployment-guide.md) | [简体中文](deployment-guide.zh-CN.md)

本文面向第一次接触本项目的操作者，说明怎样把 EviTriage-QL 从检出目录
部署成可用的本地命令行工具，并逐步跑通离线演示、已有 SARIF 导入、真实
CodeQL 扫描和可选的 DeepSeek 研判。

当前版本是研究型 CLI，不是 Web 服务：没有监听端口、后台 daemon、任务队列
或多用户控制台，也不需要外部数据库服务器。每条命令创建一个新的、可审计的
运行目录；元数据数据库若需要则使用本地 SQLite。不要把“部署”理解为启动一个
长期在线的漏洞自动处置服务。

## 1. 先选择要跑的路径

建议始终从第一行开始，逐级增加外部工具、网络和数据暴露面。

| 路径 | 能证明什么 | 额外依赖 | 成功终态 |
| --- | --- | --- | --- |
| `make demo` | 六个合成案例的完整流水线和确定性报告可复现 | 无 Java、CodeQL、API Key 或真实模型 | `JUDGED` |
| `ingest-sarif` | 已有 SARIF 可被保存、标准化并绑定源码上下文/证据 | 与 SARIF 对应的本地源码 | `CONTEXT_READY` |
| `triage --sarif` + Replay | 已有 SARIF 可经过三 Agent 和保守策略 | 与精确请求哈希匹配的可信只读 Replay 缓存 | `JUDGED` |
| `scan` | 真实 CodeQL 可以构建项目、产生 SARIF 并提取上下文 | JDK 17、CodeQL 2.26.1、Maven 3.9.9 缓存 | `CONTEXT_READY` |
| `triage --scan` | 在一次新运行中从真实扫描继续到报告 | 真实扫描环境，加 Replay 缓存或已授权的 DeepSeek | `JUDGED` |
| DeepSeek `triage` | 受控证据可发送到固定远程模型端点完成三阶段研判 | 网络、显式上传策略和安全交接的 API Key | `JUDGED` |

`TP`、`FP` 和 `NMC` 是二次研判标签。无论标签是什么，
`auto_dismiss` 永远为 `false`；系统不会自动关闭 CodeQL 告警。Golden SARIF、
Replay 响应和证据补充都是合成夹具，不能被解释为真实项目准确率。

## 2. 部署拓扑与目录

推荐把检出目录、输入源码和运行输出视为三个不同的安全域：

```text
EviTriage-QL checkout
├── src/、configs/、tests/       # 程序、可信配置示例和合成夹具
├── .venv/                      # uv 管理的 Python 环境
├── workspaces/                 # 只读源码快照、构建副本、CodeQL 数据库
└── artifacts/
    ├── evitriage.db            # 可选的本地 SQLite 元数据
    └── runs/<run-id>/          # SARIF、证据、模型阶段、报告和 manifest

/path/to/target-source/          # 操作者提供的输入，只读对待
~/.local/share/... 或
~/.password-store/...           # 可选的仓库外加密凭据
```

默认的 `workspaces/`、`artifacts/` 和秘密相关文件都被 Git 忽略。它们可能
包含私有源码、SARIF、源码摘录和模型输出，必须使用与目标源码相同或更高的
访问控制。不要把这些目录放进公开制品、普通 CI 日志或源代码提交。

一次成功的完整研判通常产生：

```text
artifacts/runs/<run-id>/
├── workflow-events.jsonl
├── run-manifest.json
├── input/source.sarif 或 codeql/results.sarif
├── normalized/alerts.json
├── context/
├── evidence/
├── triage/{analyst,rebuttal,judged}.json
└── reports/{decisions.jsonl,index.html}
```

最终化时，注册产物、事件日志和 manifest 会被复验 SHA-256 并设成仅所有者
可读（`0400`）。这不是权限故障，不要为了方便查看而批量放宽权限。

## 3. 基础环境

### 必需组件

- Linux 或 WSL shell；
- Python 3.12；项目元数据允许 `>=3.12,<3.14`，当前验收环境使用 3.12；
- 持久安装并能从全新 login shell 的 `PATH` 找到的 `uv 0.8.3`；
- GNU Make 或兼容的 `make`；
- 足够容纳依赖、源码副本和运行产物的本地磁盘。

`pyproject.toml` 会拒绝不是 `0.8.3` 的 uv。可以通过 uv 的官方安装方式或
受控的软件包管理器安装，但最终必须验证实际解析到的可执行文件；放在
`/tmp` 的临时 bootstrap 不算完成部署。

```bash
cd /path/to/EviTriage-QL

python3 --version
command -v uv
uv --version
make --version
```

预期 `uv --version` 输出 `uv 0.8.3`。第一次同步依赖可能访问 Python 包索引；
若组织要求离线安装，应提前准备 uv 缓存或从经过验证的源码分发包和锁定依赖
建立内部镜像。依赖就绪后，演示和默认测试不会访问模型服务。

```bash
uv sync --all-extras
uv run --offline evitriage version
```

如果部署需要 Gate A 本地元数据表，可显式初始化或升级受管 SQLite：

```bash
uv run evitriage db migrate --json
```

默认文件是 `artifacts/evitriage.db`，权限为 `0600`。离线演示、SARIF 产物和
run manifest 仍各自保存在运行目录中；这条迁移命令不会把项目变成数据库
服务，也不需要独立的数据库进程。

应从仓库根目录运行命令。若确实需要从其他目录调用，可把
`EVITRIAGE_PROJECT_ROOT` 设置为当前 EviTriage-QL 根目录；不要让不可信项目
控制这个变量。

## 4. 第一次启动：完全离线跑通

先运行环境诊断，再运行完整质量门禁和演示：

```bash
uv run evitriage doctor --json
make check
make security-test
make demo
```

- `doctor` 会如实报告 Python、uv、SQLite、受管目录、Java、`javac` 和
  CodeQL 状态。离线演示中 Java/CodeQL 缺失可以接受，真实扫描中则不可以。
- `make check` 包含锁文件、格式、lint、mypy、schema、秘密扫描、pytest 和
  分支覆盖率门禁。
- `make security-test` 单独运行提示词注入、恶意 URI、路径/符号链接、
  HTML 转义、shell 元字符和秘密脱敏安全回归。
- `make demo` 使用固定 Replay 数据，不读取 API Key，也不发起模型网络请求。

成功的 `make demo` 应输出一个 JSON `TriageRunSummary`，主要特征是：

- `state` 为 `JUDGED`；
- `real_codeql` 为 `false`；
- 共六条告警，结果为三个 `TP`、两个 `FP`、一个 `NMC`；
- 共十八次 Replay 调用；
- `artifact_run_root` 指向本次运行的审计目录。

打开 `artifact_run_root/reports/index.html` 可以查看自包含的转义报告；
`reports/decisions.jsonl` 适合机器处理。报告中的标签是固定合成案例的
可复现性证据，不是模型质量基准。

## 5. 接入已有 SARIF

这是接入自有项目成本最低、风险最小的路径。它不执行目标项目构建，也不需要
CodeQL 或模型，但操作者必须提供**产生该 SARIF 时对应版本的源码**。

### 5.1 创建项目配置

从最接近的示例复制一份私有 ProjectSpec，例如
`configs/projects/example-local.yaml`。建议私有文件命名为
`configs/projects/private-<name>.yaml`；该模式已被 Git 忽略。至少检查：

| 配置 | 说明 |
| --- | --- |
| `project.id` | 稳定且不含秘密的项目标识 |
| `source.path` | 与 SARIF 对应的本地源码目录 |
| `source.snapshot_mode` | 当前只能为 `copy` |
| `build.command` | 供真实扫描使用的 Maven Wrapper 参数数组 |
| `codeql.cli_version` | 当前真实扫描门禁固定为 `2.26.1` |
| `analysis.target_cwes` | 本次关注的 CWE |
| `security.source_upload_policy` | 离线路径应保持 `offline_only` |
| `storage.workspace_root` / `artifact_root` | 两个不重叠的受管写入目录 |

ProjectSpec 是严格 schema：未知字段、路径逃逸、符号链接逃逸、shell 命令、
未固定 query pack 和危险构建设置都会被拒绝。

### 5.2 验证并导入

若源码在当前检出目录内：

```bash
uv run evitriage project validate \
  --config configs/projects/private-example.yaml \
  --json

uv run evitriage ingest-sarif \
  --project-config configs/projects/private-example.yaml \
  --sarif /path/to/result.sarif \
  --json
```

若源码在检出目录外，可信操作者还必须在两个命令中显式重复允许根：

```bash
uv run evitriage project validate \
  --config configs/projects/private-example.yaml \
  --allowed-source-root /canonical/path/to/target-source \
  --json

uv run evitriage ingest-sarif \
  --project-config configs/projects/private-example.yaml \
  --sarif /path/to/result.sarif \
  --allowed-source-root /canonical/path/to/target-source \
  --json
```

成功应到达 `CONTEXT_READY`。系统会保留原始 SARIF 字节，记录精确的
`(SARIF SHA-256, run index, result index)`，并生成标准化告警、源码切片、
证据注册表、证据图和转义后的源码映射。

如果 SARIF 声明的文件哈希与当前源码不一致，系统会拒绝；文件缺失时会明确
记录为未知/部分上下文，而不会声称坐标已经验证。`CONTEXT_READY` 不是
`TP`/`FP`/`NMC` 裁决。

## 6. 离线 Replay 研判

对已有 SARIF 继续研判：

```bash
uv run evitriage triage \
  --project-config configs/projects/private-example.yaml \
  --sarif /path/to/result.sarif \
  --llm-profile configs/llm/replay-v0.1.yaml \
  --replay-cache /trusted/read-only/replay-cache \
  --json
```

Replay 缓存必须是可信、只读、无符号链接逃逸的目录，并已经包含与每个规范化
模型请求 SHA-256 精确匹配的结构化响应。当前仓库只提供固定六案例演示缓存，
**没有**面向任意项目的通用 Replay 缓存生成器。缺少条目时会得到可审计的
`MODEL_FAILED`，不会自动切换到网络模型。

可以用 `--evidence-supplement` 添加经过审阅的证据，但补充文件必须与项目、
源码快照、原始 SARIF 和结果出现位置严格绑定；它只能增加 assertion，不能
直接指定最终标签。不要把演示补充套用到其他项目。

## 7. 部署真实 CodeQL 扫描环境

EviTriage-QL 不会替你安装 JDK、CodeQL 或 Maven。当前检入配置要求：

- 同一个 JDK 17 提供匹配的 `java` 和 `javac`；
- CodeQL CLI `2.26.1` 位于 `PATH`；
- 目标源码中有经过校验的 Maven Wrapper；
- Maven Wrapper 所声明的 Maven `3.9.9` 已在受控步骤中进入缓存，因为实际
  构建命令带 `--offline`；
- 可选 query/model pack 使用精确的 `scope/name@x.y.z` 版本固定。

先验证外部工具：

```bash
codeql version --format=terse
java -version
javac -version
uv run evitriage doctor --json
```

再验证项目配置并扫描：

```bash
uv run evitriage project validate \
  --config configs/projects/private-example.yaml \
  --allowed-source-root /canonical/path/to/target-source \
  --json

uv run evitriage scan \
  --project-config configs/projects/private-example.yaml \
  --allowed-source-root /canonical/path/to/target-source \
  --json
```

成功的 `scan` 必须报告 `real_codeql=true`、CodeQL `2.26.1` 并到达
`CONTEXT_READY`。工具缺失、版本不符、构建失败、超时或不安全输出都会形成
结构化失败，绝不会用 Golden SARIF 伪装成功。

真实扫描会以当前主机用户身份执行目标 Maven 构建。受管副本和参数校验不是
完整的操作系统沙箱。对不是完全可信的项目，应在 EviTriage-QL 之外使用专用
低权限账户或隔离 VM/容器，并施加网络、CPU、内存、进程和文件系统限制；
不要让扫描账户继承云凭据、SSH agent、开发者 Token 或其他项目秘密。仓库
当前不提供可以直接视为生产沙箱的容器模板。

## 8. 从真实扫描直接研判

`triage` 要求 `--sarif` 和 `--scan` 二选一。使用已经准备好的 Replay 缓存：

```bash
uv run evitriage triage \
  --project-config configs/projects/private-example.yaml \
  --scan \
  --llm-profile configs/llm/replay-v0.1.yaml \
  --replay-cache /trusted/read-only/replay-cache \
  --allowed-source-root /canonical/path/to/target-source \
  --json
```

这会分配一个全新运行，从 CodeQL 一直执行到 JSONL/HTML 报告。当前不能把
一个已最终化的旧 `scan` run 原地续接为 triage，也没有
`report --run-id` 命令；保留旧运行只是审计，不会改变其状态。

## 9. 可选 DeepSeek 远程研判

只有在组织允许把受控源码摘录和证据发送给 DeepSeek 时才启用。模型端点固定
为 `api.deepseek.com:443/chat/completions`，不能由项目配置改写。可信的
ProjectSpec 和 LLM Profile 必须同时声明 `remote_llm_allowed`，例如：

- `configs/projects/example-local-deepseek-v4.yaml`
- `configs/llm/deepseek-v4-pro.yaml`

**绝不要**把 API Key 放入聊天、命令参数、YAML、`.env`、shell 脚本、日志、
Git 或运行产物。已经在聊天中暴露的 Key 必须先撤销，再通过下列方式重新录入。

### 一次性环境变量：WSL/Linux 通用

```bash
(
  trap 'unset DEEPSEEK_API_KEY' EXIT
  read -rsp 'DeepSeek API Key: ' DEEPSEEK_API_KEY
  printf '\n'
  export DEEPSEEK_API_KEY

  uv run evitriage triage \
    --project-config configs/projects/private-deepseek.yaml \
    --sarif /path/to/result.sarif \
    --llm-profile configs/llm/deepseek-v4-pro.yaml \
    --credential-provider environment \
    --allowed-source-root /canonical/path/to/target-source \
    --json
)
```

### pass/GPG：WSL 或原生 Linux 持久存储

先在 EviTriage-QL 之外用**受口令保护**的 GPG 私钥初始化标准 pass 密码库：

```bash
pass init <your-gpg-key-id>
uv run evitriage credentials set-deepseek --provider pass
uv run evitriage credentials status --json
```

随后给 `triage` 传 `--credential-provider pass`。固定密码库条目是
`evitriage/deepseek-api-key`。gpg-agent 可能缓存解锁状态，应按主机风险设置
较短 TTL，并在会话结束时锁定或终止 agent。

### systemd-creds/TPM2：具备 TPM2 的原生 Linux

确认操作者能访问 `/dev/tpmrm0` 且存在受支持的 `/usr/bin/systemd-creds`
后，通过隐藏的双重提示写入仓库外密文：

```bash
uv run evitriage credentials set-deepseek --provider systemd-creds
uv run evitriage credentials status --json
```

随后给 `triage` 传 `--credential-provider systemd-creds`。WSL 通常不具备这条
路径，应使用 pass/GPG 或一次性环境变量。凭据保护只保护 API Key；已授权的
证据和源码摘录仍会发给模型提供方，并可能产生费用。完整边界见
[大模型调用、凭据边界与全流程](llm-invocation-and-credential-flow.md)。

## 10. 日常运维、CI 与审计

### 每次运行前

```bash
uv run evitriage doctor --json
uv run evitriage project validate \
  --config /path/to/project.yaml \
  --allowed-source-root /canonical/path/to/target-source \
  --json
```

确认当前源码版本与 SARIF 对应、磁盘空间充足、`workspaces/` 和
`artifacts/` 不与源码重叠，并确认本次是否真的允许远程上传。

### 每次运行后

- 记录命令、退出码、`run_id`、`state`、`artifact_run_root` 和
  `real_codeql`；
- 保存整个 run 目录，不要只复制 HTML；
- 用 `run-manifest.json` 中的大小和 SHA-256 审计所有注册产物；
- 对 HTML/JSONL/源码摘录采用与原始源码相同的保密级别；
- 失败时检查 `metadata/error.json` 以及已注册的有限 stdout/stderr，不要
  用手工成功结果覆盖失败历史。

CLI 的 `--json` 成功摘要写到标准输出，结构化错误写到标准错误，并以非零
退出码失败。CI 应按退出码判定结果，而不是搜索人类可读日志。每个 CI job
都应使用独立受管根，发布整个审计 run 目录为受限访问制品。远程模型 Key
只能使用 CI 的短期 secret 注入到该进程，不能写入 workspace 或缓存。

项目当前按新运行工作，不支持操作者指定 run ID、失败点恢复或并发工作流
续接。`make clean` 会拒绝宽泛清理。保留策略应由部署方基于精确 run 目录、
数据等级和审计要求制定，不要对仓库根、`workspaces/` 或 `artifacts/`
执行未经核对的递归删除。

如果需要重建并校验发布闭包：

```bash
make release-artifacts
make release-verify
```

默认输出位于 `dist/release/0.2.0/`。从源码分发包进行洁净重装和独立复验的
步骤见[可复现性指南](reproducibility.md)。成功构建 release 不代表可直接
投入生产，也不代表模型准确率已经验证。

## 11. 常见故障

| 现象 | 优先检查 |
| --- | --- |
| uv 版本被拒绝 | `command -v uv` 和 `uv --version` 是否确为 `0.8.3` |
| 找不到项目根 | 是否在检出/解包根内运行，或正确设置了可信的 `EVITRIAGE_PROJECT_ROOT` |
| `doctor` 报 CodeQL/Java 缺失 | 离线演示可继续；真实扫描必须补齐固定版本 |
| ProjectSpec 路径被拒绝 | 使用规范绝对允许根，避免 `..`、符号链接和源码/输出目录重叠 |
| SARIF 哈希或坐标失败 | 源码是否为产生 SARIF 时的精确版本，SARIF 是否为严格 2.1.0 |
| Maven Wrapper 离线失败 | Maven 3.9.9 是否已在受控步骤中进入 wrapper 缓存 |
| Replay `MODEL_FAILED` | 请求哈希对应的响应是否存在、只读并符合精确角色 schema |
| DeepSeek 配置失败 | 两侧 `remote_llm_allowed`、模型 ID、凭据状态和 provider 选择 |
| 最终文件无法写入 | `0400` 是正常最终化结果；不要修改已完成运行，应创建新运行 |

使用 `uv run evitriage -v ...` 可以输出经过脱敏的调试级结构化日志。不要
通过修改 schema、关闭路径校验或把失败替换为夹具成功来绕过问题。

## 12. 部署验收清单

最低离线验收：

```bash
uv sync --all-extras
make check
make security-test
make demo
uv run evitriage doctor --json
uv run evitriage project validate \
  --config configs/projects/example-local.yaml \
  --json
uv run evitriage ingest-sarif \
  --project-config configs/projects/example-local.yaml \
  --sarif tests/fixtures/sarif/single-path.sarif \
  --json
```

若部署承诺真实扫描，还必须单独记录 `codeql version --format=terse`、
`java -version`、`javac -version` 和真实 `scan` 的命令、退出码、run ID、
`real_codeql=true` 及最终状态。若部署承诺远程模型路径，还必须另行记录
上传授权、非秘密凭据状态、提供方、模型 ID、费用/限流边界和一次明确授权的
live smoke；自动化测试不得读取操作者真实凭据或调用真实模型。

最后再次确认：EviTriage-QL v0.2.0 是有界、可审计的研究基础设施，不是生产
就绪的漏洞分类器。真实构建需要外部操作系统隔离，模型输出需要人工复核，
任何组件都不会自动关闭上游告警。
