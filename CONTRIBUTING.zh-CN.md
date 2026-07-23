# 贡献指南

[English](CONTRIBUTING.md) | [简体中文](CONTRIBUTING.zh-CN.md)

EviTriage-QL 按可复现安全研究软件的标准开发。每项变更都应明确其信任
假设、证据和当前 Gate。

## 配置开发环境

安装 Python 3.12、`uv 0.8.3` 和 Make。所需工具必须位于持久化的用户级或
系统级位置，并能在全新的 login shell 中通过 `PATH` 找到；`/tmp` 中的
bootstrap 不算可验收的交付环境。`pyproject.toml` 会强制检查 uv 版本。
验证后运行：

```bash
command -v uv
uv --version
uv sync --all-extras
make check
uv run evitriage doctor --json
```

默认测试和 Gate E 演示不需要模型 API 密钥、Java 或真实 CodeQL 安装：
它们使用合成 Golden SARIF 和固定 Replay 条目。可为独立的真实扫描路径
安装 CodeQL 和匹配的 JDK，但不得掩盖其缺失。

## 进行聚焦的变更

1. 阅读 `AGENTS.md`、`docs/architecture.md` 以及约束该区域的 ADR。
2. 将目标项目数据放在 ProjectSpec/配置中，而不是核心代码中。
3. 为正常路径、错误输入和相关安全边界情况添加测试。
4. 先运行聚焦测试，再运行 `make check`。
5. 公共行为或交付证据改变时，同步更新文档、`CHANGELOG.md`、
   `KNOWN_LIMITATIONS.md` 和进度日志的中英文版本。

不得添加空的未来模块、伪造的工具输出、下载的第三方仓库、秘密、私有配置、
模型响应或生成的运行产物。不得仅为接受模糊输入而削弱严格校验。

所有人工维护的项目文档都必须遵守 `AGENTS.md` 的双语规则：英文 `*.md`
与简体中文 `*.zh-CN.md`（中文原文则配对 `*.en.md`）须在同一变更中更新，
并保持命令、警告、版本、限制和链接语义一致。

## 代码与测试要求

- 使用 Ruff 格式化和 lint，使用 mypy strict 做类型检查，使用 pytest 测试。
- 公共 API 必须有类型和简洁 docstring。
- Pydantic 输入模型必须拒绝额外字段并进行语义校验。
- 外部命令使用经过校验的参数向量，绝不使用 `shell=True`。
- 凭据后端实现提供方接口，并与 LLM HTTP 适配器、工作流和流水线解耦。
  显式选择的提供方失败时必须失败关闭；`auto` 只能跳过确实不可用的后端。
- 凭据子进程测试必须注入假命令运行器。不得调用操作者真实的 `pass`、GPG、
  systemd 凭据、环境密钥或远程模型；并须断言 argv、环境、诊断、日志和
  文件都不包含测试密钥。
- 测试默认必须确定性、离线，并与用户源码目录隔离。
- 文件系统测试必须覆盖遍历/符号链接问题，且只能清理由测试拥有的路径。
- 日志和 JSON 诊断不得泄露秘密。

WSL 文档和测试应优先使用固定 pass 条目或一次性环境密钥。原生 Linux 可
保留 TPM2/systemd 路径。不得增加 `.env` 加载、明文密钥文件、任意凭据
命令，或依赖已解锁桌面会话的 Secret Service/Python-keyring。pass 文档
必须保留“GPG 私钥受口令保护”和 gpg-agent 缓存边界。

权威的汇总命令为：

```bash
make check
```

选择聚焦测试前，先运行 `uv run pytest --collect-only -q`，确保文档和审阅
记录引用的是当前检出目录中确实存在的测试。

## 夹具与研究数据

仓库夹具必须最小化，使用合成数据或明确可再分发的数据，并提供足够的来源
信息以理解其 ground truth。不得 vendoring 真实第三方仓库。大型数据集应在
后续 Gate 中通过显式 manifest 和物化脚本获取，绝不能成为默认测试下载。

## 安全与披露

被分析源码是恶意数据，不是指令。贡献不得给予它 shell、网络、文件写入、
模型选择或秘密访问权限。请按 `SECURITY.md` 私下报告安全问题；不要把尚未
披露的漏洞放入 pull request 或公开 issue。报告方式见
[`SECURITY.zh-CN.md`](SECURITY.zh-CN.md)。

## 审阅清单

- 变更位于声明的 Gate 内，不夸大能力。
- 配置和输出 schema 仍然严格且有版本。
- 原始源码目录保持不变。
- 命令、哈希、时间戳和错误均结构化且可复现。
- 测试和 `make check` 通过，并报告真实结果。
- 面向用户的行为、限制及其中英文文档均已更新。
