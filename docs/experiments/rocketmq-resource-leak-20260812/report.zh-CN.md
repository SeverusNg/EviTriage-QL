# Apache RocketMQ 资源泄露检测实验报告

[English](report.md) | [简体中文](report.zh-CN.md)

实验日期：2026-08-12（Asia/Shanghai）
实验性质：真实开源项目、真实 Maven 构建、真实 CodeQL SARIF、EviTriage existing-SARIF ingest/context、离线 Replay 兼容性验证与人工证据复核。
实验版本：RocketMQ `e3458616d207ee636b1762f0f8dcf788a590d59d`；EviTriage-QL `ff9848ca4046cd4faf2fcc576bb0cd17a673d085` / 0.2.0。

## 1. 结论摘要

### 1.1 历史缺陷：CodeQL 检出并验证了修复效果

以下结论由 Git 对象、实际 diff、两个独立 CodeQL 数据库和修复前后 SARIF 共同确认：

- 候选修复提交存在：`a6c5604b6cb6fce255fe9e0e6e860f94d37c2050`；准确父提交为 `04711367b7378115ed0c8e656aea88dab2a050da`。
- 实际提交标题为 `[ISSUE #10046] Fix lock leak risk in sendHeartbeatToBroker (#10047)`，修改 `client` 模块的 `MQClientInstance.java`。
- 修复前，`sendHeartbeatToBroker` 在 `lockHeartbeat.tryLock()` 成功后，会在进入带 `finally` 的 `try` 之前准备心跳数据，并可能因为 producer/consumer 均为空而 `return false`。此路径已经获得锁，却到不了 `lockHeartbeat.unlock()`。
- 修复把心跳准备和提前返回移入 `try`，使正常返回、提前返回和异常退出均受到 `finally` 保护。
- `java/unreleased-lock` 从修复前 6 条变为修复后 5 条；消失的一条准确定位目标方法，其他 5 条位置不变。
- `java-security-and-quality.qls` 从 680 条变为 679 条；其中锁告警同样从 6 条变为 5 条，目标告警消失。

因此，该历史案例属于本实验定义下的 **TP**，而且 CodeQL 2.26.1 / `codeql/java-queries@1.11.6` 对这段具体实现有效。这不是根据提交标题推测出的结论。

### 1.2 当前版本：26 条告警的人工证据基线

当前 `develop` 快照的四个独立查询得到：

| 查询 | 数量 |
|---|---:|
| `java/input-resource-leak` | 3 |
| `java/output-resource-leak` | 1 |
| `java/database-resource-leak` | 0 |
| `java/unreleased-lock` | 22 |
| **合计** | **26** |

结合 EviTriage 提取的源码上下文、RocketMQ 源码、JDK 17 字节码和实际 Netty 4.1.130.Final 字节码，人工逐条复核得到：

| 人工结论 | 数量 | 构成 |
|---|---:|---|
| TP | 5 | 2 个 TLS certificate 输入流；1 个多个资源顺序关闭时的异常路径；2 个测试代码锁中断路径 |
| FP | 18 | 1 个 FileStream/FileChannel 所有权建模误报；17 个被 `finally` 覆盖的锁告警 |
| NMC | 3 | `ReceiptHandleGroup` 的自定义超时租约/信号量协议 |

这组 5/18/3 是**人工证据复核基线，不是 EviTriage 模型输出，也不是独立验证过的绝对 ground truth**。

### 1.3 EviTriage：输入兼容，自动资源研判尚未闭环

- 四份 code-quality SARIF 均通过 EviTriage 严格规范化、源码边界检查与上下文/证据注册，全部到达 `CONTEXT_READY`。
- 离线 Replay 正式运行退出码为 1，状态为 `MODEL_FAILED`，错误为 `MODEL_REPLAY_MISS`。Replay 中没有匹配资源泄露请求的条目，`invocations=[]`，没有自动 label 或最终报告。
- 实验没有远程模型授权，因此没有调用 DeepSeek 或其他远程大模型，也没有伪造 Replay 命中。
- 当前 claim schema 只覆盖 `source_controllable`、`path_feasible`、`sanitizer_effective`、`sink_dangerous`、`exploit_succeeds`，缺少 acquisition、release coverage、ownership transfer、escape、lease expiry 和 callee-close summary。

因此，V1 证明的是“真实 code-quality SARIF 可以进入 EviTriage 并形成可审计上下文”，而不是“当前模型已独立完成资源泄露判断”。

## 2. 证据等级

- **事实（F）**：由 Git、源码、POM/构建文档、实际退出码、CodeQL 日志、SARIF、EviTriage 清单或本地依赖字节码直接确认。
- **证据判断（J）**：依据已确认控制流和所有权语义作出的人工 TP/FP 判断；不等同于动态复现。
- **NMC**：现有上下文不足以在 TP 与 FP 之间可靠选择。
- **未验证（U）**：尚未执行 close 故障注入、文件描述符计数、长暂停/并发压力实验或真实模型调用。

## 3. 仓库与工具版本

| 项目 | 实际值 | 证据状态 |
|---|---|---|
| RocketMQ URL | `https://github.com/apache/rocketmq.git` | F |
| 默认远程分支 | `origin/develop` | F |
| 当前扫描 SHA | `e3458616d207ee636b1762f0f8dcf788a590d59d` | F |
| 当前提交标题 | `fix(common): compare message queue ids safely (#10884)` | F |
| EviTriage-QL 实验 SHA / 版本 | `ff9848ca4046cd4faf2fcc576bb0cd17a673d085` / `0.2.0` | F |
| CodeQL CLI | `2.26.1`，`/opt/codeql/2.26.1/codeql/codeql` | F |
| Java query pack | `codeql/java-queries@1.11.6` | F |
| Java / javac | OpenJDK `17.0.19` / `17.0.19` | F |
| Maven | Apache Maven `3.9.9` | F |
| Python / uv | `3.12.3` / `0.8.3` | F |
| Git | `2.43.0` | F |

RocketMQ 没有 Maven Wrapper。根据实际 `BUILDING` 和根 POM 使用独立 Maven 3.9.9，而不是让 EviTriage 的 wrapper-only scan 绕过安全约束。Maven 归档的官方 SHA-512 经精确字符串比较验证为：

```text
a555254d6b53d267965a3404ecb14e53c3827c09c3b94b5678835887ab404556bfaf78dcfe03ba76fa2508649dca8531c74bca4d5846513522404d48e8c4ac8b
```

官方校验文件只有裸哈希，不符合 `sha512sum -c` 所需的 `hash filename` 格式，因此首次直接检查退出 1；随后进行精确哈希字符串比较并成功。该失败被保留，没有包装成成功。

## 4. 独立工作区、构建命令与数据库

外部实验根目录为 `/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812`，其中建立三个 detached、源码干净的 worktree：

| worktree | SHA | 目的 |
|---|---|---|
| `worktrees/pre` | `04711367b7378115ed0c8e656aea88dab2a050da` | 修复前 |
| `worktrees/post` | `a6c5604b6cb6fce255fe9e0e6e860f94d37c2050` | 修复后 |
| `worktrees/current` | `e3458616d207ee636b1762f0f8dcf788a590d59d` | 当前版本 |

读取 reactor 和 `client/pom.xml` 后，历史版本只构建实际受影响的 `client` 及其依赖：

```bash
/opt/codeql/2.26.1/codeql/codeql database create <DB> \
  --language=java-kotlin \
  --source-root=<PRE_OR_POST_WORKTREE> \
  --command="/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812/tools/apache-maven-3.9.9/bin/mvn -pl client -am -DskipTests -Dcheckstyle.skip -Drat.skip=true package"
```

| 数据库 | Maven 结果/时间 | CodeQL 退出码 |
|---|---|---:|
| `databases/pre-client` | `BUILD SUCCESS` / 05:02 | 0 |
| `databases/post-client` | `BUILD SUCCESS` / 01:00 | 0 |

当前版本使用根 reactor 建完整数据库：

```bash
/opt/codeql/2.26.1/codeql/codeql database create \
  /home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812/databases/current-full \
  --language=java-kotlin \
  --source-root=/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812/worktrees/current \
  --command="/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812/tools/apache-maven-3.9.9/bin/mvn -DskipTests -Dcheckstyle.skip -Drat.skip=true package"
```

19 个 reactor project 全部成功；Maven 时间 05:31；CodeQL 退出码 0；完整 suite 扫描 2245/2246 个 Java/Kotlin 文件。`-DskipTests` 跳过测试执行，但 Maven 仍编译测试，所以 22 条锁告警中有 4 条来自 `store/src/test`。

查询统一使用 SARIF 2.1.0、`--threads=2 --ram=12000` 并退出 0。必须保留的一次失败是：修复前完整 suite 初次以 `--threads=0 --ram=12000` 运行，因 `java.lang.OutOfMemoryError: Java heap space` 退出 70；随后仅将并行度限制为 2，未改变源码、查询或策略，运行成功。这是主机资源/并行度问题，不是查询逻辑失败。

## 5. SARIF 清单

原始文件位于外部目录 `sarif/`，未进入 Git；完整 SHA-256 也记录在 `SHA256SUMS`。

| 文件 | 总结果 | 目标资源计数 | SHA-256 |
|---|---:|---|---|
| `pre-unreleased-lock.sarif` | 6 | lock=6 | `b226de0d01f682c38f37335a55f6496ec8902a8530d784b5772fac1864b2069e` |
| `post-unreleased-lock.sarif` | 5 | lock=5 | `a10bd1d24be5046d11683be74d7cd11abb187e5e4b098d709dbf75dd7c683193` |
| `pre-security-and-quality.sarif` | 680 | input=3, output=1, JDBC=0, lock=6 | `a42993f6a345ea67a3529972e9bba19a5dc262cbee75ddb6a6d18657728546ec` |
| `post-security-and-quality.sarif` | 679 | input=3, output=1, JDBC=0, lock=5 | `69be7987a11fe7aad703673f736b321a5385280b7c8b51c9370e090eb57c3446` |
| `current-input.sarif` | 3 | input=3 | `5d899cf425a0b2713426d3e685fcb12881c8cd94ade1c1c4fe3ce7832ebd8788` |
| `current-output.sarif` | 1 | output=1 | `3604c6c1c7d13316caa1a09f290b8957f0a041265bf5e6e6cbd05f355238b7f8` |
| `current-database.sarif` | 0 | JDBC=0 | `5b8ad61ccc5fb911cb637b551d5197ea2518df73a817e2a7995c1b81c98c1908` |
| `current-lock.sarif` | 22 | lock=22 | `9601a9b7a6304cecb26fe6f119d8c8b8fec5f54684d05d564756eb150e0bb493` |
| `current-security-and-quality.sarif` | 1939 | input=3, output=1, JDBC=0, lock=22 | `6b1b74611978ecf919d5dafb3242c8300134e9940dfaab1442a11c4464a7d79b` |

0 条 JDBC 只表示该查询没有结果，不能推出项目没有 JDBC 使用或所有数据库资源都经动态实验确认关闭。完整 suite 的其余 1913 条非目标结果不属于本阶段逐条研判范围。

## 6. 历史修复的二次研判

修复前的可行路径是：

1. `lockHeartbeat.tryLock()` 成功；
2. 调用 `prepareHeartbeatData(false)`；
3. producer/consumer 集合均为空时，在进入 `try` 前 `return false`；
4. 后面的 `finally` 不可达，所以 `lockHeartbeat.unlock()` 不执行。

资源没有被存入字段、集合或返回给调用方，也不存在有效所有权转移。修复后，步骤 2 和 3 被放进 `try`，使提前返回和异常均经过 `finally`。CodeQL 的修复前位置包含目标 `MQClientInstance.java:623`，修复后只剩相同的另外 5 条位置。该目标告警因此是 **TP（F+J）**，且修复有效。

与当前版本比较时要区分两件事：历史案例提供了一个由真实修复提交支持的高质量正例；当前 26 条告警则包含大量查询建模不足造成的 FP、测试代码 TP 和协议不明的 NMC。它们用于检验 EviTriage 是否能理解资源所有权与全路径释放，难度和类型比单一历史回归更广。

## 7. EviTriage 输入、状态与兼容性

使用 Git 忽略的 `configs/projects/private-rocketmq-resource-leak.yaml`；ProjectSpec SHA-256 为 `eb57f9ee6b1462a48e933576d05f2e61107d722a494f062f41be8ff3456ab69f`。配置指向干净的 RocketMQ 主克隆。本实验只运行 existing-SARIF ingest/triage，未调用 EviTriage `scan`，因此没有绕过 Maven Wrapper 约束。

| 输入 | run_id | alerts/contexts/evidence | 状态 | normalized / registry SHA-256 |
|---|---|---:|---|---|
| current-input | `20260812T041930063026Z-1454ba959ba6` | 3/3/26 | `CONTEXT_READY` | `65d2ec…67ea` / `cc7fd4…f87b` |
| current-output | `20260812T041956925577Z-dd1cf82c4ee1` | 1/1/6 | `CONTEXT_READY` | `de91d3…708d` / `9a6e90…e9cf` |
| current-database | `20260812T042005686048Z-ff010ac314b4` | 0/0/0 | `CONTEXT_READY` | `5d3e45…c9ec` / `79f401…dd2` |
| current-lock | `20260812T042013191049Z-6a45fe086f34` | 22/22/100 | `CONTEXT_READY` | `35eb93…ba61` / `591861…98a9` |

四份输入均为 SARIF 2.1.0 且声明 `run.columnKind=utf16CodeUnits`。每个非空告警都有 enclosing-function context，没有 missing-source/partial omission。查询类型为 SARIF `problem`，本身没有 CodeQL path，因此 EviTriage 如实保存空 `paths`，没有制造路径。

最终离线 triage 运行：

| 字段 | 值 |
|---|---|
| run_id | `20260812T055911630168Z-b87279b555ed` |
| 退出码/状态 | `1` / `MODEL_FAILED` |
| 错误 | `MODEL_REPLAY_MISS` / `no ReplayLLM cache entry matches the canonical request` |
| 阶段 | `analyst` attempt 0 |
| 远程/Replay 调用 | `invocations=[]` |
| 自动标签 | 0 |
| prompt SHA-256 | `573ee25e8a8cac8cc928aa53f1871eeb9050777713a4c68aacb5b7e10ea53feb` |
| request SHA-256 | `4a1b8fbd54bc2f11403b4468a522ad39c41261f4c96f06af18fe178cb180403e` |

结论是：输入层兼容；离线数据缺口已确认；提示词/schema 存在资源领域兼容性缺口。不能把 `MODEL_REPLAY_MISS` 说成 CodeQL 或 EviTriage ingest 失败，也不能把人工标签说成模型结果。

## 8. 当前 26 条告警的证据结论

机器可读逐条证据见 `alert-triage.jsonl`。以下表格保留协作者最需要对齐的控制流、所有权和范围结论。

### 8.1 输入与输出资源

| ID | 位置 | 结论 | 核心证据 |
|---|---|---|---|
| I-0 | `IOTinyUtils.java:93 copyFile` | FP | `FileInputStream.getChannel()` 返回的 `FileChannel sc` 在 `finally` 关闭；JDK 17 的 channel close 会关闭 parent stream。正常返回和 `transferTo` 异常均受覆盖，无逃逸。 |
| I-1 | `TlsHelper.java:130 buildSslContext` | TP | certificate `FileInputStream` 无 TWR/finally/close；实际 Netty 只解析证书/私钥对象，不关闭或保留调用方流。正常返回和解析异常均可泄露。 |
| I-2 | `TlsHelper.java:144 buildSslContext` | TP | server 分支与 I-1 相同。 |
| O-0 | `IOTinyUtils.java:92 copyFile` | TP | `finally` 先 `sc.close()` 再 `tc.close()`；前者若抛 `IOException`，后者不执行。该结论是静态可行路径，未做故障注入（U）。 |

另有一个不计入 26 条 SARIF 的漏报候选：`DecryptionStrategy.decryptPrivateKey` 返回 `FileInputStream`，调用处又把它交给同一组不会关闭流的 Netty API。CodeQL 把 helper return 视为逃逸，却没有继续验证调用方/Netty 的关闭行为；这是需要跨方法查询的合理候选，尚未动态确认。

### 8.2 锁资源

| ID 范围 | 结论 | 核心证据 |
|---|---|---|
| L-0 至 L-6 | 7 个 FP | 对每个 `tryLock`/`lockInterruptibly` 分支检查后，成功获取均由 `finally`、获取标志或 `forceUnlock` 条件正确覆盖；获取失败无需释放。 |
| L-7 至 L-13 | 7 个 FP | `RouteInfoManager` 方法在成功获取后均由 `finally` 覆盖。部分方法可能在 `lockInterruptibly` 获取前中断后仍执行 unlock，这是潜在 over-unlock，而不是“成功获取后未释放”。 |
| L-14 至 L-16 | 3 个 NMC | `ReceiptHandleGroup.HandleData` 将 semaphore 当超时租约：2×timeout 后 unlock 故意不 release，3×timeout 后后续 lock 又可绕过/恢复。缺少产品所有权契约与长暂停/压力证据。 |
| L-17 | FP | `DLedgerCommitLog.asyncPutMessages` 的提前返回仍执行内外两层 finally，分别释放两个锁。 |
| L-18、L-20 | 2 个 TP（测试代码） | 主测试线程获取锁后在 unlock 前调用可抛 `InterruptedException` 的 `Thread.sleep`，方法直接声明异常且无 finally。 |
| L-19、L-21 | 2 个 FP（测试代码） | 子线程捕获 `InterruptedException` 后继续执行 unlock，无提前退出。 |

锁误报主要来自 CodeQL `UnreleasedLock` 的有限 basic-block/CFG 建模无法充分证明重复 accessor、boolean guard、嵌套 `finally` 和自定义协议等价性。这里没有因为“看见 unlock”就判 FP；每条均检查了获取成功后的返回与异常路径。

## 9. 查询覆盖边界

本地查询源码显示：input 只覆盖 `Reader`、`InputStream`、`ZipFile` 派生类型；output 只覆盖 `Writer`、`OutputStream`；database 只覆盖 `java.sql.Connection`、`Statement`、`ResultSet` 及特定创建/执行调用；lock 依赖 CodeQL `Concurrency.LockType` 与有限 lock/unlock 计数规则。

因此，四个查询不能穷尽任意 `AutoCloseable`、NIO `Channel` 本身、socket、executor/thread pool、Netty reference-counted `ByteBuf`、native handle、临时文件、框架托管 session、分布式锁/租约、RocketMQ 自定义 keyed lock，以及跨方法/跨对象所有权协议。完整 security-and-quality suite 成功也不能证明这些资源均无泄露。

## 10. 对 EviTriage 与 CodeQL 的下一步建议

EviTriage 要实现无人工介入的技术闭环，应先增加：

1. 资源专项 claim：acquire、release、release coverage、ownership transfer、escape、lease expiry、callee-close summary；
2. 能表达正常返回、异常、提前返回、break/continue、TWR/finally 和跨方法 close/unlock 的证据收集；
3. 资源专项 Replay fixture，或在明确授权后使用真实 provider；
4. 保守的确定性策略，证据不足时稳定输出 NMC，且不自动关闭上游告警；
5. 新建 V2 artifact/workspace，按 SHA-256 复用不变的 V1 SARIF，不覆盖本次运行。

CodeQL 自定义查询优先级：

1. Netty `SslContextBuilder` InputStream 不接管所有权 + `decryptPrivateKey` 跨方法传播；
2. 同一 finally 顺序关闭多个资源时，前一个 close 抛异常阻断后续 close；
3. FileStream/FileChannel 共同关闭关系；
4. `lockInterruptibly`、tryLock boolean、重复 accessor 和 lock-acquired guard；
5. `ReceiptHandleGroup` 应先做长暂停/并发压力实验，再决定是否建自定义 lease 查询。

即使 V2 能自动运行到报告，5/18/3 的准确性评价仍需要人工或独立评审标签；“流程无需人工”与“准确率无需 ground truth”是两个不同问题。

## 11. 文件位置、保留和 Git 边界

- RocketMQ 源码：`/home/nigeriacrop/code/third-party/rocketmq`。
- 冻结 worktree、Maven、数据库、SARIF、CodeQL 日志：`/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812`。
- EviTriage V1 ingest/triage 运行与原始报告：`/home/nigeriacrop/code/EviTriage-QL/artifacts/rocketmq-resource-leak-20260812`。
- EviTriage 快照/工作区：`/home/nigeriacrop/code/EviTriage-QL/workspaces`。
- 本次提交的轻量协作证据：`docs/experiments/rocketmq-resource-leak-20260812`。

原始本机报告 SHA-256 为 `4282758d08a0cb583c217f5a64247d4b3b1da59d5939b6b9e37403725dfecfd9`。本次整理没有删除或移动任何原始输入/产物；Git 只保存报告、机器清单、逐条人工结论和哈希索引，不包含源码、数据库、SARIF、构建产物、运行工作区、模型响应或凭据。
