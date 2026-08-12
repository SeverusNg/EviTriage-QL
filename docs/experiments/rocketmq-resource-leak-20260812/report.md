# Apache RocketMQ Resource-Leak Detection Experiment

[English](report.md) | [简体中文](report.zh-CN.md)

Experiment date: 2026-08-12 (Asia/Shanghai)
Experiment type: real open-source project, real Maven builds, real CodeQL SARIF, EviTriage existing-SARIF ingest/context, offline Replay compatibility testing, and manual evidence review.
Experiment revisions: RocketMQ `e3458616d207ee636b1762f0f8dcf788a590d59d`; EviTriage-QL `ff9848ca4046cd4faf2fcc576bb0cd17a673d085` / 0.2.0.

## 1. Executive summary

### 1.1 Historical defect: CodeQL detected the defect and verified the fix effect

The following statements are jointly confirmed by Git objects, the actual diff, two independent CodeQL databases, and the pre/post SARIF files:

- The candidate fix exists at `a6c5604b6cb6fce255fe9e0e6e860f94d37c2050`; its exact parent is `04711367b7378115ed0c8e656aea88dab2a050da`.
- Its actual title is `[ISSUE #10046] Fix lock leak risk in sendHeartbeatToBroker (#10047)`, and it changes `MQClientInstance.java` in the `client` module.
- Before the fix, `sendHeartbeatToBroker` could successfully execute `lockHeartbeat.tryLock()`, prepare heartbeat data before entering the `try` guarded by `finally`, and return `false` when both producer and consumer sets were empty. That path owned the lock but could not reach `lockHeartbeat.unlock()`.
- The fix moved heartbeat preparation and the early return into the `try`, so normal return, early return, and exceptional exit are all protected by `finally`.
- `java/unreleased-lock` changed from six results before the fix to five afterward. The removed result precisely identified the target method; the other five locations stayed unchanged.
- `java-security-and-quality.qls` changed from 680 results to 679. Its lock subset likewise changed from six to five, removing the same target result.

The historical case is therefore a **TP** under this experiment's definition, and CodeQL 2.26.1 with `codeql/java-queries@1.11.6` detects this concrete implementation. The conclusion was not inferred from the commit title.

### 1.2 Current revision: human evidence baseline for 26 alerts

The four individual queries produced the following results on the current `develop` snapshot:

| Query | Count |
|---|---:|
| `java/input-resource-leak` | 3 |
| `java/output-resource-leak` | 1 |
| `java/database-resource-leak` | 0 |
| `java/unreleased-lock` | 22 |
| **Total** | **26** |

Manual review of EviTriage source contexts, RocketMQ source, JDK 17 bytecode, and the actual Netty 4.1.130.Final bytecode produced:

| Human label | Count | Composition |
|---|---:|---|
| TP | 5 | two TLS certificate input streams; one exceptional sequential-close path; two interrupted lock paths in test code |
| FP | 18 | one FileStream/FileChannel ownership-modeling false positive; 17 lock results covered by `finally` |
| NMC | 3 | the custom timeout lease/semaphore protocol in `ReceiptHandleGroup` |

The 5/18/3 distribution is a **human evidence-review baseline, not EviTriage model output and not independently validated absolute ground truth**.

### 1.3 EviTriage: compatible input, incomplete autonomous resource triage

- All four code-quality SARIF files passed strict EviTriage normalization, source-bound checks, and context/evidence registration, reaching `CONTEXT_READY`.
- The formal offline Replay triage exited 1 with state `MODEL_FAILED` and error `MODEL_REPLAY_MISS`. The Replay cache had no matching resource-leak request, `invocations=[]`, and no automatic label or final report was produced.
- No remote model was authorized, so the experiment did not call DeepSeek or any other remote LLM and did not fabricate a Replay hit.
- The current claim schema only supports `source_controllable`, `path_feasible`, `sanitizer_effective`, `sink_dangerous`, and `exploit_succeeds`. It lacks acquisition, release coverage, ownership transfer, escape, lease expiry, and callee-close summary claims.

V1 therefore demonstrates that real code-quality SARIF can enter EviTriage and produce auditable source context. It does not demonstrate that the current model independently completed resource-leak classification.

## 2. Evidence levels

- **Fact (F):** directly established by Git, source, POM/build documentation, real exit codes, CodeQL logs, SARIF, EviTriage manifests, or local dependency bytecode.
- **Evidence judgment (J):** a human TP/FP assessment based on established control flow and ownership semantics; it is not equivalent to dynamic reproduction.
- **NMC:** available context cannot reliably distinguish TP from FP.
- **Unverified (U):** no close fault injection, file-descriptor counting, long-pause/concurrency pressure test, or real-model call has been performed.

## 3. Repository and tool versions

| Item | Actual value | Evidence status |
|---|---|---|
| RocketMQ URL | `https://github.com/apache/rocketmq.git` | F |
| Default remote branch | `origin/develop` | F |
| Current scan SHA | `e3458616d207ee636b1762f0f8dcf788a590d59d` | F |
| Current commit title | `fix(common): compare message queue ids safely (#10884)` | F |
| EviTriage-QL experiment SHA/version | `ff9848ca4046cd4faf2fcc576bb0cd17a673d085` / `0.2.0` | F |
| CodeQL CLI | `2.26.1`, `/opt/codeql/2.26.1/codeql/codeql` | F |
| Java query pack | `codeql/java-queries@1.11.6` | F |
| Java / javac | OpenJDK `17.0.19` / `17.0.19` | F |
| Maven | Apache Maven `3.9.9` | F |
| Python / uv | `3.12.3` / `0.8.3` | F |
| Git | `2.43.0` | F |

RocketMQ has no Maven Wrapper. The experiment used standalone Maven 3.9.9 based on the actual `BUILDING` guide and root POM, instead of bypassing EviTriage's wrapper-only scan safety constraint. The verified official Maven archive SHA-512 was:

```text
a555254d6b53d267965a3404ecb14e53c3827c09c3b94b5678835887ab404556bfaf78dcfe03ba76fa2508649dca8531c74bca4d5846513522404d48e8c4ac8b
```

The official checksum file contained a bare hash rather than the `hash filename` format expected by `sha512sum -c`, so the first direct check exited 1. Exact hash-string comparison then succeeded. The first failure is retained rather than presented as success.

## 4. Independent worktrees, build commands, and databases

The external experiment root is `/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812`. It contains three detached, source-clean worktrees:

| Worktree | SHA | Purpose |
|---|---|---|
| `worktrees/pre` | `04711367b7378115ed0c8e656aea88dab2a050da` | pre-fix |
| `worktrees/post` | `a6c5604b6cb6fce255fe9e0e6e860f94d37c2050` | post-fix |
| `worktrees/current` | `e3458616d207ee636b1762f0f8dcf788a590d59d` | current revision |

After inspecting the reactor and `client/pom.xml`, the historical builds selected the affected `client` module and its actual dependencies:

```bash
/opt/codeql/2.26.1/codeql/codeql database create <DB> \
  --language=java-kotlin \
  --source-root=<PRE_OR_POST_WORKTREE> \
  --command="/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812/tools/apache-maven-3.9.9/bin/mvn -pl client -am -DskipTests -Dcheckstyle.skip -Drat.skip=true package"
```

| Database | Maven result/time | CodeQL exit |
|---|---|---:|
| `databases/pre-client` | `BUILD SUCCESS` / 05:02 | 0 |
| `databases/post-client` | `BUILD SUCCESS` / 01:00 | 0 |

The current revision used the root reactor for a full database:

```bash
/opt/codeql/2.26.1/codeql/codeql database create \
  /home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812/databases/current-full \
  --language=java-kotlin \
  --source-root=/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812/worktrees/current \
  --command="/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812/tools/apache-maven-3.9.9/bin/mvn -DskipTests -Dcheckstyle.skip -Drat.skip=true package"
```

All 19 reactor projects succeeded; Maven took 05:31; CodeQL exited 0; and the full suite reported 2245/2246 Java/Kotlin files scanned. `-DskipTests` skipped test execution but Maven still compiled tests, so four of the 22 lock results came from `store/src/test`.

Successful query executions used SARIF 2.1.0 and `--threads=2 --ram=12000`, exiting 0. One failure must remain visible: the first pre-fix full-suite attempt used `--threads=0 --ram=12000` and exited 70 with `java.lang.OutOfMemoryError: Java heap space`. A rerun limited parallelism to two without changing source, query, or policy and succeeded. This was a host-resource/concurrency issue, not a query-logic failure.

## 5. SARIF inventory

The raw files remain in the external `sarif/` directory and are not committed. `SHA256SUMS` contains the complete checksum inventory.

| File | Total results | Target resource counts | SHA-256 |
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

Zero JDBC results only means that `java/database-resource-leak` emitted no results. It does not prove the project has no JDBC use or that dynamic testing validated every database resource. The other 1,913 non-target results in the full suite were outside the per-alert triage scope of this stage.

## 6. Second-level assessment of the historical fix

The feasible pre-fix path was:

1. `lockHeartbeat.tryLock()` succeeds;
2. `prepareHeartbeatData(false)` executes;
3. both producer and consumer sets are empty, causing `return false` before entering `try`;
4. the later `finally` is unreachable, so `lockHeartbeat.unlock()` does not execute.

The resource was not stored in a field or collection, returned to a caller, or transferred to another owner. The fix moved steps 2 and 3 into the `try`, so early return and exceptions pass through `finally`. The pre-fix CodeQL locations included the target at `MQClientInstance.java:623`; the post-fix database retained only the same other five locations. The target result is therefore **TP (F+J)** and the fix is effective.

The comparison with the current revision must separate two roles: the historical case is a high-quality positive example backed by a real fix commit, while the 26 current results include many modeling false positives, test-only true positives, and custom-protocol NMCs. They test a wider and more difficult set of ownership and all-path release reasoning than the single historical regression.

## 7. EviTriage input, state, and compatibility

The experiment used the Git-ignored `configs/projects/private-rocketmq-resource-leak.yaml`, whose ProjectSpec SHA-256 is `eb57f9ee6b1462a48e933576d05f2e61107d722a494f062f41be8ff3456ab69f`. It pointed to the clean RocketMQ main clone. Only existing-SARIF ingest/triage was executed; EviTriage `scan` was not invoked, so the Maven Wrapper constraint was not bypassed.

| Input | run_id | alerts/contexts/evidence | State | normalized / registry SHA-256 |
|---|---|---:|---|---|
| current-input | `20260812T041930063026Z-1454ba959ba6` | 3/3/26 | `CONTEXT_READY` | `65d2ec…67ea` / `cc7fd4…f87b` |
| current-output | `20260812T041956925577Z-dd1cf82c4ee1` | 1/1/6 | `CONTEXT_READY` | `de91d3…708d` / `9a6e90…e9cf` |
| current-database | `20260812T042005686048Z-ff010ac314b4` | 0/0/0 | `CONTEXT_READY` | `5d3e45…c9ec` / `79f401…dd2` |
| current-lock | `20260812T042013191049Z-6a45fe086f34` | 22/22/100 | `CONTEXT_READY` | `35eb93…ba61` / `591861…98a9` |

All four inputs were SARIF 2.1.0 and declared `run.columnKind=utf16CodeUnits`. Every non-empty result received enclosing-function context with no missing-source or partial omission. The queries emit SARIF `problem` results without CodeQL paths, so EviTriage correctly preserved empty `paths` instead of inventing a path.

The final offline triage run was:

| Field | Value |
|---|---|
| run_id | `20260812T055911630168Z-b87279b555ed` |
| Exit/state | `1` / `MODEL_FAILED` |
| Error | `MODEL_REPLAY_MISS` / `no ReplayLLM cache entry matches the canonical request` |
| Stage | `analyst`, attempt 0 |
| Remote/Replay invocations | `invocations=[]` |
| Automatic labels | 0 |
| Prompt SHA-256 | `573ee25e8a8cac8cc928aa53f1871eeb9050777713a4c68aacb5b7e10ea53feb` |
| Request SHA-256 | `4a1b8fbd54bc2f11403b4468a522ad39c41261f4c96f06af18fe178cb180403e` |

The evidence supports three separate conclusions: the input layer is compatible; the offline resource replay data is absent; and the prompt/schema has a resource-domain compatibility gap. `MODEL_REPLAY_MISS` is neither a CodeQL failure nor an ingest failure, and the human labels must not be described as model results.

## 8. Evidence conclusions for the 26 current alerts

Machine-readable per-alert evidence is in `alert-triage.jsonl`. The tables below retain the control-flow, ownership, and scope conclusions most useful for collaborator alignment.

### 8.1 Input and output resources

| ID | Location | Label | Core evidence |
|---|---|---|---|
| I-0 | `IOTinyUtils.java:93 copyFile` | FP | The `FileChannel sc` returned by `FileInputStream.getChannel()` is closed in `finally`; JDK 17 channel close closes the parent stream. Normal return and `transferTo` exceptions are covered, with no escape. |
| I-1 | `TlsHelper.java:130 buildSslContext` | TP | The certificate `FileInputStream` has no TWR/finally/close. The actual Netty implementation parses certificate/key objects without closing or retaining the caller stream, so normal return and parse exceptions can leak it. |
| I-2 | `TlsHelper.java:144 buildSslContext` | TP | The server branch has the same evidence as I-1. |
| O-0 | `IOTinyUtils.java:92 copyFile` | TP | `finally` executes `sc.close()` before `tc.close()`. If the first throws `IOException`, the second is skipped. This is a statically feasible path without fault injection (U). |

There is also a missed candidate outside the 26 SARIF results: `DecryptionStrategy.decryptPrivateKey` returns a `FileInputStream` that its caller passes to the same Netty APIs that do not close the stream. CodeQL treats the helper return as an escape but does not continue through the caller and Netty ownership behavior. This is a reasonable cross-method candidate, not a dynamically confirmed result.

### 8.2 Lock resources

| ID range | Label | Core evidence |
|---|---|---|
| L-0 through L-6 | 7 FP | Each `tryLock`/`lockInterruptibly` branch was checked: successful acquisition is covered by `finally`, an acquisition flag, or the correct `forceUnlock` condition; failed acquisition creates no release duty. |
| L-7 through L-13 | 7 FP | The `RouteInfoManager` methods cover every exit after successful acquisition with `finally`. Some may unlock after `lockInterruptibly` is interrupted before acquisition; that is a possible over-unlock, not a successful-acquire leak. |
| L-14 through L-16 | 3 NMC | `ReceiptHandleGroup.HandleData` treats its semaphore as a timed lease: unlock intentionally omits release after 2x timeout, while later lock calls may bypass or restore after 3x timeout. Product ownership semantics and long-pause/pressure evidence are missing. |
| L-17 | FP | The early return in `DLedgerCommitLog.asyncPutMessages` still executes nested finally blocks that release both locks. |
| L-18 and L-20 | 2 TP (test code) | The main test thread acquires, then calls interruptible `Thread.sleep` before unlock. The test declares `InterruptedException` and has no finally. |
| L-19 and L-21 | 2 FP (test code) | Each child thread catches `InterruptedException` and then reaches unlock, with no early exit. |

The lock false positives mainly arise because CodeQL `UnreleasedLock` uses limited basic-block/CFG modeling and cannot fully prove the equivalence of repeated accessors, boolean guards, nested finally blocks, or custom protocols. No result was labeled FP merely because an `unlock()` was visible; each assessment checked returns and exceptions after successful acquisition.

## 9. Query coverage boundaries

The local query source shows that input covers derived `Reader`, `InputStream`, and `ZipFile` types; output covers derived `Writer` and `OutputStream`; database covers `java.sql.Connection`, `Statement`, `ResultSet`, and selected create/execute returns; and lock relies on CodeQL `Concurrency.LockType` plus bounded lock/unlock count rules.

The four queries therefore do not exhaust arbitrary `AutoCloseable`, NIO `Channel` itself, sockets, executor/thread pools, Netty reference-counted `ByteBuf`, native handles, temporary files, framework-managed sessions, distributed locks/leases, RocketMQ custom keyed locks, or cross-method/cross-object ownership protocols. A successful full security-and-quality suite does not prove those resources leak-free.

## 10. Recommended next steps for EviTriage and CodeQL

To create a technically autonomous EviTriage loop, first add:

1. resource claims for acquire, release, release coverage, ownership transfer, escape, lease expiry, and callee-close summaries;
2. evidence collection for normal return, exceptions, early return, break/continue, TWR/finally, and cross-method close/unlock;
3. resource-specific Replay fixtures, or a real provider only after explicit authorization;
4. a conservative deterministic policy that consistently returns NMC when evidence is insufficient and never auto-dismisses upstream alerts;
5. a new V2 artifact/workspace that verifies and reuses the frozen V1 SARIF by SHA-256 without overwriting V1.

Recommended custom CodeQL priorities are:

1. non-owning Netty `SslContextBuilder` InputStream handling plus cross-method `decryptPrivateKey` propagation;
2. multiple resources closed sequentially in one finally where an earlier close exception prevents later closes;
3. shared FileStream/FileChannel close ownership;
4. `lockInterruptibly`, tryLock booleans, repeated accessors, and lock-acquired guards;
5. long-pause/concurrency testing of `ReceiptHandleGroup` before deciding whether to encode its lease protocol in a custom query.

Even if V2 runs end-to-end without human intervention, evaluating the accuracy of its 5/18/3 predictions will still require human or independent reference labels. “The pipeline runs autonomously” and “accuracy needs no ground truth” are different claims.

## 11. File locations, preservation, and Git boundary

- RocketMQ source: `/home/nigeriacrop/code/third-party/rocketmq`.
- Frozen worktrees, Maven, databases, SARIF, and CodeQL logs: `/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812`.
- EviTriage V1 ingest/triage runs and original report: `/home/nigeriacrop/code/EviTriage-QL/artifacts/rocketmq-resource-leak-20260812`.
- EviTriage snapshots/workspaces: `/home/nigeriacrop/code/EviTriage-QL/workspaces`.
- Lightweight collaboration evidence in this change: `docs/experiments/rocketmq-resource-leak-20260812`.

The original host-local report SHA-256 is `4282758d08a0cb583c217f5a64247d4b3b1da59d5939b6b9e37403725dfecfd9`. This packaging did not delete or move any original input or output. Git stores only reports, the machine manifest, per-alert human conclusions, and hash indexes—not source, databases, SARIF, build outputs, runtime workspaces, model responses, or credentials.
