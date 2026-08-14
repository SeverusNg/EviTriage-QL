# Apache RocketMQ resource-leak V2 experiment protocol

[English](rocketmq-resource-leak-v2-protocol.md) | [简体中文](rocketmq-resource-leak-v2-protocol.zh-CN.md)

**Protocol date:** 2026-08-14  
**Status:** authorized live DeepSeek batch and post-freeze V1 comparison completed

## Objective and blindness boundary

V2 automatically triages CodeQL input/output/database/lock resource alerts with
resource-specific Analyst, Rebuttal, Judge, and deterministic TP/FP/NMC policy.
No human evidence supplement or label enters model requests or decisions.

The V1 `alert-triage.jsonl` is human evidence review, not independently verified
absolute ground truth. It may be opened only by `experiment evaluate` after all
V2 automatic decisions and reports are owner-read-only. Alignment uses only
`(raw SARIF SHA-256, run_index, result_index)`. Developer exposure to V1 means
the final comparison is an engineering comparison, not an unbiased benchmark.

## Frozen source identities

| Revision | Commit |
| --- | --- |
| Historical before fix | `04711367b7378115ed0c8e656aea88dab2a050da` |
| Historical fix | `a6c5604b6cb6fce255fe9e0e6e860f94d37c2050` |
| Current V1 revision | `e3458616d207ee636b1762f0f8dcf788a590d59d` |

Every source worktree must match its commit and be clean before any model or
credential access. The historical target is rule `java/unreleased-lock`, file
`client/src/main/java/org/apache/rocketmq/client/impl/factory/MQClientInstance.java`,
method `sendHeartbeatToBroker`.

## Frozen SARIF identities

| File | SHA-256 | Mode / count |
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

Raw bytes are never rewritten or split. Every occurrence preserves its SARIF
SHA-256, run index, and result index. Full-suite SARIF is audit-only: it proves
counts and historical disappearance and is never model input.

The triage population is 37 occurrences: historical pre 6, historical post 5,
and current 26 (input 3, output 1, database 0, lock 22). At three normal calls
per occurrence and at most one repair per role, the full experiment is 111–222
calls. A separate smoke is 3–6 calls.

## Offline acceptance

From the repository root:

```bash
uv run evitriage experiment preflight \
  --manifest configs/projects/private-rocketmq-resource-leak-v2-manifest.yaml \
  --json
uv run evitriage experiment run \
  --manifest configs/projects/private-rocketmq-resource-leak-v2-manifest.yaml \
  --dry-run \
  --json
```

The private manifest and three ProjectSpecs are ignored and must never be
committed because they contain host-specific absolute paths. Existing SARIF is
used deliberately: RocketMQ has no checked-in Maven Wrapper, so EviTriage
`--scan` must not bypass the wrapper-only boundary. Offline acceptance also
requires the repository's `uv sync --all-extras`, `make check`,
`make security-test`, `make demo`, doctor, four ProjectSpec validations,
ingest smoke, focused resource tests, Replay end-to-end, and `git diff --check`.

## Mandatory authorization boundary

After all offline checks pass, stop before credential loading or the first
DeepSeek connection. On WSL, the preferred persistent provider is pass/GPG:

```bash
pass init <operator-GPG-key-id>
uv run evitriage credentials set-deepseek --provider pass
uv run evitriage credentials status --json
```

The operator enters the key only in their WSL terminal through the hidden
double prompt. Never place it in chat, YAML, `.env`, arguments, logs, artifacts,
or Git. A one-process environment value may not propagate into the agent's
separate process.

## Authorized execution and outputs

After explicit authorization, first check non-secret credential status, then
run one 3–6-call synthetic smoke, inspect redaction/artifacts, and only then run
the sequential 111–222-call batch. 401/403 are not retried; 429, 5xx, and
transient network failures have finite retries. Any failed case makes the
experiment incomplete until a successful rerun.

The isolated V2 aggregate root contains `preflight.json`, resolved manifest,
per-run directories, `automatic-decisions.jsonl`, `historical-comparison.json`,
summary, bilingual Markdown, escaped HTML, redacted execution summary, and
`SHA256SUMS`. Only after these are frozen may `experiment evaluate` create
`evaluation-v1-baseline.json` and refresh the checksum index.

The historical report must keep two facts separate: the pre-fix target receives
a model/policy decision, while the post-fix corresponding CodeQL occurrence is
absent; absence is not an FP model decision. The full-suite count is 680→679.
The current evaluation compares 26 automatic decisions with the V1 5 TP / 18 FP
/ 3 NMC review and reports every match, mismatch, NMC, and alignment gap without
calling agreement “accuracy.”


## Observed 2026-08-14 execution

The first resource batch remained `incomplete`: five non-empty cases failed
after the permitted Analyst repair because non-empty evidence references were
not visible in JSON Schema. The JDBC zero-result case completed and failed runs
retained redacted invocation metadata. Resource Schema 1.0 was tightened with
`minItems: 1`; 34 focused tests, `make check`, and `make security-test` passed,
and a one-alert RocketMQ resource smoke completed with three accepted calls.

The successful aggregate is
`artifacts/rocketmq-resource-leak-20260812-v2/attempt-2`. All 37 occurrences
completed with 111 accepted calls, zero repair, and zero failure. Judge
candidates were 25 FP / 1 TP / 11 NMC; policy finalized 37 NMC because 19 had
unknown/unresolved obligations, 7 had incomplete resource context, and 11 were
already Judge NMC. The pre-fix historical target was NMC; the post-fix
occurrence was absent, with 6→5 target-query and 680→679 full-suite counts.

Only after automatic decisions were owner-read-only did evaluation open V1.
All 26 current occurrences aligned: V1 was 5 TP / 18 FP / 3 NMC, V2 was
0 / 0 / 26, agreement was 3/26 (11.54%), determined rate was 0%, and NMC rate
was 100%. Eleven historical occurrences intentionally had no V1 row. This is
engineering evidence about conservative closure, not unbiased accuracy.
