# Apache RocketMQ Resource-Leak Experiment (2026-08-12)

[English](README.md) | [简体中文](README.zh-CN.md)

This directory is the reviewable, Git-safe evidence package for the first real-project resource-leak experiment performed against Apache RocketMQ with CodeQL 2.26.1 and EviTriage-QL 0.2.0.

It deliberately does **not** contain RocketMQ source code, CodeQL databases, raw SARIF, Maven outputs, EviTriage workspaces, model requests/responses, or credentials. Those inputs and run artifacts remain outside Git. The package records their identities, locations, hashes, counts, commands, exit codes, and manually reviewed alert outcomes so the same frozen inputs can be reused after EviTriage gains a resource-specific autonomous triage path.

## Contents

- [report.md](report.md): detailed English experiment report, including the historical regression, current-version scan, EviTriage compatibility result, and evidence-backed conclusions.
- [report.zh-CN.md](report.zh-CN.md): semantically aligned Simplified Chinese report.
- [experiment-manifest.json](experiment-manifest.json): machine-readable repository/tool/build/database/SARIF/EviTriage run inventory.
- [alert-triage.jsonl](alert-triage.jsonl): one record for each of the 26 current-version resource-leak alerts, with TP/FP/NMC labels and concise evidence. These are human evidence reviews, not model outputs.
- `SHA256SUMS`: SHA-256 identities for the nine frozen external SARIF inputs and the original host-local report.

## Confirmed result at a glance

- The historical pre-fix revision produced six `java/unreleased-lock` alerts. The post-fix revision produced five. The removed alert precisely identified `MQClientInstance.sendHeartbeatToBroker` and disappeared after commit `a6c5604b6cb6fce255fe9e0e6e860f94d37c2050` moved the risky operations under `try/finally`.
- The current RocketMQ revision produced 26 alerts across the four requested resource queries: 3 input, 1 output, 0 database, and 22 lock alerts.
- Manual evidence review classified them as 5 TP, 18 FP, and 3 NMC. This is a review baseline, not an independent ground-truth benchmark.
- EviTriage successfully ingested and contextualized all four code-quality SARIF files. Offline triage then stopped honestly at `MODEL_FAILED` with `MODEL_REPLAY_MISS`: the checked-in replay cache has no resource-leak response, no remote model was authorized, and no automatic TP/FP/NMC label was produced.
- The present EviTriage prompt/schema is security-exploit-oriented and lacks explicit resource acquisition, release coverage, and ownership-transfer claims. Completing the autonomous loop therefore requires a code change before reusing the frozen SARIF inputs for Experiment V2.

## External preservation map

The paths below are host-local and intentionally Git-ignored or outside the repository:

| Purpose | Host-local path | Preservation rule |
|---|---|---|
| RocketMQ mirror/current source | `/home/nigeriacrop/code/third-party/rocketmq` | Keep outside EviTriage Git |
| Frozen experiment root: worktrees, Maven, CodeQL DBs, SARIF, logs | `/home/nigeriacrop/code/third-party/rocketmq-resource-leak-20260812` | Treat as read-only V1 evidence |
| EviTriage ingest/triage runs and original Chinese report | `/home/nigeriacrop/code/EviTriage-QL/artifacts/rocketmq-resource-leak-20260812` | Git-ignored; do not delete |
| EviTriage source snapshots/workspaces | `/home/nigeriacrop/code/EviTriage-QL/workspaces` | Git-ignored; retain run IDs referenced by the report |
| Private local ProjectSpec | `/home/nigeriacrop/code/EviTriage-QL/configs/projects/private-rocketmq-resource-leak.yaml` | Git-ignored; never publish private provider settings |

The original host-local report has SHA-256 `4282758d08a0cb583c217f5a64247d4b3b1da59d5939b6b9e37403725dfecfd9`. Raw SARIF identities are recorded in `SHA256SUMS` and `experiment-manifest.json`.

## Experiment V2 contract

Do not overwrite the V1 evidence. After implementing resource-aware claims, evidence collection, replay fixtures/provider authorization, and decision policy:

1. create a new V2 artifact/workspace root;
2. verify every reused SARIF file against this package's SHA-256 inventory;
3. run EviTriage on the unchanged SARIF and unchanged RocketMQ snapshot;
4. preserve the V2 model inputs, outputs, policy decisions, logs, and report under new run IDs;
5. compare automatic labels with `alert-triage.jsonl`, while continuing to describe the latter as a human review baseline rather than unquestionable ground truth.

No source was modified, no SARIF was fabricated, no policy was relaxed, and no GitHub issue or upstream pull request was created during V1.
