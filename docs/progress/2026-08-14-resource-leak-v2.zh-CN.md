# 资源泄露 V2 实现与真实实验记录

[English](2026-08-14-resource-leak-v2.md) | [简体中文](2026-08-14-resource-leak-v2.zh-CN.md)

**日期：** 2026-08-14  
**状态：** 经授权的真实闭环已完成；37 条最终决策均为保守 NMC

## 已实现并验证

- 四类资源精确分派，legacy security 身份不变。
- 独立严格资源 Analyst/Rebuttal/Judge schema 与 fail-closed policy。
- 有界方法/生命周期/callee 证据、显式 gap 和惰性不可信源码边界。
- manifest 全局 preflight、顺序 run、零结果闭合、audit-only suite、不可变双语
  聚合、历史比较和固化后评估。
- 资源证据数组显式声明 `minItems: 1`；唯一 repair 获得有界字段级问题，未知
  evidence ID 仍会被拒绝。

live 修复后的最终检查为：`make check`（退出 0，285 passed，coverage 81.62%）、
`make security-test`（退出 0，41 passed）、资源/Fake/Replay/batch focused（退出 0，
34 passed）和 preflight（退出 0，37 条，111–222 次）。此前规定的 doctor、四个
ProjectSpec validate、ingest smoke、`make demo`、dry-run 和 `git diff --check` 也
均退出 0。

## 经授权的真实执行

凭据状态选择 pass/GPG，没有暴露 Key。合成 legacy smoke run
`20260814T060228810603Z-9e5fc3d0979b` 完成三次调用。第一次资源 batch 正确结束
为 `incomplete`：五个非空 case 在一次 Analyst repair 后仍为
`MODEL_RESPONSE_INVALID`；JDBC 零结果完成，脱敏失败记录得到保留。修复后单条
资源 smoke run `20260814T063250067970Z-79184cd88a3a` 以三次 accepted 完成。

成功聚合根为
`/home/nigeriacrop/code/EviTriage-QL/artifacts/rocketmq-resource-leak-20260812-v2/attempt-2`。

| Case | Run ID | 告警 / 调用 | 最终 |
| --- | --- | ---: | --- |
| historical pre lock | `20260814T063819539272Z-38a0d7507184` | 6 / 18 | 6 NMC |
| historical post lock | `20260814T064412825418Z-8cbf3ce0c9ac` | 5 / 15 | 5 NMC |
| current input | `20260814T064907745727Z-7311b1478da2` | 3 / 9 | 3 NMC |
| current output | `20260814T065147952685Z-463aabc33e45` | 1 / 3 | 1 NMC |
| current database | `20260814T065258895366Z-e5e1b5aac419` | 0 / 0 | 零结果完整结束 |
| current lock | `20260814T065300685754Z-87089c69c61b` | 22 / 66 | 22 NMC |

最终 111 次调用均为 accepted attempt 0：三角色各 37 次，无 repair、无失败。
Judge 候选为 25 FP / 1 TP / 11 NMC。策略因 19 条
`unknown_or_unresolved`、7 条 `resource_context_incomplete` 和 11 条
`judge_requested_nmc`，最终输出 37 NMC；`auto_dismiss` 始终为 false。

## 历史与基线比较

修复前 `sendHeartbeatToBroker` 目标为 NMC，并绑定已注册关键证据；修复后同一
occurrence 消失，而不是模型 FP。专项为 6→5，完整 suite 为 680→679。自动决策
先固化，且 `baseline_registered_as_model_evidence=false`，评估才读取 V1。

26 条当前告警全部对齐。V1 为 5 TP / 18 FP / 3 NMC，V2 为 0 / 0 / 26；一致
3/26（11.54%），determined rate 0%，NMC rate 100%。11 条历史告警按设计没有
V1 行。这是工程比较，不是无偏准确率。下一能力边界是编译器级 CFG/异常覆盖、
更强 alias identity、本地 callee/所有权摘要；可能需要自定义 CodeQL 证据查询。
