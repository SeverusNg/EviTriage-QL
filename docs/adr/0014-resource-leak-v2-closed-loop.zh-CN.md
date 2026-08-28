# ADR 0014：分离资源泄露研判并闭合 existing-SARIF 实验

[English](0014-resource-leak-v2-closed-loop.md) | [简体中文](0014-resource-leak-v2-closed-loop.zh-CN.md)

- **状态：** 离线实现已接受；真实 RocketMQ 证据等待授权
- **日期：** 2026-08-14
- **适用范围：** Java 资源泄露工作流、策略、证据、批处理与评估

## 背景

legacy Gate D 路径要求安全漏洞的 source/data-flow/sink 证据；资源泄露需要推理
获取成功、资源身份、退出覆盖、释放与所有权/生命周期。扩展 legacy claim enum
会改变其 response schema 和 canonical Replay hash。CodeQL problem query 也可能
没有 `codeFlows`，原 path/function slice 不一定把可用生命周期源码送入模型。

RocketMQ 实验还要求在任何付费模型调用前验证全部冻结输入身份，并且 V1 人工
复核必须在自动决策不可变之前保持隔离。

## 决策

1. 仅将四个精确资源 rule ID 分派到独立版本化 `resource-leak-1.0` 工作流，
   保持 legacy schema 和 Replay 身份不变。
2. 将完整受限方法源码注册为不可信证据，增加词法生命周期/退出候选和受限
   同文件一跳 callee。记录所有解析/预算/源码 omission，不把词法观察升级成
   已验证语义。
3. 使用严格资源 Analyst/Rebuttal/Judge 输出。每个角色最多一次 repair，只能
   引用精确 SARIF occurrence 的证据。
4. 使用独立保守策略。TP 要求获取成功、存在可行未释放退出且没有释放/所有权
   冲突；FP 要求全路径释放覆盖或已证明的所有权/callee/生命周期契约；关键
   事实 unknown、partial 或 conflicting 时强制 NMC。
5. 增加严格 existing-SARIF manifest runner。在访问 profile/凭据前全局检查
   commit、cleanliness、SHA、结果计数/查询族、ProjectSpec 和根目录；随后为
   每个 case 创建独立 run 并顺序执行。保留零结果与部分成功；模型失败绝不
   转换成 NMC，也不把 incomplete 批次报告成 complete。
6. 先聚合报告和历史前后比较，生成 checksum 并冻结；然后独立 evaluator 才能
   打开 V1 基线，只按精确 raw occurrence 身份连接。
7. 目标专用路径只存在于被忽略的 manifest/ProjectSpec，不在核心逻辑加入
   RocketMQ 例外；没有已检入 wrapper 时不调用 `--scan`。

## 后果

资源请求拥有独立 schema/Prompt hash，不会使 legacy Replay fixture 失效。模型
请求包含 provenance 绑定的受限源码和证据，但仍可能包含机密仓库文本，因此
远程使用需要明确授权并保持凭据分离。

缺少编译器/CFG/别名证明、第三方实现、框架契约或自定义协议时，保守策略会
输出 NMC。这是有意行为。本次不增加 `javap` adapter 或在线源码获取。

批处理顺序运行且没有 checkpoint continuation。失败后成功 sibling 仍可审计，
但聚合状态保持 incomplete。固化后基线比较是工程 agreement 研究，不是独立
准确率基准。

## 验证

离线验收覆盖精确分派、legacy Replay 稳定、TWR/finally/return/throw/break/
continue 与锁获取等生命周期路径、所有权和未知 callee、Prompt injection、严格
证据 ID、一次 repair、零结果闭合、模型前 preflight、模型失败语义、路径/
symlink/HTML/secret 边界、Fake/Replay 端到端和冻结 RocketMQ dry-run。只有操作
者明确授权 DeepSeek smoke 与有界完整实验后，才允许执行真实验证。
