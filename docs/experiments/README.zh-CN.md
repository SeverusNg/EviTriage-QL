# 实验记录

[English](README.md) | [简体中文](README.zh-CN.md)

本目录保存真实项目实验中适合评审的证据交接材料。每个证据包都会区分已确认事实、证据判断、未验证假设与产品能力缺口。第三方源码、CodeQL 数据库、SARIF、构建产物、运行工作区、模型响应和凭据继续保存在 Git 之外。

## 已有证据包

- [Apache RocketMQ 资源泄露实验（2026-08-12）](rocketmq-resource-leak-20260812/README.zh-CN.md)：历史锁泄露回归、当前版本 CodeQL 扫描、26 条资源告警人工复核、EviTriage existing-SARIF 兼容性结论，以及供未来自动闭环 V2 复用的冻结输入约定。
