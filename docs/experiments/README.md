# Experiments

[English](README.md) | [简体中文](README.zh-CN.md)

This directory contains reviewable evidence handoffs for real-project experiments. Each package distinguishes checked facts, evidence judgments, unverified hypotheses, and product capability gaps. Raw third-party source, CodeQL databases, SARIF, build outputs, runtime workspaces, model responses, and credentials remain outside Git.

## Available evidence packages

- [Apache RocketMQ resource-leak experiment (2026-08-12)](rocketmq-resource-leak-20260812/README.md): historical lock-leak regression, current-revision CodeQL scan, 26 human-reviewed resource alerts, EviTriage existing-SARIF compatibility result, and a frozen-input contract for a future autonomous V2 rerun.
