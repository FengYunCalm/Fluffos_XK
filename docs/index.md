---
layout: doc
title: FluffOS_XK Documentation
---

# FluffOS_XK Documentation / FluffOS_XK 文档

## Current Project Status / 当前项目状态

FluffOS_XK is a production-oriented FluffOS maintenance fork for modern LPC/MUD
projects. The current `master` branch includes the completed owner/service
multicore runtime baseline, Runtime v4 hardening, LPC Modern Runtime contracts,
source/session encoding boundaries, VM diagnostics, and benchmark/stress entry
points.

FluffOS_XK 是面向现代 LPC/MUD 项目的生产型 FluffOS 维护分支。当前 `master`
已经包含完成的 owner/service 多核基线、Runtime v4 加固、LPC Modern Runtime
合同、源码/会话编码边界、VM 诊断以及 benchmark/stress 入口。

Ordinary legacy LPC remains compatible and default-closed for arbitrary
background execution. Multicore execution requires explicit owner-safe contracts:
same-owner execution, driver callback allowlists, frozen payloads, ObjectHandle
routing, owner futures, commit proposals, or service shard domains.

普通 legacy LPC 仍保持兼容，并且默认不开放任意后台执行。进入多核路径必须使用明确的
owner-safe 合同：same-owner 执行、driver callback allowlist、frozen payload、
ObjectHandle route、owner future、commit proposal 或 service shard domain。

## Start Here / 推荐入口

- [README / 项目说明](../README.md)
- [README_CN / 中文说明](../README_CN.md)
- [Engine Overview / 引擎概览](./fluffos-xk-overview.md)
- [Build Guide / 构建指南](./build.md)
- [Driver CLI](./cli/driver.md)
- [lpcc CLI and owner audit / lpcc 命令与 owner 审计](./cli/lpcc.md)

## Modern Runtime / 现代运行时

- [LPC Modern Runtime / LPC 现代运行时](./lpc-modern-runtime.md)
- [Owner Multicore API / Owner 多核接口](./owner-multicore-api.md)
- [Multicore Runtime v4 / 多核运行时 v4](./multicore-runtime-v4.md)
- [Multicore Runtime v2 Contract / 多核 Runtime v2 合同](./multicore-runtime-v2.md)
- [Production Gate / 生产门禁](./multicore-production-gate.md)
- [Production Baseline Release Note / 生产基线发布说明](./releases/multicore-production-baseline-2026-06-27.md)

## LPC Reference / LPC 参考

- [LPC Reference Index / LPC 参考入口](./lpc/index.md)
- [EFUN Reference / EFUN 参考](./efun/index.md)
- [Apply Reference / Apply 回调参考](./apply/index.md)
- [Interactive Encoding: set_encoding / 交互编码：set_encoding](./efun/interactive/set_encoding.md)
- [Chinese set_encoding Reference / 中文 set_encoding 文档](./zh-CN/efun/set_encoding.md)

## Diagnostics And Verification / 诊断与验证

Core verification commands:

```bash
cmake --build build --target lpc_tests driver -j2
build/src/tests/lpc_tests
build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract
cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract
tools/lpc-modern-runtime-stress.sh smoke
```

核心验证命令：

```bash
cmake --build build --target lpc_tests driver -j2
build/src/tests/lpc_tests
build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract
cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract
tools/lpc-modern-runtime-stress.sh smoke
```

Benchmark reports:

```bash
cmake --build build --target owner_runtime_bench lpc_vm_bench object_store_bench -j2
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
```

性能报告入口：

```bash
cmake --build build --target owner_runtime_bench lpc_vm_bench object_store_bench -j2
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
```

## Historical Material / 历史材料

Historical MudOS/FluffOS documents are preserved under `docs/archive/`. Historical
multicore plans and v1 notes are under
[docs/archive/multicore](./archive/multicore/README.md). They are kept for
traceability and should not be treated as the current runtime contract.

历史 MudOS/FluffOS 文档保存在 `docs/archive/`。历史多核计划和 v1 笔记保存在
[docs/archive/multicore](./archive/multicore/README.md)。它们用于溯源，不应作为当前运行时合同。

## Upstream / 上游

Upstream FluffOS remains the canonical base: <https://github.com/fluffos/fluffos>.
FluffOS official documentation: <https://www.fluffos.info>.

上游 FluffOS 仍是 canonical base：<https://github.com/fluffos/fluffos>。
FluffOS 官方文档：<https://www.fluffos.info>。
