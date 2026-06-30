# FluffOS_XK Engine Overview / FluffOS_XK 引擎概览

## Positioning / 项目定位

FluffOS_XK is a production-oriented FluffOS maintenance fork for modern LPC/MUD
projects. It is meant to be consumed as an engine repository: game mudlibs,
world data, accounts, deployment secrets, and operational policy stay in
downstream game repositories.

FluffOS_XK 是面向现代 LPC/MUD 项目的生产型 FluffOS 维护分支。它应作为引擎仓库被下游消费：
游戏 mudlib、世界数据、账号、部署密钥和运维策略应保留在下游游戏仓库。

The upstream FluffOS project remains the canonical base. FluffOS_XK is a
downstream-friendly engine line for projects that need a stable integration
target, controlled multicore execution, and modern LPC migration tools.

上游 FluffOS 仍是 canonical base。FluffOS_XK 是面向下游集成的引擎线，适合需要稳定接入目标、
受控多核执行和现代 LPC 迁移工具的项目。

## What It Adds / 新增能力

- Predictable CMake builds on current Linux, WSL, and Windows/MSYS2 toolchains.
- Owner/service multicore execution for production mudlib migration.
- LPC Modern Runtime with opt-in pragmas, owner audit, owner-safe APIs, and
  source encoding boundaries.
- Gateway/session behavior for WebSocket-facing clients and explicit session
  FIFO contracts.
- VM hot-path profiling, owner runtime benchmark reports, object-store fast-path
  diagnostics, and stress smoke gates.
- Security and CI maintenance suitable for public review.

- 面向当前 Linux、WSL 和 Windows/MSYS2 工具链的稳定 CMake 构建。
- 面向生产 mudlib 迁移的 owner/service 多核执行。
- LPC Modern Runtime：按需启用 pragma、owner audit、owner-safe API 和源码编码边界。
- 面向 WebSocket 客户端的 gateway/session 行为，以及明确的 session FIFO 合同。
- VM 热路径 profiling、owner runtime benchmark 报告、object-store fast-path 诊断和 stress smoke 门禁。
- 适合公开审查的安全与 CI 维护。

## Production Multicore Baseline / 生产多核基线

The multicore model is controlled, explicit, and compatibility-minded. It does
not make arbitrary legacy LPC run freely on background threads.

The sealed production path covers:

- owner-local object lifecycle;
- OwnerExecutor callback tasks;
- heartbeat and callout execution;
- async/file/db, DNS, and socket callbacks;
- gateway command execution;
- target-owner messages;
- socket release/acquire handshakes.

Executor entry requires an explicit owner-safe path: same-owner execution,
allowlist coverage, driver callback task, frozen payload, ObjectHandle route,
owner future, commit proposal, or service shard domain.

多核模型是受控、显式且兼容优先的。它不会把任意 legacy LPC 自动放到后台线程执行。

已封版的生产路径覆盖：

- owner-local object lifecycle；
- OwnerExecutor callback task；
- heartbeat 与 callout execution；
- async/file/db、DNS 和 socket callback；
- gateway command execution；
- target-owner message；
- socket release/acquire handshake。

进入 executor 必须具备明确 owner-safe 路径：same-owner execution、allowlist coverage、
driver callback task、frozen payload、ObjectHandle route、owner future、commit proposal
或 service shard domain。

## LPC Modern Runtime / LPC 现代运行时

FluffOS_XK does not replace LPC. It adds modern contracts on top of LPC:

- `#pragma modern_lpc`
- `#pragma strict_owner`
- `#pragma source_encoding("GBK")`
- `lpcc --owner-audit --format=json`
- `freeze`, `snapshot`, `owner_async`, `owner_await`, `owner_commit`
- VM profiling and dispatch cache probes

FluffOS_XK 不替换 LPC，而是在 LPC 之上增加现代合同：

- `#pragma modern_lpc`
- `#pragma strict_owner`
- `#pragma source_encoding("GBK")`
- `lpcc --owner-audit --format=json`
- `freeze`、`snapshot`、`owner_async`、`owner_await`、`owner_commit`
- VM profiling 和 dispatch cache probe

Legacy mudlibs continue to run on the classic path unless they opt into these
contracts.

旧 mudlib 默认继续走经典路径，只有主动启用后才进入这些合同。

## Integration Model / 集成模型

Recommended downstream flow:

1. Pin a FluffOS_XK commit or release tag.
2. Build `driver`, `lpcc`, and `lpc_tests`.
3. Run engine tests and runtime contracts.
4. Copy built binaries into the downstream runtime tree.
5. Run downstream smoke and audit checks against login, gateway commands,
   movement, persistence, reconnect, heartbeat, callout, and callback paths.

推荐下游流程：

1. 固定一个 FluffOS_XK commit 或 release tag。
2. 构建 `driver`、`lpcc` 和 `lpc_tests`。
3. 运行引擎测试和 runtime contract。
4. 将构建产物复制到下游运行树。
5. 在项目侧验证登录、gateway command、移动、持久化、断线重连、heartbeat、callout 和 callback。

This keeps engine upgrades reviewable and prevents game-specific runtime assets
from being mixed into the engine repository.

这样可以让引擎升级可审查，并避免把游戏特定运行资产混入引擎仓库。

## Safety Boundaries / 安全边界

FluffOS_XK is intentionally conservative:

- ordinary legacy LPC background execution remains default-closed;
- mutable cross-owner state must use snapshot, message, future, commit, or
  shard-domain contracts;
- main-thread work is limited to IO adapters, cleanup adapters, explicit
  fallback, and documented compatibility surfaces;
- production status is represented by machine-readable runtime contracts rather
  than informal claims.

FluffOS_XK 有意保持保守：

- 普通 legacy LPC 默认不开放后台执行；
- 可变 cross-owner state 必须使用 snapshot、message、future、commit 或 shard-domain 合同；
- main-thread 工作只限 IO adapter、cleanup adapter、显式 fallback 和明确兼容面；
- 生产状态由机器可读 runtime contract 表达，而不是靠非正式说明宣称。

These boundaries are part of the production design, not deferred work.

这些边界是生产设计的一部分，不是延期未完成工作。

## When To Use It / 什么时候使用

Use FluffOS_XK when you need:

- a modern FluffOS-compatible LPC runtime;
- a source-level engine baseline that can be audited and rebuilt;
- a safe migration path from single-threaded global mudlib services toward
  owner/service execution;
- a driver suitable for gateway-backed web or mobile clients;
- clear separation between engine code and private game operations.

当你需要以下能力时，可以使用 FluffOS_XK：

- 现代 FluffOS-compatible LPC runtime；
- 可审计、可重建的源码级引擎基线；
- 从单线程全局 mudlib 服务迁移到 owner/service execution 的安全路径；
- 适合 gateway-backed web/mobile client 的 driver；
- 清晰分离引擎代码和私有游戏运维。

Do not use this repository to store a complete mudlib, accounts, private
deployment scripts, or project-specific secrets.

不要把完整 mudlib、账号、私有部署脚本或项目密钥放进本仓库。

## Key References / 关键参考

- [README / 项目说明](../README.md)
- [README_CN / 中文说明](../README_CN.md)
- [LPC Modern Runtime / LPC 现代运行时](./lpc-modern-runtime.md)
- [Owner Multicore API / Owner 多核接口](./owner-multicore-api.md)
- [Multicore Runtime v4 / 多核运行时 v4](./multicore-runtime-v4.md)
- [Multicore Runtime v2 / 多核运行时 v2](./multicore-runtime-v2.md)
- [Production Gate / 生产门禁](./multicore-production-gate.md)
- [Production Baseline Release Note / 生产基线发布说明](./releases/multicore-production-baseline-2026-06-27.md)
