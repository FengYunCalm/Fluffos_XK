# FluffOS_XK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CMake](https://img.shields.io/badge/build-CMake-blue.svg)](CMakeLists.txt)
[![LPC Runtime](https://img.shields.io/badge/runtime-LPC%20%2F%20MUD-informational.svg)](https://www.fluffos.info)
[![Multicore](https://img.shields.io/badge/multicore-owner%2Fservice%20executor-success.svg)](docs/multicore-runtime-v4.md)

中文在前；每个主要章节后提供英文说明。
Chinese first. English follows each major section.

## 这个引擎是什么

FluffOS_XK 是面向现代 LPC/MUD 项目的生产型 FluffOS 引擎分支。它保留 LPC
和经典 FluffOS driver 模型，同时加入已经完成的 owner/service 多核运行时、
按需启用的现代 LPC 合同、源码/会话编码边界、VM 热路径诊断，以及适合下游项目长期维护的工程边界。

本仓库应作为引擎源码树，或作为重建 `driver` 与 `lpcc` 二进制的来源。
mudlib、世界内容、账号、部署密钥和运维策略应留在游戏项目仓库中。

FluffOS_XK is a production-oriented FluffOS engine fork for modern LPC/MUD
projects. It keeps LPC and the classic FluffOS driver model, then adds a
completed owner/service multicore runtime, opt-in modern LPC contracts,
source/session encoding boundaries, VM hot-path diagnostics, and
downstream-friendly maintenance practices.

Use this repository as an engine source tree or as the source for rebuilt
`driver` and `lpcc` binaries. Keep mudlib content, world data, accounts,
deployment secrets, and operations policy in your game repository.

## 为什么值得用

- **受控多核执行**：owner/service executor 路径覆盖 object lifecycle、heartbeat、
  callout、async/file/db、DNS、socket callback、gateway command、target-owner
  message 和 socket release/acquire handshake。
- **不破坏旧 LPC 的现代化**：`#pragma modern_lpc` 与 `#pragma strict_owner`
  是按需启用能力。旧 mudlib 默认保持原行为，只有新代码主动选择后才进入更严格合同。
- **显式 owner-safe API**：mudlib 可以使用 `freeze`、`snapshot`、
  `owner_async`、`owner_await`、`owner_commit`、owner future、ObjectHandle
  route 和 service shard domain，避免跨 owner 传递可变对象。
- **编码兼容放在正确边界**：VM 内部字符串保持规范 UTF-8；遗留源码、玩家会话、
  gateway payload 和外部文本可在明确边界使用 GBK、GB2312、Big5 或其他 ICU 支持编码。
- **运行行为可量化**：VM profiling、owner runtime status、benchmark report、
  stress script、队列/反压计数、fallback 计数和 stale/drop 分类让生产行为可审计。

- **Controlled multicore execution**: owner/service executor paths cover object
  lifecycle, heartbeat, callout, async/file/db, DNS, socket callbacks, gateway
  commands, target-owner messages, and socket release/acquire handshakes.
- **Modern LPC without breaking legacy code**: `#pragma modern_lpc` and
  `#pragma strict_owner` are opt-in. Existing mudlibs keep legacy behavior until
  they choose stricter contracts.
- **Explicit owner-safe APIs**: mudlibs can use `freeze`, `snapshot`,
  `owner_async`, `owner_await`, `owner_commit`, owner futures, ObjectHandle
  routing, and service shard domains instead of passing mutable objects across
  owner boundaries.
- **Encoding compatibility at the right boundary**: VM strings remain canonical
  UTF-8, while legacy source files, player sessions, gateway payloads, and
  external text can opt into GBK, GB2312, Big5, or other ICU-supported encodings
  at explicit boundaries.
- **Measurable runtime behavior**: VM profiling, owner runtime status, benchmark
  reports, stress scripts, queue/backpressure counters, fallback counters, and
  stale/drop classifications make production behavior auditable.

## 运行时边界

FluffOS_XK 不会把任意 legacy LPC 自动放到后台线程执行，这是有意保守的安全边界。
普通 LPC 默认不开放后台执行。进入多核路径必须满足以下合同之一：

- same-owner 直接执行；
- driver callback allowlist；
- frozen mapping/array payload；
- ObjectHandle route；
- owner message/future；
- owner/service commit proposal；
- keyed service shard domain。

main thread 仍可作为 IO adapter、cleanup adapter、显式兼容 fallback 和明确的
main-required 兼容面。生产业务正常路径要求 `normal_path_main_fallback_count=0`。

FluffOS_XK does not make arbitrary legacy LPC run freely on background threads.
That is deliberate. Normal LPC remains default-closed for background execution.
The multicore path requires same-owner execution, a driver callback allowlist,
frozen payloads, ObjectHandle routing, owner futures, commit proposals, or keyed
service shard domains.

The main thread remains available for IO adapters, cleanup adapters, explicit
compatibility fallback, and documented main-required surfaces. Production
business paths are expected to keep `normal_path_main_fallback_count=0`.

## 现代 LPC 示例

```c
#pragma modern_lpc
#pragma strict_owner
#pragma source_encoding("GBK")

mapping submit_reward_commit(string player_id, mapping reward) {
    mapping frozen = freeze(([
        "player_id": player_id,
        "reward": reward,
    ]));

    if (!frozen["ok"]) {
        return frozen;
    }

    return owner_async("service/reward/" + player_id, ([
        "type": "owner_task_reward",
        "payload_key": "reward/commit/v1",
        "payload": frozen["value"],
    ]));
}
```

迁移旧代码前可以先审计：

```bash
build/bin/lpcc --owner-audit --format=json etc/config.test path/to/file.c
```

The example enables modern LPC and strict owner audit explicitly, freezes data
before it crosses an owner boundary, and submits work through `owner_async`.
Use `lpcc --owner-audit --format=json` before migrating legacy files.

## 理论性能模型

多核收益来自把相互独立的玩家、房间、物品、callback 和服务工作迁移到 owner/service
路径。它不会让单个 same-owner 命令自动并行，也不会消除 IO adapter 或全局协调这类串行部分。

| 负载类型 | 预期表现 |
|---|---|
| 单玩家轻命令路径 | 通常收益很小；兼容层开销可能盖过收益。 |
| 多玩家分布在不同 owner 或房间 | 吞吐提升明显；命令可分摊到 owner executor。 |
| heartbeat/callout 密集世界 | 尾延迟改善，因为 callback 会被 admission 和分类。 |
| async/db/file/DNS/socket callback 尖峰 | 隔离性更好；frozen result 回到 callback owner。 |
| 全局服务未拆 shard | 会受剩余 service bottleneck 限制。 |
| keyed service shard 和 owner-safe mudlib 改造充分 | 扩展性最好，但仍受串行部分和核心数限制。 |

理论上限符合 Amdahl 定律：

```text
speedup = 1 / (serial_part + parallel_part / cores)
```

若 70% 热路径可按 owner/service 并行，30% 仍串行，8 核机器理论上限约 2.6x；
若 90% 热路径进入 owner/service，8 核理论上限约 4.7x。真实收益取决于 shard key、
mudlib 结构、持久化成本、callback 规模和 fallback 计数。

The multicore runtime improves throughput when a mudlib moves independent
player, room, item, callback, and service work into owner/service paths. It does
not make one same-owner command automatically parallel, and it does not remove
serial work such as IO adapters or unavoidable global coordination.

Real gains depend on shard keys, mudlib structure, persistence cost, callback
volume, and fallback counters.

## 构建与验证

```bash
git clone https://github.com/FengYunCalm/Fluffos_XK.git
cd Fluffos_XK
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target driver lpcc lpc_tests -j2
build/src/tests/lpc_tests
```

运行时合同验证：

```bash
build/src/tests/lpc_tests --gtest_filter=DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract
cd testsuite && ../build/bin/driver etc/config.test -ftest:single/tests/efuns/owner_executor_contract
tools/lpc-modern-runtime-stress.sh smoke
```

性能与诊断报告：

```bash
cmake --build build --target owner_runtime_bench lpc_vm_bench object_store_bench -j2
build/src/tests/owner_runtime_bench --json build/reports/owner_runtime_bench.json
build/src/tests/lpc_vm_bench --json build/reports/lpc_vm_bench.json
build/src/tests/object_store_bench --json build/reports/object_store_bench.json
```

Build with CMake, then run `lpc_tests`, the LPC owner executor contract, and the
modern runtime smoke gate. Benchmark JSON is for trend analysis and regression
diagnostics, not for machine-specific absolute timing thresholds.

## 下游集成方式

推荐流程：

1. 固定一个 FluffOS_XK commit 或 release tag。
2. 构建 `driver`、`lpcc` 和 `lpc_tests`。
3. 运行引擎测试和 runtime contract。
4. 将重建的二进制同步到游戏运行树。
5. 在项目侧验证登录、gateway、命令、移动、持久化、断线重连、heartbeat、callout 和 callback。
6. 使用 `lpcc --owner-audit --format=json` 与 `vm_owner_runtime_status()` 验证真实 owner/service 使用情况。

Recommended flow for a game repository:

1. Pin a FluffOS_XK commit or release tag.
2. Build `driver`, `lpcc`, and `lpc_tests`.
3. Run engine tests and runtime contracts.
4. Copy the rebuilt binaries into the game runtime tree.
5. Run game-level smoke tests for login, gateway, commands, movement,
   persistence, reconnect, heartbeat, callout, and callbacks.
6. Use `lpcc --owner-audit --format=json` and `vm_owner_runtime_status()` to
   verify real owner/service usage.

## 文档

- [Documentation index / 文档入口](docs/index.md)
- [Engine overview / 引擎概览](docs/fluffos-xk-overview.md)
- [Build guide / 构建指南](docs/build.md)
- [LPC Modern Runtime / LPC 现代运行时](docs/lpc-modern-runtime.md)
- [Owner Multicore API / Owner 多核接口](docs/owner-multicore-api.md)
- [Multicore Runtime v4 / 多核运行时 v4](docs/multicore-runtime-v4.md)
- [Production Gate / 生产门禁](docs/multicore-production-gate.md)
- [Driver CLI](docs/cli/driver.md)
- [lpcc CLI](docs/cli/lpcc.md)
- [LPC Reference](docs/lpc/index.md)

## 上游与许可

上游 FluffOS 仍是 canonical base：<https://github.com/fluffos/fluffos>
官方文档：<https://www.fluffos.info>

许可证为 [MIT](LICENSE)。历史 LPmud/MudOS notice 保留在 [Copyright](Copyright)、
[NOTICE](NOTICE) 和 `src/thirdparty/*`。

Upstream FluffOS remains the canonical base: <https://github.com/fluffos/fluffos>
Official FluffOS documentation: <https://www.fluffos.info>

License: [MIT](LICENSE). Historical LPmud/MudOS notices remain in
[Copyright](Copyright), [NOTICE](NOTICE), and `src/thirdparty/*`.
