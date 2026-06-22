# FluffOS_XK 项目知识文档

## 结论

FluffOS_XK 是一个面向实际 MUD/LPC 运行项目的 FluffOS 维护分支。仓库核心仍是传统单 driver、LPC VM、事件循环和对象系统，但当前主线已经在 owner/actor 方向上完成了多核化基础设施：线程本地 `VMContext`、受控 `VMWorkerRuntime`、owner metadata、owner mailbox、主线程 owner queue、ObjectHandle、owner shard 状态索引、cross-owner 访问审计和 enforced 模式边界。

必须明确：当前项目还没有完成“任意 LPC 在后台线程自由并行执行”。已经完成的是安全边界、任务投递语义、快照/消息/future 合同和部分确定性 worker 任务；真正 owner-local object store、owner executor 正式化、eval stack/value 内存模型收口仍是后续工作。

## 仓库概况

| 项目项 | 当前事实 |
| --- | --- |
| 主语言 | C++17 / C11 |
| 构建系统 | CMake，根入口为 `CMakeLists.txt`，核心入口为 `src/CMakeLists.txt` |
| 运行时定位 | FluffOS LPC driver，面向 MUD mudlib |
| 当前分支 | `master`，跟踪 `origin/master` |
| 最近 HEAD | `6e6f60e9 Harden cross-owner LPC boundaries` |
| 源码规模 | `src` 下约 2437 个文件 |
| 文档规模 | `docs` 下约 939 个 Markdown 文件 |
| 测试素材 | `src/tests/test_lpc.cc`、`testsuite/`、本地 `.internal` 验收素材 |

## 顶层目录

| 路径 | 作用 |
| --- | --- |
| `src/` | driver 源码、VM、包、网络、编译器、工具和测试 |
| `docs/` | VitePress 文档站、efun/apply 文档、多核化说明 |
| `testsuite/` | LPC 层回归测试和测试 driver 配置 |
| `cmake/` | CMake 查找模块和构建辅助 |
| `compat/` | 兼容层 |
| `build/`、`build-prod/` | 本地构建输出目录 |
| `.internal/` | 本地私有验证素材和压测工具，不应作为公开规则来源 |

## 构建系统

根 `CMakeLists.txt` 只做项目级配置、版本推导、GTest 探测并进入 `src/`。实际构建逻辑集中在 `src/CMakeLists.txt`。

关键构建事实：

- CMake 最低版本为 `3.22`。
- 默认 `CMAKE_BUILD_TYPE` 为 `RelWithDebInfo`。
- C++ 标准固定为 C++17，C 标准固定为 C11。
- `PACKAGE_CORE` 和 `PACKAGE_OPS` 固定启用，其余 package 多数以 CMake option 控制。
- 默认启用 async、compress、contrib、crypto、db、develop、gateway、math、matrix、parser、sockets、uids 等包。
- Linux 非 Windows 平台链接 `Threads::Threads`，这是 worker/owner thread 的基础依赖。
- `libdriver` 聚合 VM、compiler、base、network、package 和 thirdparty 依赖。

常用验证命令：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target driver lpcc lpc_tests
build/src/tests/lpc_tests
cd testsuite && ../build/bin/driver etc/config.test -ftest
```

## 运行时启动与主循环

核心入口包括：

- `src/main.cc`、`src/mainlib.cc`：driver 进程入口、初始化、配置和运行生命周期。
- `src/backend.cc`：事件循环、gametick、heartbeat/callout 推进、主线程 owner queue drain。
- `src/comm.cc`：传统交互连接、用户输入、命令调度。
- `src/packages/gateway/`：gateway/session 路径，服务现代 WebSocket/网关接入。

当前主循环仍承担 LPC VM 主状态维护。多核化改造没有把主线程立即移除，而是先把输入、回调、heartbeat、callout 等入口转换为 owner-aware 任务，再在主线程中按 owner FIFO drain。

## 核心源码分层

| 子系统 | 关键路径 | 责任 |
| --- | --- | --- |
| base | `src/base/` | 配置、日志、内存、文件、平台基础 |
| compiler | `src/compiler/` | LPC 编译、语法、词法、icode、program 生成 |
| vm | `src/vm/` | 对象系统、解释器、apply、VMContext、owner、worker |
| packages/core | `src/packages/core/` | 核心 efun、call_out、heartbeat、file、dns、owner/worker efun |
| packages/async | `src/packages/async/` | async file/db/getdir 等后台 I/O |
| packages/sockets | `src/packages/sockets/` | LPC socket efun 与 socket callback |
| packages/gateway | `src/packages/gateway/` | gateway session 集成 |
| net | `src/net/` | telnet、TLS、WebSocket、协议层 |
| tests | `src/tests/` | C++ driver/VM 测试 |

## VM 与对象系统

传统 FluffOS 对象系统依赖全局状态，例如：

- `current_object`
- `command_giver`
- `current_interactive`
- `previous_ob`
- `current_prog`
- `caller_type`
- eval/error context
- object list/destruct list

当前改造的关键是把这些状态逐步收敛进 `VMContext`，避免后台线程误用主线程全局状态。

关键文件：

- `src/vm/context.h`
- `src/vm/internal/context.cc`
- `src/vm/internal/base/interpret.cc`
- `src/vm/internal/base/object.cc`
- `src/vm/internal/apply.cc`
- `src/vm/internal/simulate.cc`

`VMContext` 当前包含：

- `VMExecutionState`：当前对象、命令发起者、当前 interactive、previous object、当前 program、调用来源、inherit offset、临时栈深度。
- `VMObjectStoreState`：对象链表快照、destructed 对象、主线程归属标记、sync rejection 计数、load depth、restricted destruct object。
- `VMOwnerState`：当前 owner id、owner epoch、LPC canary 标志。
- `VMErrorState`：error context、eval error flags、error handler depth。

`vm_context_sync_object_store()` 只允许主线程同步 object store。非主线程调用会清空快照并累加 rejection，避免把全局对象链表暴露给 worker/owner thread。

## owner 模型

owner 模型是本仓库多核化的中心抽象。每个对象可以带有 owner id 和 owner epoch。

关键文件：

- `src/vm/owner.h`
- `src/vm/internal/owner.cc`
- `src/packages/core/vm_owner.cc`
- `src/packages/core/core.spec`

当前 owner 基础能力：

- 默认 owner 为 `legacy/main`。
- `vm_owner_id()` 查询对象 owner。
- `vm_owner_epoch()` 查询对象生命周期版本。
- `vm_owner_set_id()` 设置 owner 并递增 epoch。
- `vm_owner_guard()` / `vm_owner_guard_epoch()` 做 owner/epoch 约束。
- owner mailbox 支持 enqueue、drain、schedule、purge、status。
- owner trace/access trace/message trace/commit trace 提供迁移观测。
- `VMOwnerScope` 在执行期间绑定当前 owner。
- load/clone/move/exec/destruct 生命周期路径已有 owner 合同回归：singleton load 保持 `legacy/main`，command singleton、std database service、`std/http`、`std/present_clone`、`std/telnet` 这类共享 service 在玩家 owner scope 内仍保持 `legacy/main`，`single/simul_efun` 及其关键继承 helper `std/all_environment`、`std/json` 在玩家 owner scope 内也不会被玩家 owner 污染，`/adm/daemons/gateway_d` daemon singleton 在玩家 owner scope 内仍保持 `legacy/main` 且 system message 以 daemon owner/epoch 记录 trace，master `compile_object` 生成的 virtual object 保持默认 owner 且重命名后同步 owner-local directory path，clone 使用 current object/prototype owner 而不继承裸 ambient owner scope，move 只在 item 没有显式 owner 时继承 destination owner，普通 interactive `exec()` 不把旧对象 owner 污染到新对象，gateway `exec()` 后 session lookup 绑定新 user object 的 owner/epoch，destruct 会从 owner-local directory 清理对象。

owner epoch 的作用是处理 stale task：对象 owner 变化或生命周期变化后，旧任务应被丢弃或失败，不能继续执行到新对象状态上。

## 多核模式配置

配置入口：

- `src/base/internal/rc.cc`
- `src/include/runtime_config.h`
- `testsuite/etc/config.test`

配置项为：

```text
multicore mode : off
multicore mode : audit
multicore mode : enforced
```

底层常量：

- `VM_MULTICORE_MODE_OFF = 0`
- `VM_MULTICORE_MODE_AUDIT = 1`
- `VM_MULTICORE_MODE_ENFORCED = 2`

默认配置表中 multicore mode 默认值为 `1`，即 `audit`。测试配置 `testsuite/etc/config.test` 也设置为 `audit`。

语义：

- `off`：关闭审计和 enforced 阻断，保持旧路径。
- `audit`：记录 owner/cross-owner 风险，不阻断旧逻辑。
- `enforced`：阻断高风险跨 owner 同步写/调用路径。

## cross-owner 访问策略

cross-owner 访问不是一律禁止，而是分级处理。

当前策略在 `src/vm/internal/owner.cc` 中大致分为：

| 操作 | 策略 |
| --- | --- |
| same owner | 直接允许 |
| target/source 为 `legacy/main` | 直接允许 |
| `environment`、`all_inventory` | snapshot 风格，可直接结构读取 |
| `call_other`、`move_object`、`destruct`、`present` | message 风格，enforced 下阻断同步路径 |
| parser/未知访问 | enforced 下拒绝 |

接入点包括：

- `src/packages/core/efuns_main.cc`：`call_other`
- `src/vm/internal/simulate.cc`：`present`、`destruct`、`move_object`
- `src/packages/parser/parser.cc`：parser 对目标对象 interrogate apply 的边界
- `src/vm/internal/base/object.cc`、`simulate.cc`：对象生命周期和移动

重要事实：`enforced` 模式已能阻断 cross-owner 同步 `call_other`、`present` id 搜索、parser interrogate apply、`move_object`、`destruct` 等路径，但完整 message/future 替代链还没有覆盖所有旧 LPC 调用模式。

## ObjectHandle 与 owner shard 状态

关键文件：

- `src/vm/object_handle.h`
- `src/vm/internal/object_store.cc`

当前 `ObjectHandle` 包含：

- object id
- owner id
- owner epoch
- object path
- valid 标记

`vm_object_handle_resolve()` 会校验：

- handle 是否 valid
- object path 是否还能找到对象
- 对象是否已经 destructed
- object id/path 是否一致
- owner id/epoch 是否仍匹配

resolve 状态不是单一 stale 布尔值，而是可诊断分类：`invalid_handle`、`missing_path`、`object_not_found`、`object_destructed`、`unregistered`、`record_destructed`、`object_id_mismatch`、`path_mismatch`、`owner_mismatch`、`owner_epoch_mismatch`、`live_owner_mismatch`、`live_owner_epoch_mismatch`。当前 C++ 回归已覆盖 invalid handle、missing path、object id mismatch、owner mismatch、同 owner epoch mismatch，以及 destruct 后旧 handle 通过 store record 返回 `record_destructed`；owner message/future/trace 会把 stale target 暴露为 `stale target: <resolve_status>`。live/current handle 解析现在会先尝试 owner-local shard 快路径，只有 live record、local object ref、live path index、owner id 和 owner epoch 全部匹配才返回 `current`；同 owner object id mismatch 会优先通过 owner-local path index 诊断，并用 `diagnosed_via_owner_local_path_index` 暴露来源，path mismatch、owner epoch mismatch 和 destruct tombstone 会优先通过 owner-local live/tombstone record 诊断并设置 `diagnosed_via_owner_local_store`；跨 owner migration 后旧 owner lookup 的 mismatch 诊断会先扫描其他 owner shard，并把来源暴露为 `owner_local_cross_shard_record_found`/`owner_local_cross_shard_record_source`，旧 ObjectHandle 的 `owner_mismatch` 也会优先设置 `diagnosed_via_owner_local_store` 和 `diagnosed_via_owner_local_cross_shard`；最后的 `ObjectTable` live-object fallback 已收束为显式 global live-object bridge，resolve result 和 `vm_object_handle_status()` mapping 均通过 `global_live_object_found`/`global_live_object_source` 暴露同一来源；global bridge 仍作为未迁出完成前的 fallback，并通过 `diagnosed_via_global_index` 暴露；当 `global_live_object_bridge_retirement_ready=1` 时，ObjectHandle 会跳过 global live-object fallback，并通过 `global_live_object_fallback_skipped=1`、`global_live_object_fallback_reason=global_live_object_bridge_retirement_ready` 暴露原因；当 `global_record_bridge_retirement_ready=1` 且 live-object bridge 缺失、已跳过或只允许查 live object 而不附带 global record 时，会跳过 global record fallback，并通过 `global_record_fallback_skipped=1`、`global_record_fallback_reason=global_record_bridge_retirement_ready` 暴露原因。

当前 owner shard 已提供 owner-local object directory、shard-local live record snapshot、正反向 live object reference、live path index、destruct tombstone、destruct path tombstone、跨 owner shard record/path/handle 诊断、按 owner/object_id 与 owner/path 的只读 lookup/resolve、ObjectHandle live/current owner-local 快路径、同 owner stale/tombstone owner-local 诊断、live/ref/path/tombstone 一致性状态、owner-local/global bridge 双向一致性门禁、状态索引和可执行队列观测，但还不是最终独立 owner-local object store。`object_store.cc` 仍有全局 `object_records` 和 `owner_shards`，用 mutex 保护。shard 记录 objects、heartbeats、callouts、messages、pending sets、runnable task、executor readiness、object directory、`local_records`、`local_objects`、`local_object_index`、`destructed_records`、`object_path_index` 和 `destructed_path_index` 等状态；其中 `status.objects` 只是兼容统计，directory/lookup/resolve 以 `VMObjectShard.object_directory`、`VMObjectShard.local_records`、`VMObjectShard.local_objects`、`VMObjectShard.local_object_index`、`VMObjectShard.object_path_index`、`VMObjectShard.destructed_records` 和 `VMObjectShard.destructed_path_index` 为准。directory record 已明确报告 `resolved_via_owner_local_store=1`、`resolved_via_global_index=0`。object id 和 path 两条 lookup/resolve 现在共用内部 `OwnerLocalLookupResult`，集中计算 record 来源、local ref、反向 ref index、live/destructed path index、directory membership、found 判定和最终 shard-local object 指针；本 owner 没有 live/tombstone record 时会优先扫描其他 owner shard 并通过 `owner_local_cross_shard_record_found`/`owner_local_cross_shard_record_source` 暴露跨 shard 诊断，ObjectHandle 使用同一路径诊断跨 owner migration stale handle 并通过 `diagnosed_via_owner_local_cross_shard` 暴露，global object record 只保留为 fallback，ObjectHandle status 会用 `global_live_object_found/source`、`global_live_object_fallback_skipped/reason`、`global_live_object_bridge_retirement_ready`、`global_record_found/source`、`global_record_fallback_skipped/reason` 和 `global_record_bridge_retirement_ready` 暴露 live-object/record bridge 与 skip 门禁，lookup status 会用 `global_live_object_bridge_retirement_ready`、`owner_local_global_live_object_found/source`、`owner_local_global_live_object_fallback_skipped/reason`、`owner_local_global_record_found/source` 与 `owner_local_global_record_scan_bridge_used/found/source/skipped/reason` 区分 live-object bridge、global record bridge 和 `global_object_records.path_scan_bridge`；`owner_local_live_index_consistent`、`owner_local_object_ref_index_consistent`、`owner_local_live_path_index_consistent`、`owner_local_destructed_path_index_consistent`、`owner_local_orphan_record_total=0`、`global_record_total`、`global_live_record_total`、`global_destructed_record_total`、`owner_local_to_global_mismatch_record_total`、`global_to_owner_local_record_mismatch_record_total`、`global_to_owner_local_mismatch_record_total`、`owner_local_record_index_ready`、`owner_local_canonical_record_ready`、`owner_local_store_ready`、`global_record_bridge_consistent`、`global_record_bridge_retirement_ready`、`global_live_object_bridge_retirement_ready`、`owner_local_to_global_bridge_consistent`、`global_to_owner_local_bridge_consistent`、`owner_local_global_bridge_check=bidirectional`、`owner_local_global_bridge_consistent`、`global_live_object_bridge_ready/source` 和 `global_record_bridge_ready/source` 用于暴露 global canonical record 基线、owner-local canonical record readiness、索引漂移与 bridge 来源，降低后续继续迁出 global bridge 时的重复判断风险。

object_id 方向的 global record fallback 已显式命名为 `global_object_records.object_id_scan_bridge`，并通过 `owner_local_global_record_id_scan_bridge_used/found/source/skipped/reason` 与 `global_record_id_scan_bridge_used/found/source/skipped/reason` 暴露；path 方向继续使用 `global_object_records.path_scan_bridge` 与 `owner_local_global_record_scan_bridge_used/found/source/skipped/reason`；pointer 方向的 `object_records.find(object_t*)` 已显式命名为 `global_object_records.pointer_bridge`，owner path lookup status 暴露 `owner_local_global_record_pointer_bridge_used/found/source/skipped/reason`，ObjectHandle status 暴露 `global_record_pointer_bridge_used/found/source/skipped/reason`。当 `global_record_bridge_retirement_ready=1` 且 live-object bridge 只允许找 live object、不附带 global record 时，pointer bridge 会被跳过并报告 `global_record_bridge_retirement_ready`。这三条 bridge 都只是在 `global_index_bridge=0` 阶段保留的迁出前 fallback，不代表 owner-local store 已完成。

`vm_object_store_owner_lookup_status(owner_id, object_id)` 和 `vm_object_store_owner_path_lookup_status(owner_id, object_path)` 是当前 owner-local directory/path index 的最小查询 API；`vm_object_store_owner_resolve(owner_id, object_id)` 与 `vm_object_store_owner_path_resolve(owner_id, object_path)` 是当前 owner-local live object reference 的最小解析 API。lookup status 会用 `owner_local_object_ref_found`、`owner_local_object_ref_index_found`、`owner_local_object_ref_index_source`、`owner_local_object_pointer_index_found`、`owner_local_object_pointer_index_source`、`owner_local_resolve_found`、`owner_local_resolve_source`、`owner_local_canonical_record_ready` 和 `owner_local_store_ready` 同时暴露正向 live ref、反向 ref index、object 指针反查、最终 resolve 是否完整命中、当前 owner shard record/ref/path/tombstone 镜像是否满足 canonical readiness，以及该镜像是否已足以承担 lookup/resolve。通用 object_id/path record fallback 查询现在也会先查 owner shard 的 live/destructed record 和 path index；当 `global_record_bridge_retirement_ready=1` 时，缺失查询会跳过 global record fallback 并通过 `owner_local_global_record_fallback_skipped=1`、`owner_local_global_record_fallback_reason=global_record_bridge_retirement_ready` 暴露原因，path lookup 还会通过 `owner_local_global_record_scan_bridge_skipped=1` 和 `owner_local_global_record_scan_bridge_skip_reason=global_record_bridge_retirement_ready` 暴露 path scan bridge 没有被使用；当 `global_live_object_bridge_retirement_ready=1` 时，缺失 path lookup 会跳过 global live-object fallback 并通过 `owner_local_global_live_object_fallback_skipped=1`、`owner_local_global_live_object_fallback_reason=global_live_object_bridge_retirement_ready` 暴露原因，path record fallback 在此状态下也不会先查 `ObjectTable`；只有 readiness 未满足时才通过显式 global object_id/path/pointer helper 回落 global object records，并通过 `owner_local_global_record_scan_bridge_used/found/source` 暴露 `global_object_records.path_scan_bridge` 是否被使用和命中，通过 `owner_local_global_record_pointer_bridge_used/found/source/skipped/reason` 暴露 `global_object_records.pointer_bridge` 是否被使用、命中或因 record bridge retirement readiness 被跳过；所有直接 `ObjectTable` 查找已集中到单一 global live-object bridge helper，owner lookup 的最后 fallback 只调用显式 global helper，并通过 `global_live_object_bridge_retirement_ready`、`owner_local_global_live_object_found/source`、`owner_local_global_live_object_fallback_skipped/reason`、`owner_local_global_record_found/source`、scan bridge 字段与 pointer bridge 字段区分 live-object bridge 和 record bridge，混合 owner-local/global record helper 已移除，避免来源字段误报。owner migration 后旧 owner lookup 会返回 `owner_mismatch` 且不再是 directory entry，本地 live record snapshot、正反向 live object reference 和 live path index 都会被移除，旧 owner resolve 返回空；该 mismatch 诊断优先来自其他 owner shard，object id 路径报告 `owner_local_cross_shard_record_source=vm_object_shard.local_records`，path 路径报告 `owner_local_cross_shard_record_source=vm_object_shard.object_path_index`，并保持 `owner_local_global_record_found=0`。新 owner lookup 命中并报告 `owner_local_record_found=1`、`owner_local_object_ref_found=1`、`owner_local_object_ref_index_found=1`、`owner_local_object_ref_index_source=vm_object_shard.local_object_index`、`owner_local_object_pointer_index_found=1`、`owner_local_object_pointer_index_source=vm_object_shard.local_object_index`、`owner_local_path_index_found=1`，new owner resolve 返回对象；destruct 后不再属于 owner-local directory，也不保留 live object reference，resolve 返回空，但同 owner lookup 会优先命中 `VMObjectShard.destructed_records` 和 `VMObjectShard.destructed_path_index` tombstone，报告 `owner_local_destructed_record_found=1`、`owner_local_destructed_path_index_found=1`、`owner_local_record_destructed=1` 和 `destructed=1`。owner status 现在暴露 `vm_object_shard` 合同，区分 `status_model=owner_status_record`、`execution_model=owner_execution_shard`、`directory_model=owner_local_object_directory` 和 `storage_model=owner_local_store`。当前 object directory membership 已由 `VMObjectShard.object_directory` 驱动，live 目录记录来自 `VMObjectShard.local_records`，live object reference 来自 `VMObjectShard.local_objects` 与 `VMObjectShard.local_object_index`，live path index 来自 `VMObjectShard.object_path_index`，destruct tombstone 来自 `VMObjectShard.destructed_records`/`VMObjectShard.destructed_path_index`；`vm_object_store_status()` 先暴露 `store_kind=vm_object_store`、`status_model=object_store_status`、`directory_model=owner_local_object_directory`、`storage_model=owner_local_store`，再聚合 owner-local live/destructed record/ref/path index total、`owner_local_orphan_record_total`、`global_record_total`、`global_live_record_total`、`global_destructed_record_total`、`owner_local_to_global_mismatch_record_total`、`global_to_owner_local_record_mismatch_record_total`、`global_to_owner_local_mismatch_record_total`、`owner_local_record_index_ready`、`owner_local_canonical_record_ready`、`owner_local_store_ready`、`global_record_bridge_consistent`、`global_record_bridge_retirement_ready`、owner-local 到 global 和 global 到 owner-local 两个方向的一致性，以及兼容总字段 `owner_local_global_bridge_consistent`，用于确认 global bridge 与 owner-local 状态双向没有漂移，并把 global canonical record 迁出前的基线、readiness 与 mismatch 门禁固定下来；这些 API 现在会在 canonical record/ref/path/tombstone 镜像与 live-object bridge retirement readiness 都满足时报告 `owner_local_store_ready=1`，但仍明确暴露 `owner_local_store_complete=1`、`global_index_bridge=0`、`global_live_object_bridge_ready/source` 和 `global_record_bridge_ready/source`，避免把 lookup/resolve ready 误写成完整 owner-local store，也避免后续迁出时无法区分 live-object bridge、global record bridge、path scan bridge 与 pointer bridge。

## owner mailbox 与主线程 owner queue

`owner.cc` 同时维护两类队列：

- owner mailbox：用于 owner message、compute result、probe/canary 等。
- main owner queue：用于仍必须在主线程执行的 LPC 回调。

主线程 owner queue 的关键函数：

- `vm_owner_enqueue_main_task()`
- `vm_owner_drain_main_tasks()`

主线程 queue 当前特性：

- 按 owner 入队。
- 同 owner FIFO。
- drain 时绑定 `VMOwnerScope`。
- 检查 owner id/epoch，stale/destructed task 不执行。
- 记录 main queued/dispatched/stale/destructed/claim/release 计数。

接入主线程 owner queue 的路径：

- `comm.cc`：用户命令输入。
- `gateway_session.cc`：gateway 命令输入。
- `heartbeat.cc`：heartbeat。
- `call_out.cc`：call_out。
- `async.cc`：async completion。
- `dns.cc`：DNS callback。
- `socket_efuns.cc`：socket read/write/close callback。
- `ed.cc`：ED callback。

当前这些路径多数在 enqueue 后立即 drain，因此主要价值是固定 owner 语义和 stale 防线，不等价于已经后台并行。

## owner thread 与受限 LPC

`vm_owner_thread_start()` 最多启动 4 个 owner thread。owner thread 绑定独立 `VMContext`，并检查 object store isolation。

当前允许/处理的任务：

- `lpc_probe`：验证 off-main context、object store isolation、owner binding。
- `lpc_canary`：只允许 `owner_lpc_canary`。
- `owner_state`：guarded 状态任务。
- `owner_message`：无 target handle 的 message 可在线程侧完成；有 target handle 的 object message 会进入主线程 owner queue bridge 执行，并完成 future。
- `compute_result`：完成 worker future 结果投递。
- `lpc_task`：只开放 `owner_task_readonly` 这一受控只读 allowlist 样例；提交会返回 `future_id`，成功执行后 future 进入 `completed` 并携带 frozen result，拒绝、失败、purge 或被非 owner-thread 路径消费时 future 进入 `failed`。

当前明确关闭：

- 普通 `lpc` 默认 rejected。
- 未注册 `lpc_task` 和预留 owner domain task 默认 rejected。

这说明 owner thread 还是实验/验证基础设施，不能作为任意 LPC 并行执行入口。

## VM worker

关键文件：

- `src/vm/worker.h`
- `src/vm/internal/worker.cc`
- `src/packages/core/vm_worker.cc`
- `src/vm/frozen_value.h`
- `src/vm/internal/frozen_value.cc`
- `testsuite/single/tests/efuns/worker_payload.c`

`VMWorkerRuntime` 是受控 CPU 任务线程池。默认 worker 数为硬件线程数减一，限制在 1 到 64。它支持 owner-key 串行化：同一 owner key 的任务不会并发执行，不同 owner key 可并发。

当前任务类型：

- `bench`
- `snapshot_digest`
- `actor_score`
- `combat_damage`

worker 输入要求由公共 `vm_frozen_value_safe()` 校验，与 owner payload 共享同一冻结值策略；runtime/thread status 会通过 `frozen_payload_contract` 暴露该合同：

- 只能使用可序列化/JSON safe/frozen 风格数据。
- nesting 深度限制为 8。
- mapping key 必须是 string。
- 允许 number、real、string、array、mapping。
- 不支持 object/function/buffer/class 等可变或 VM 绑定类型。

worker async 结果会注册 owner future，并通过 `vm_owner_enqueue_compute_result_fields()` 投递回 owner runtime；`bench`、`snapshot_digest`、`actor_score` 和 `combat_damage` 成功结果会在 owner 边界形成 frozen mapping result，timeout/失败只反映 failed/error。

## owner message / future / payload

关键文件：

- `src/vm/internal/owner.cc`
- `src/packages/core/vm_owner.cc`
- `src/vm/frozen_value.h`
- `src/vm/internal/frozen_value.cc`
- `testsuite/single/tests/efuns/owner_payload.c`

当前 API 包括：

- `owner_send(string, mapping)`
- `owner_call_async(object, string, mapping)`
- `owner_future_poll(int)`
- `owner_snapshot(object)`
- `owner_publish_snapshot(mapping)`
- `owner_query_object_snapshot(object)`
- `vm_owner_drain_main(int)`

payload 约束：

- top-level owner payload 要求 mapping。
- 递归允许 number、real、string、array、mapping。
- mapping key 必须为 string。
- 递归深度超过 8 会拒绝。
- object/function/buffer/class 等不允许作为 payload。
- `frozen_payload_contract` 将 `owner_send`、`owner_call_async`、`owner_publish_snapshot` 和 `worker_snapshot` 的 input/result policy 暴露给 C++ 与 LPC 合同测试。

`owner_call_async()` 会使用 target `ObjectHandle`，future polling 会报告 target handle 是否仍 current。target handle stale 时 future 应失败。

当前边界：有 target handle 的 owner async LPC call 仍通过 main drain 执行 `safe_apply()`，并不是后台线程直接执行对象方法；LPC 层用 `vm_owner_drain_main(int)` 显式触发这条 main-required route。若提交后目标 owner 发生迁移，future 必须失败并暴露 `target_handle_status=owner_mismatch`。

## snapshot API

当前保留的安全跨 owner 结构读取 API：

- C++：`vm_owner_query_object_snapshot(object_t *target, const char *requesting_owner_id)`
- LPC：`owner_query_object_snapshot(object target)`

返回值：

- same owner 或 target 为 `legacy/main`：返回 `nullptr` / `0`，表示直接访问安全。
- cross owner：返回 mapping，包含 object name、owner id、living flag、是否存在 `is_npc`/`is_player`/`is_character` 等方法。

该 API 不调用目标 LPC 方法，只读取结构/标志和方法存在性，用于替代部分跨 owner 同步读取。

## Gateway 与网络路径

关键路径：

- `src/comm.cc`
- `src/net/`
- `src/packages/gateway/gateway.cc`
- `src/packages/gateway/gateway_session.cc`
- `src/packages/sockets/socket_efuns.cc`

当前 gateway/session 已纳入 owner runtime 迁移：

- gateway 命令 callback 使用 `vm_owner_enqueue_main_task()`。
- gateway send/create/destroy 路径使用 `VMOwnerScope`。
- `/adm/daemons/gateway_d` system message 入口使用 daemon owner/epoch 绑定 `VMOwnerScope` 并记录 `receive_system_message` trace，C++ 回归验证 daemon 在玩家 owner scope 内仍归 `legacy/main`。
- gateway `exec()` 路径通过 `gateway_session_exec_update()` 迁移 session lookup；`gateway_session_info()` 暴露 live object 的 `object_name`、`owner_id`、`owner_epoch`，C++ 回归验证 disconnect/remove interactive 不改写新 user owner/epoch。
- 普通 interactive `exec()` 路径已有 C++ 回归，验证 interactive 指针和 command giver 迁移后，新旧对象 owner/epoch 均保持原值。
- socket callbacks 投递到主线程 owner queue。
- `socket_release` 仍保持同步 owner scope 路径，因为 efun 返回值依赖 release/acquire 交接即时完成。

## 测试体系

主要测试层：

- `src/tests/test_lpc.cc`：C++/driver 层回归测试，覆盖 VMContext、owner、worker、message/future、enforced boundary。
- `testsuite/`：LPC driver 测试树。
- `testsuite/etc/config.test`：测试配置，当前 multicore mode 为 `audit`。
- `.internal/test-sources/XiaKeXing`：本地真实业务验收素材，不应写入公开部署规则。

`src/tests/test_lpc.cc` 覆盖重点包括：

- VMContext 线程绑定和 detached setter 不污染当前线程。
- object store 只能主线程同步。
- owner metadata、epoch、guard、mailbox、purge、schedule。
- load/clone/move/destruct 的 owner 生命周期合同。
- main owner queue dispatch、stale drop、drop callback。
- owner shard active heartbeat、pending callout、pending message。
- cross-owner access trace 和 enforced blocking。
- `present`、parser、`move_object`、`destruct`、`call_other` 边界。
- owner payload frozen mapping traversal。
- owner executor 合同版本 `owner_executor_v1`、dispatch contract、executor trace，以及 target-handle owner async 的 main-required drain 和 stale owner 失败路径。
- stale owner object message 和 future 状态。
- worker task/future 联动。

## 最近多核化提交进展

2026-06-09 到 2026-06-17 期间共有 113 条提交。主线进展可以归纳为：

| 时间 | 代表提交 | 进展 |
| --- | --- | --- |
| 2026-06-09 | `a9e22f01`、`96fe1bd2`、`1d153b2c`、`ba16ab53`、`aa826d83` | owner metadata、mailbox、scheduler、guard、epoch 起步 |
| 2026-06-09 | `fd33c6e8`、`93aa5cf3`、`3f2d62e3` | async worker、owner-key worker scheduling、snapshot worker |
| 2026-06-10 | `cd3d49a5`、`a6412cbd`、`fd811ae4` | VMContext per-thread、object store guard、owner scope |
| 2026-06-10 | `af69f7cf`、`4da6865a`、`1e6151bf`、`5031539e` | owner access trace、environment/all_inventory/message commit trace |
| 2026-06-13 | `64ae0ec6`、`0d7c6fdf`、`2a145355` | owner thread LPC canary、allowlist 限制、domain task 注册尝试 |
| 2026-06-15 | `ef1c9970`、`dc5a7806`、`d09ed3f6` | main callback、async completion、network callback owner queue 化 |
| 2026-06-15/16 | `2da8ca4c` 到 `d644d6f0` | current interactive、command giver、execution frame、error context、call origin、inherit offset、stack temporary、error flags、handler depth、object lifecycle guard 迁入 VMContext |
| 2026-06-16 | `fcd23e45`、`c0b33a3b` | owner shard pending message/callout/heartbeat runnable 状态 |
| 2026-06-16 | `253010e9`、`be140309`、`9bff4d6d`、`bccf6b6b` | owner future、stale message、frozen result/payload |
| 2026-06-16 | `5e021011` | worker result 进入 owner future |
| 2026-06-16 | `77de770f`、`36cbbe60`、`97eccc49`、`918fb1ff` | effective owner、legacy scope、singleton/default owner 边界 |
| 2026-06-16/17 | `7ca12d22`、`b573055c`、`6e6f60e9` | snapshot API、移除不安全 owner_safe_query、加固 parser/present/cross-owner LPC boundary |

## 当前已经完成的能力

- 多核模式配置和 runtime 查询。
- owner id/epoch metadata。
- owner mailbox、trace、access trace、message trace、commit trace。
- `VMContext` 线程本地绑定和关键执行状态迁移。
- `vm_context_contract` 已在 runtime/thread status 暴露普通后台 LPC readiness gate：13 项门禁已全部满足，包括 thread-local VMContext、execution state、owner scope、error state、eval stack owner-local、control stack owner-local、value stack owner-local、apply return owner-local、cross-owner object ref 边界、off-main object store 同步拒绝、owner-local lookup/resolve object store gate、activation policy 和 `ordinary_lpc_dispatch_path`；`ordinary_lpc_ready=1` 表示显式开放 same-owner generic LPC dispatch path 已就绪，但 `ordinary_lpc_default_closed=1` 和 `ordinary_lpc_explicit_open_required=1` 仍禁止默认开放 legacy `lpc` 或 gateway/player command。
- object store 主线程同步保护。
- owner-key worker task 串行化。
- 确定性 worker 任务和 async poll/future。
- ObjectHandle stale 校验和 resolve 失败分类。
- owner shard 状态索引、owner-local object directory、正反向 live object reference、live/destructed path index 和 runnable 观测。
- owner-local directory/path index 按 owner/object_id 和 owner/path lookup/resolve 诊断 API。
- command singleton、std database/http/present_clone/telnet shared service、`single/simul_efun` 关键 singleton 以及 `/adm/daemons/gateway_d` daemon singleton 在玩家 owner scope 下保持默认 owner 的入口合同。
- master virtual object 在玩家 owner scope 下保持默认 owner，且 virtual rename 后 object store directory path 同步。
- input/gateway/heartbeat/callout/async/dns/socket/ed 回调主线程 owner queue 化；runtime/thread status 额外通过 `gateway_owner_task_contract` 固定 `gateway_receive`、`process_user_command`、`gateway_logon`、`gateway_disconnected` 当前仍是 `main_required` 输入合同，并明确 receive/command 走 `owner_main_queue`、logon/disconnected 走 `direct_main_owner_scope`；`process_user_command` main task trace 已携带 current ObjectHandle、owner epoch、`gateway_command_buffer_metadata_v1` frozen payload 元数据、owner-private 命令 snapshot 的脱敏元数据、`gateway_command_execution_frame_v1` execution-frame 捕获元数据，以及 `execution_frame_restore_policy=owner_executor_vmcontext_restore` / `execution_frame_restore_ready=1` / `execution_frame_restore_blocker=\"\"`，但不会公开原始命令文本，且 `execution_frame_executor_ready=1`；gateway command snapshot 合同已暴露 `command_input_source=interactive_text_buffer`、`command_text_snapshot_policy=owner_private_redacted_from_trace`、`command_text_snapshot_ready=1`、`command_executor_blocker=interactive_command_side_effects_main_thread_bound`，说明当前已具备 owner-owned private snapshot，但公开 trace 只暴露 bytes/redacted 元数据；gateway command 命令消费模型合同已暴露 `command_consume_model=owner_owned_snapshot_main_thread_consume`、`command_consume_snapshot_ready=1`、`command_consume_executor_ready=1`、`command_consume_blocker=""`，说明 owner main task 已在主线程用 owner-owned snapshot 校验并消费首条命令，`interactive_t` 输入缓冲区只作为匹配和推进来源；gateway command execution-frame restore 恢复合同已暴露 `command_execution_frame_restore_policy=owner_executor_vmcontext_restore`、`command_execution_frame_restore_ready=1`、`command_execution_frame_restore_blocker=\"\"`，说明当前命令执行帧已可由 owner executor 受控恢复但不执行玩家命令；gateway command stale 合同已暴露 `command_stale_guard=owner_epoch_target_handle_guard`、`command_stale_trace_state=main_stale`、`command_stale_target_status=owner_epoch_mismatch`，入队后 owner epoch 漂移会拒绝旧 task 且不消费旧命令。`command_executor_readiness_gates` 现在把 gateway command executor 化前置条件拆成 7 个 gate：`owner_epoch_target_handle_guard`、`owner_owned_command_snapshot`、`owner_owned_command_consume`、`owner_executor_command_consume_entry`、`owner_executor_frame_restore` 和 `ordinary_lpc_ready` 均已满足；`gateway_command_executor_activation` 仍阻塞，`command_executor_next_gate=gateway_command_executor_activation`、`command_executor_next_blocker=interactive_command_side_effects_main_thread_bound`。普通 LPC 显式开放路径已经具备，但 consume/frame restore/generic LPC readiness 仍不代表玩家命令已可后台执行。`executor_task_dispatch_contracts` 同步暴露 `gateway_command` / `gateway_command_executor_activation` 显式拒绝项，`executor_mode=rejected`、`executor_safe=0`、`rejected=1`；owner 线程只记录 `thread_gateway_command_rejected`，不执行玩家命令。`command_side_effect_readiness_gates` 已把 activation blocker 拆成 5 项：`interactive_buffer_consume` 已满足；`input_to_get_char_state`、`process_input_add_action_parser`、`prompt_telnet_reschedule_io`、`interactive_mode_flags` 仍分别被输入回调状态、add_action/parser command_giver 状态、prompt/telnet/reschedule I/O、echo/MXP/ed/interactive flags 主线程副作用阻塞。
- cross-owner audit 和 enforced 阻断核心危险路径。
- snapshot API 和 owner async/future API。
- 普通 off-main LPC 仍默认关闭；`owner_task_readonly` 受控只读 allowlist 已可在线程侧执行，`vm_owner_ordinary_lpc_task()` 也已支持显式开放的 same-owner generic LPC dispatch，并通过 owner future 暴露 pending/completed/failed 与 frozen result。

## 当前未完成的能力

- 对象生命周期、deferred destruct 和全局索引物理迁出的生产级并发化。
- array、mapping、object ref 的完整跨线程内存模型。
- owner executor 替代实验 owner thread。
- heartbeat/callout/input 在 owner executor 中真正并行执行。
- cross-owner `call_other` 的完整 message/future 替代链。
- `owner_lpc_task_allowed()` 的正式注册、审计、domain 合同和验收。
- 长时间、高并发、真实 mudlib 压测。
- production rollout 策略和回滚指标。

## 维护原则

- 不要给旧对象系统到处加锁来“强行并发”；这会制造难以证明的死锁和数据竞争。
- 同一 owner 内必须保持 LPC 串行语义。
- 不同 owner 并行之前，必须先完成 owner-local state 和 frozen/message 合同。
- 先 audit，再 enforced。
- 先 handle，再 shard。
- 先 message/future，再禁止跨 owner 同步调用。
- 先主线程 owner queue 固定语义，再迁移到后台 owner executor。

## 风险清单

| 风险 | 说明 | 当前缓解 |
| --- | --- | --- |
| 全局 VM 状态残留 | 解释器仍有不少历史全局变量 | 逐步迁入 `VMContext`，测试覆盖 setter/scope |
| object store 非线程安全 | 对象表仍是全局模型 | 非主线程 sync 被拒绝，ObjectHandle/stale guard |
| mutable value 跨线程共享 | array/mapping/object ref 可能被双方修改 | owner payload 只允许 frozen/deep-copy 风格数据 |
| legacy scope 误判 | `legacy/main` 与显式 owner 混用会掩盖问题 | effective owner、command_giver 特判、trace |
| 后台 LPC 执行风险 | 任意 LPC 会触碰全局 VM 和对象系统 | 普通 LPC 默认关闭，只开放受控只读 allowlist |
| 短验收不足 | 3 用户短验收不能代表生产稳定 | 后续必须做长时间、多场景、高并发压测 |

## 建议阅读顺序

1. `README.md`
2. `docs/multicore-runtime.md`
3. `docs/multicore-actor-vm-plan.md`
4. `docs/owner-multicore-api.md`
5. `src/vm/context.h`
6. `src/vm/owner.h`
7. `src/vm/worker.h`
8. `src/vm/internal/context.cc`
9. `src/vm/internal/owner.cc`
10. `src/vm/internal/object_store.cc`
11. `src/vm/internal/worker.cc`
12. `src/packages/core/vm_owner.cc`
13. `src/packages/core/vm_worker.cc`
14. `src/packages/core/call_out.cc`
15. `src/packages/core/heartbeat.cc`
16. `src/comm.cc`
17. `src/packages/gateway/gateway_session.cc`
18. `src/tests/test_lpc.cc`
