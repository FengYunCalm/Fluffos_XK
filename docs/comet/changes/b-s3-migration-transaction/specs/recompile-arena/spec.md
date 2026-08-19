# Recompile 迁移事务与编译期 Arena（B-S3 / C-S1 / C-S2）

## 概述

本 capability 完成 #1247 优化计划的 B-S3（per-kind policy 与迁移事务）、C-S1（编译期 monotonic arena 原子迁移）与 C-S2（本地 A/B 验收）。B-S1（ObjectVariableBlock 解耦）与 B-S2（recompile_layout 纯模块）已提交。

## B-S3：per-kind policy 与迁移事务

### 生命周期 policy

```cpp
enum class RecompileInitPolicy { Never, OnMigratableLayoutChange, Always };
enum class RecompileMigrationPolicy { None, OnMigratableLayoutChange, Always };
enum class RecompileStateOrder { InitThenMigrate, MigrateThenInit };
enum class RecompileCreatePolicy { Never, AfterStateReady };
struct RecompileLifecycle { ... };
RecompileLifecycle recompile_lifecycle_for(RecompileTargetKind kind);
```

固定 policy 表：

| Target kind | __INIT | 变量迁移 | 状态顺序 | create() |
|---|---|---|---|---|
| BlueprintFamily | 仅可迁移布局变化时 | 仅可迁移布局变化时 | InitThenMigrate | 从不 |
| Master | 总是 | 总是 | MigrateThenInit | state ready 后 |
| SimulEfun | 总是 | 总是 | MigrateThenInit | state ready 后 |

exact layout 是否运行 __INIT 以及 init/migrate 相对顺序由该表显式决定，不由"变量数量是否变化"或散落分支隐式决定。BlueprintFamily 的新 block 先运行 initializer 再由旧值覆盖 matched 槽（新增变量保留 initializer）；Master/SimulEfun 先把旧值复制到独立新 block 再运行 __INIT（__INIT 看到旧状态且写入不被迁移覆盖）。两种顺序都不修改旧 block，失败可完整回滚。

### PreparedVariableMigration

```cpp
struct PreparedVariableMigration {
  ObjectVariableBlock old_block;  // 发布期间从 object 临时 detach
  ObjectVariableBlock new_block;  // 按 policy 执行 init/migrate
  std::vector<VariableMatch> matches;
  RecompileLayoutDiff diff;
};
```

所有权状态只有三种：准备前/完成后 Object owns attached payload；临时发布期间 Object owns new payload、migration owns old payload；回滚后 Object owns old payload、migration owns/discards new payload。析构、commit_finish() 和 rollback() 是 detached payload 的唯一释放者。

### 事务顺序

1. admission 关闭 + quiescence；固定 target snapshot、program refs、generation、derived flags 和旧变量 block。
2. fallible prepare 段：layout diff、migration matches、新变量 block、apply cache、simul staging；不修改 live object。BlueprintFamily exact layout 不创建 migration；Master/SimulEfun 按 Always 创建。
3. commit_swap() noexcept：换 prog/generation/flags + obj_vars_move 发布（old payload → migration，new payload → object）；两个 move 之间不开放 admission、不调用可失败代码。
4. copy_matches()：对每个 match 执行 assign_svalue(&new[dst], &old[src])（引用复制，旧槽不动）；不执行 mudlib callback。
5. prepare_target_state() 按 state_order：BlueprintFamily 为 call___INIT() 后 copy_matches()；Master/SimulEfun 为 copy_matches() 后 call___INIT()。任一 error 或 self-destruct 进统一失败路径。
6. Master/SimulEfun 通过 call_create_only() 运行 APPLY_CREATE（base/object 新原语；call_create() 组合 __INIT + create_only；recompile 不自行实现 apply 变体）。
7. 成功 commit_finish() noexcept 释放旧 block/program/simul 表；失败 rollback() noexcept 换回 program/generation/flags/simul 表/旧 block 并销毁新 block。

### 失败与副作用契约

- 回滚恢复 driver 持有的 program、变量值、generation、flags 和 dispatch 状态。
- __INIT/create 的外部副作用（其他对象、call_out、文件、网络、全局 daemon）不可回滚；命令失败信息明确该边界。
- target 在 __INIT/create 中 destruct 时 snapshot ref 保持 object 内存和两个 block 可清理；事务返回失败，不重新开放半提交对象。
- migration 引用复制在 noexcept 前提内（assign_svalue 仅 ref++）；no-fail 段只允许指针、计数和已预留引用的交换。

### 放行规则（efuns_main）

exact match 走严格门禁；非 exact 时 classify_recompile_layout 的 diff.migratable() 决定放行。可迁移：新增/删除/重排（改名=删+增不保值）。必须拒绝：matched 类型变化、inherit graph/edge type_mod 变化、class schema 变化、重复稳定身份、无法证明兼容的布局变化。

## C-S1：编译期 monotonic arena

### 核心

- 独立 src/compiler/internal/compile_arena.{h,cc} 作为 chunk pool 生命周期唯一 owner。
- 进程级 pool：1MB 静态 base chunk，最多保留 8 个 1MB standard chunk；超保留上限的 standard chunk 和所有 oversize exact-fit chunk 在 compile scope 结束时释放。
- compile 级 scope：显式 compile_arena_begin()（compile_file 入口）与 compile_arena_end()（成功路径 compiler.cc:2503 与错误清理路径 compiler.cc:2612 双点显式调用）；普通 parse error 走 clean_parser() 返回；不引入半套 CompileSession。
- allocation：max_align_t 对齐 monotonic bump，不跨 chunk。
- deallocation：individual deallocate 为 no-op；旧 scratch_free() 三分语义不保留，依赖 tail rewind/立即 free 的调用点同阶段改写。
- 容器：ArenaString、ArenaVector<T>、token materialization API；跨 compile 存活数据在边界复制到自有 storage。
- lexer：string builder API 替换直接游标操作；同一提交删除 scr_last/scr_tail/scratch_end 导出。
- parser/compiler：grammar source、generated parser、trees、宏参数、类型名等全部 scratch 调用点迁移；生成文件由对应源重新生成并通过一致性检查。
- observability：cycle bytes、peak cycle bytes、chunk mallocs、reset count、retained chunks、retained heap bytes 接入 mud_status()。

### 门禁

- src/compiler/ 中 scr_last|scr_tail|scratch_end|scratch_alloc|scratch_realloc|scratch_free 零生产调用。
- GTest 覆盖 alignment、exact fit、spill、oversize、retained ceiling、bulk reset、错误 unwind 和统计；错误 unwind 测试验证 error() longjmp 路径经错误清理路径显式 end 后 arena cycle bytes 归零、下次 compile 复用 retained chunks；普通 parse error 同样归零。
- lexer/parser randomized lpc_tests 至少连续 3 轮通过。
- Debug ASan/UBSan 无 UAF、double free、orphan chunk；生成 parser 与 grammar source 一致。

## C-S2：本地 A/B 与内存验收

- 基线和候选使用相同 compiler、CMake options、build type、CPU affinity、输入 corpus、预热和测量轮次；WSL2 构建前 df -h /，固定 -j4/-j8。
- bench_scratchpad：tokens、string accumulation、macro arguments、compile mix。
- bench_compile：真实 compile_file() 反复编译固定代表性 LPC corpus，报告 throughput、median、p95、p99、chunk mallocs、retained bytes、peak RSS；每组至少 5 次独立进程，保留原始 CSV/JSON、commit、工具链、机器负载和汇总脚本。
- 通过条件：warmup 后 chunk_mallocs 增量为 0；真实 compile throughput ≥+10%；median/p95/p99 任一不回退 >5%；scratch 路径 malloc 次数降 ≥50%；steady-state retained heap ≤8 standard chunk；peak RSS ≤110%；last-10%/first-10% ≤1.10。
- 任一硬门禁失败回滚 C-S1，保留 benchmark 和失败原因；不得只调低阈值宣布成功。

## 完成定义

- 对象变量 storage 的长度、布局、统计和释放不依赖可能已切换的 ob->prog；program_layout_digest() 是 layout_id 唯一生产者；布局迁移按稳定身份复制并可恢复整个旧 block。
- 纯 recompile_layout 模块独立完成 descriptor、class schema、diff 和 matches；事务模块只消费结果。
- per-kind lifecycle policy 是唯一行为入口；普通 blueprint、Master、SimulEfun 的 init/migrate 顺序和 create 语义均有回归测试；纯 create apply 由 call_create_only() 提供。
- compiler arena 不导出内部游标，旧 scratch API 无生产调用；显式 begin/end 在 parse error、error() longjmp 和正常返回路径都恰好执行一次 bulk reset。
- GTest、lpc_tests 全绿和对应 sanitizer 门禁通过；性能结论来自同工具链、本地 before/after 原始数据。
