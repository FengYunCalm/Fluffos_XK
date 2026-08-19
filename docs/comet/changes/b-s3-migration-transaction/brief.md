# Outcome

完成 optimization-master-plan-2026-08-18.md 的 B-S3（per-kind policy 与迁移事务）、C-S1（编译期 monotonic arena 原子迁移）与 C-S2（本地 A/B 验收），使整项 #1247 优化计划的完成定义全部成立。B-S1（ObjectVariableBlock 解耦）与 B-S2（recompile_layout 纯模块）已提交（3916813b / 7eeaae3c / 2fb62604）。

# Scope

- B-S3：PreparedVariableMigration 每 target 迁移块；per-kind lifecycle policy（BlueprintFamily/Master/SimulEfun 的 __INIT/迁移顺序/create 语义）；事务段（prepare → commit_swap 发布 → copy_matches → prepare_target_state → commit_finish/rollback）；call_create_only() 原语；efuns_main 按 diff.migratable() 放行；失败回滚（__INIT 失败、create 失败、self-destruct）。
- 修复当前 B-S3 测试段错误（TestRecompileMigrationAddRemovePreserves 等 5 个新测试在 ASan 下定位）。
- B-S3 门禁测试：迁移保值（新增 initializer 保留/matched 恢复旧值/删除释放/重排保值/改名不保值）、Master/SimulEfun exact 与布局变化路径、同名不同 inherit 路径不串值、exact layout 按 policy、失败回滚、replace_program/save-restore/clone/destruct/master/simul reload 回归、ASan/UBSan/TSan 零新增。
- C-S1：compile_arena.{h,cc}（1MB 静态 base chunk + 8 个 standard chunk 保留上限 + oversize exact-fit）；显式 compile_arena_begin/end（compile_file 入口 + 成功/错误双清理点，error() 是 longjmp 不用 RAII）；ArenaString/ArenaVector/token materialization；lexer string builder 替换直接游标；全部 scratch 调用点原子迁移；scr_last/scr_tail/scratch_end 零生产调用；mud_status 观测。
- C-S2：bench_scratchpad + bench_compile 同工具链 A/B（warmup 后 chunk_mallocs 增量为 0、throughput ≥+10%、median/p95/p99 不回退 >5%、scratch malloc 降 ≥50%、retained heap ≤8 chunk、peak RSS ≤110%）；原始数据写入 evidence。
- 统一门禁：GTest 全绿、lpc_tests 全绿、全量 -ftest 绿、ASan/UBSan/TSan 零新增、每阶段提交。

# Non-goals

- 不改变 A 阶段已提交的 #1247 安全移植内容。
- 不引入 RAII CompileArenaScope（error() 是 longjmp，跨帧析构不运行；计划 C.2 已明确显式 begin/end）。
- 不把 digest 当作迁移放行的完整结构比较（B-S2 已明确 64 位 digest 无碰撞不成立）。
- 不修改 per-kind policy 表（若需上游式普通 blueprint 每次 __INIT，须作为单独兼容性决策）。
- 不执行 git reset --hard 或覆盖并行改动。

# Acceptance examples

- B-S3：BlueprintFamily 布局变化时新增变量获得 initializer 值、matched 变量恢复旧值、删除变量释放、重排保值、改名不保值；Master/SimulEfun exact 与布局变化路径 __INIT 读取迁移后的旧状态且写入保留；同名不同 inherit 路径不串值；class schema/type_mod/类型变化拒绝；exact layout 按 policy 表执行；__INIT/create 失败与 self-destruct 完整回滚；replace_program/save-restore/clone/destruct/master/simul reload 回归通过。
- C-S1：compile_arena_begin/end 在成功与错误清理路径双点显式调用；错误 unwind 后 arena cycle bytes 归零且下次 compile 复用 retained chunks；lexer/parser randomized lpc_tests 连续 3 轮通过；scr_last|scr_tail|scratch_end|scratch_alloc|scratch_realloc|scratch_free 在 src/compiler/ 零生产调用。
- C-S2：warmup 后 chunk_mallocs 增量为 0；真实 compile throughput ≥+10%；median/p95/p99 不回退 >5%；scratch 路径 malloc 降 ≥50%；steady-state retained heap ≤8 standard chunk；peak RSS ≤110%；last-10%/first-10% ≤1.10。

# Constraints and invariants

- 对象变量 storage 的长度、布局、统计和释放不依赖可能已切换的 ob->prog；program_layout_digest() 是 layout_id 唯一生产者。
- 纯 recompile_layout 模块独立完成 descriptor/class schema/diff/matches；事务模块只消费结果。
- per-kind lifecycle policy 是唯一行为入口；纯 create apply 由 base/object 的 call_create_only() 提供。
- compiler arena 不导出内部游标；旧 scratch API 无生产调用；显式 begin/end 在 parse error、error() longjmp 和正常返回路径都恰好执行一次 bulk reset。
- WSL2 构建固定 -j4/-j8，构建前 df -h /，同一时刻只保留一个活动构建。
- 提交原则：B 按 object vars storage / recompile_layout / migration lifecycle 三个可回滚边界；C 开发提交可细分但合入保持原子可编译。

# Decisions

- D1: B-S3 的 per-kind policy 表按计划固定：BlueprintFamily = OnMigratableLayoutChange/OnMigratableLayoutChange/InitThenMigrate/Never；Master/SimulEfun = Always/Always/MigrateThenInit/AfterStateReady。
- D2: migrations 以 std::unique_ptr<PreparedVariableMigration> 持有（recompile.h 前向声明，完整定义在 recompile.cc，避免 object.h 依赖链）。
- D3: copy_matches 用 assign_svalue（引用复制，noexcept 段安全）；旧槽内容在 commit_finish/rollback 统一释放。
- D4: C-S1 用显式 compile_arena_begin/end（error() 是 longjmp，machine.h:38 [[noreturn]]），不用 RAII。
- D5: 当前 B-S3 测试段错误优先用 build-recompile-asan 定位（gdb 不可用）。

# Open questions

# Verification expectations

- 每阶段：GTest 全绿 + lpc_tests 全绿 + 全量 -ftest 绿 + 提交。
- B-S3 末：ASan/UBSan/TSan 零新增报告（TSan 用 setarch -R 跑，libevent 基线竞态单独登记）。
- C-S1 末：全旧 scratch 符号 grep 零命中 + arena GTest（alignment/exact fit/spill/oversize/retained ceiling/bulk reset/错误 unwind）+ 3 轮 randomized lpc_tests。
- C-S2 末：同工具链 A/B 原始数据写入 evidence，全部硬门禁通过。
