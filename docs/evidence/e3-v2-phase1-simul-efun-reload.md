# E3 v2 Phase 1 证据：simul_efun 事务重载（master/simul_efun，无 create）

日期：2026-08-18（审阅驱动三轮修复后最终验证）
仓库：fluffos-xk @ main（HEAD 40a0420f 之后的 Phase 1 待提交工作树）

## 结论

Phase 1（master/simul_efun 热重载，无 create）代码与测试全绿：
- gtest 425/425（build-sync，Release）
- ftest etc/config.recompile：`recompile_special_targets: 8 special reload checks ok` + `recompile_stress: 1000 recompiles ok, 0 failures, 4 workers`，EXIT=0
- 修复前的 0x8 段错误（simul_efun 重载路径）已消除

## 根因链（三轮审阅定位，全部经磁盘代码实证）

1. **索引键混用**（架构审阅 #1，已修复）：names/idents 是排序位置键，funcs 是 dispatch 索引键，二者一般不等（testsuite/single/simul_efun.c 声明序非字母序即反例：活表 [__assert_eq(1), same(0)] permuted）。
   - `add_simul_entry` 原按位置平移 funcs → dispatch 槽错位（复现：names=[bar(1),foo(0)] 末尾新增 → 调用错函数）
   - prepare 原写 `idents[count]` → 应为 `idents[pos]`
   - activate 原用 `simuls[i]`（位置）→ 应为 `simuls[simul_names[i].index]`（dispatch 键）
2. **0x8 段错误**（完成度审阅定位）：activate 步 1 把活表 ident 的 `sem_value--`（1→0）；步 3 的 `lookup_ident` 回退经 CHECK_ELEM（lex.cc:4372-4378）对 `sem_value==0` 且非保留字的条目返回 NULL；Release 构建 NDEBUG 吞掉 `assert(ihe != nullptr)` → `ihe->token |= IHE_SIMUL` 空指针写。ident_hash_elem_t 布局 token@offset 8 → 崩溃地址恰为 0x8（gtest 与 ftest 两处崩溃同址）。
   - 在线热重载路径免疫原因：remove_simuls 在 decrement 之前 lookup（sem_value≥1 必然命中）；重加走 find_or_add_perm_ident（无 sem_value 守卫）。
3. **测试 bug**（grounded-reviewer 核验）：程序函数表顺序按 funcname 指针排序（compiler.cc:2068 compare_funcs，非声明序），foo 实际在程序索引 1——测试断言硬编码索引 0 错。修复：按名定位程序索引（FindProgramIndex），并新增 runtime index 一致性断言。

## 修复落点（simul_efun.cc / simul_efun.h）

- `add_simul_entry`：只平移 names/idents（idents 判空），funcs 永不移动；更新分支返回 `-1 - names[j].index`（dispatch 索引编码），插入返回位置
- `find_or_add_simul_efun`（在线构建器）重构复用 add_simul_entry（r<0: sim_idx=-1-r；r>=0: sim_idx=count 并 count++）
- `simul_efuns_prepare`：克隆循环 `idents[count] = find_or_add_perm_ident(...)`（预解析全部槽，sem_value≥1 时纯查找零分配）；新名 `idents[pos]`；idents 与 names/funcs 对称 RESIZE
- `simul_efuns_activate` 步 3：直接取 `p->idents[i]`（无 lookup_ident 回退——步 1 decrement 后 sem_value==0，回退机制不可行）+ assert 守卫
- simul_efun.h：KEY DISCIPLINE 契约注释（位置键 vs dispatch 键、累积不变量、prepare 预解析、activate 禁止 lookup 回退）+ 暴露测试接口（simul_entry 结构、simul_names/num_simul_efun extern）

## 验证记录

| 载体 | 命令 | 结果 |
|---|---|---|
| gtest 单测 | `ctest -R TestSimulEfun`（build-sync） | 3/3 通过（TestSimulEfunReloadAddDropReadd 覆盖 A 插入/B 删除/C 重加三程序循环） |
| gtest 全量 | `ctest`（build-sync） | 425/425 通过 |
| ftest 主交付 | `testsuite/../build-sync/bin/driver etc/config.recompile -ftest` | EXIT=0；`recompile_special_targets: 8 special reload checks ok`；`recompile_stress: 1000 recompiles ok, 0 failures, 4 workers`；`all tests finished, shutting down.` |
| 修复前对照 | ftest-p1b.log（0x8 崩溃，Aug 18 00:22） | 修复后同路径无崩溃 |

注：ASan 构建不可用于本 bug 定位（driver 的 backward-cpp SIGSEGV 处理器抢在 ASan 之前，且 NDEBUG 吞 assert）；若再遇 no-fail 段问题改用 Debug 构建。

## 测试覆盖边界说明

- master 重载成功路径不可 ftest 测：ftest 驱动链常驻 master 帧（master.c:98 主循环）→ guard 必然拒绝；成功路径由 simul_efun 成功路径共享的 commit 管线（prepare/activate/discard）覆盖，测试注释记录此限制
- dropped-name 运行期报错路径（call_simul_efun → "Function is no longer a simul_efun."，simul_efun.cc:375）零覆盖——留待后续阶段
- 事务失败回滚（discard）路径：Phase 2（`__INIT`/create + 回滚）范围
