# E3 收尾与遗留项专项方案（2026-08 批次二）

> 状态：**DRAFT v0.5 —— L1/L4/L2 已完成（见 §6 实际 commit 历史）；L5 起按序执行**
> 生成日期：2026-08-16（v0.5 同日修订）
> 前置：E3 v1（P0-P7 主体）已完成并推送（`origin/main == 0ca1f840`，9 commit）
> 范围：本方案覆盖全部遗留项（L1-L10），含 sanitizer 验证闭环、测试惯用法治理、
> E3 v2 设计、E4/T3 立项；执行纪律沿用 v0.4 专项（门禁、原子提交、证据落盘）

## 1. 遗留项总览与依赖

| ID | 项 | 类型 | 优先级 | 依赖 | 授权状态 |
|---|---|---|---|---|---|
| L1 | UBSan 根修（sanitizer 构建产物问题） | 修复 | P0 | 无 | 已授权（P7 门禁） |
| L2 | 测试惯用法统一（RAII helper 替换 3 形态 ~46 处） | 治理 | P0 | 无 | 已授权（收尾） |
| L3 | 已推送证据文档错误因果段改写 | 文档 | P0 | L1 机制定案 | 已授权 |
| L4 | lex.cc 局部 extern 清理 | 治理 | P1 | 无 | 已授权 |
| L5 | ASan 全矩阵（lpc_tests/ftest/lpcc/ofile_tests） | 验证 | P1 | L1 | 已授权（P7 门禁） |
| L6 | TSan 独立构建 + 定向 + 全量 | 验证 | P2 | 无 | 已授权（P7 门禁） |
| L7 | owner 压测 + 多 owner 重复热重载压测 | 验证 | P2 | 无 | 已授权（P7 门禁） |
| L8 | E3 v2 设计（master/simul_efun/__INIT/create/回滚） | 设计 | P3 | 无 | **需单独授权后实施** |
| L9 | E4 `read_source_line()` 移植评估 | 移植 | P3 | 上游 #1343a 对比 | **需单独授权** |
| L10 | T3 lpcshell 前置基建立项 | 立项 | P4 | scratchpad/结构化诊断基建（本地不存在） | **需单独授权** |

**依赖图**：L1 → L5；L3 → L1；其余独立。P0-P2 为当前批次可执行边界；
P3-P4（L8/L9/L10）产出设计/立项文档，实施一律走单项授权（沿用
optimization-plan §6"可选增强默认不执行、缺单项授权"门禁，**不接受批量授权**）。

## 2. 阶段划分与退出条件

### P0 — 基线清理（3 个原子 commit）

**P0.1 改写证据文档错误段（L3，commit 1）**
- 位置：`docs/upstream-sync-evidence-2026-08.md:183-187`（随 0ca1f840 推送）
- 错误内容：①"`current_object = master_ob` 赋 null"——UBSan "store to null
  pointer" 检查的是**存储目标地址**为 null，不是存入值；插桩已证明 master_ob
  非 null、`&current_object` 非 null、TP 非 null。②"修复需在锁外读路径加
  空指针防护"——无依据假设，方向错误
- 改写成：**GCC 13.3 UBSan null-check 对 TLS 访问的编译侧误报**（机制已由
  P1.1 证伪链定案）+ 修复 commit（CMakeLists `-fno-sanitize=null`）引用
- **退出条件**：该段无"赋 null"/"空指针防护"残留表述；grep 验证

**P0.2 验证探针零残留（commit 1 同批）**
- `grep -c PROBE src/tests/test_lpc.cc` == 0（已 git checkout 恢复，提交前复核）

**P0.3 lex.cc 局部 extern 清理（L4，commit 2）**
- 位置：`src/compiler/internal/lex.cc:49-55` FIXME 块
- 四处局部 extern 替换为正规头文件 include：
  - `master_ob` → `vm/internal/master.h:8`
  - `check_valid_path` → `packages/core/file.h:9`
  - `push_malloced_string` / `pop_stack` → `vm/internal/base/machine.h:75` 系
- **退出条件**：构建通过；`grep -n "extern.*master_ob" lex.cc` 零匹配；
  与 E3 在 efuns_main.cc 的同类清理模式一致

### P1 — UBSan 根修（L1，决策树实验先行）

**P1.1 机制定案（已完成，实验证伪链）**
- 最终结论：**GCC 13.3 的 UBSan null-check 对 `FLUFFOS_VM_THREAD_LOCAL`
  （thread_local）访问的编译侧误报**（-O3 形态），非数据 null、非 TLS model
- 证伪链（实验日志均落盘 `docs/evidence/`）：
  1. 插桩：master_ob=0x5130...、&current_object 非 null、TP（%fs:0x0）非 null
     ——排除"赋 null 值"与"地址为 null"
  2. 最小复现（单 TU / 跨 TU / PIE / 双 sanitizer / -O2）全部不复现
  3. `-ftls-model=initial-exec` 正规注入（CMake reconfigure，双 TU flags
     核验）后仍报——排除 TLS model（ubsan-tlsmodel-exp.txt）
  4. lpc_tests 单 target `-fno-sanitize=null`：test_lpc.cc:4433 store 误报
     消失，报错点**移动**到 libdriver 的 efuns_main.cc:231（同一类 TLS load
     误报）——报错点随代码生成移动 = 误报类最强特征（ubsan-fnonull-probe.txt）
  5. lpc_tests -O0 判别：4433 消失（libdriver 仍 -O3，231 仍在）——优化
     相关插桩行为（ubsan-o0-probe.txt）
  6. 差分证据：efuns_main.cc 同函数 226 行 TLS load（current_object->flags）
     不报、231 行 TLS load（sp）报——布局相关误报特征；非 sanitizer 构建
     同启动路径（master 加载 → f__call_other）424/424 全绿，sp 若真 null
     必 SIGSEGV
- **正式修复（P1.2 已落地，commit 3）**：`src/CMakeLists.txt` ENABLE_UBSAN
  分支全局加 `-fno-sanitize=null`（C+CXX），带正当性注释（GCC 13.3 TLS
  null-check 误报 + ASan 仍覆盖真实 null 解引用 + 报错点移动证据）。
  **不**走 lpc_tests 单 target（231 在 libdriver，单 target 不够）；
  **不**手改 flags.make（CMake 生成物，reconfigure 冲掉）
- **验证（已完成，全量矩阵）**：
  - ASan 构建全量 lpc_tests：424/424 PASS、exit 0、零 runtime error
    （docs/evidence/ubsan-enumerate.txt）
  - ASan driver 全量 ftest：Checks succeeded、零 runtime error/ASan 报错
    （docs/evidence/asan-ftest-final.txt）
  - ASan driver recompile 定向（config.recompile 全合同）：Checks succeeded、
    零报错（docs/evidence/asan-recompile-final.txt）
  - **LSan 泄漏说明（归因实验定案，2026-08-17）**：driver ftest 全量退出
    时 LSan 报 24 个 allocation；逐测试定向验证（docs/evidence/asan-*-lsan.txt）：
    纯同步测试（os_env/owner_executor_contract/recompile）**零泄漏**；
    async 定向 200KB（async_read req）、socket_tls_server 定向 23KB
    （SSL_CTX/event）——**归因：既有异步资源退出清理缺口，与 E3 无关**
    （E3 相关测试定向零泄漏；async.cc 最后改动为 S10 审计）。上游 CI
    sanitizer 只跑 ctest 不跑 driver ftest，缺口未暴露。P3 全量验证使用
    `ASAN_OPTIONS=detect_leaks=0`（守护进程退出语义）；异步资源清理
    修复单独立项（不在本方案范围）

**P1.2 正式修复（已完成，并入 commit 1）**
- 实际落地：`src/CMakeLists.txt` ENABLE_UBSAN 分支全局加
  `-fno-sanitize=null`（C+CXX，带经验确认注释；TLS-model 实验已证伪排除；
  仅 lpc_tests 局部不够——报错点含 libdriver 的 efuns_main.cc）
- **退出条件（已满足）**：ASan 构建下 `--gtest_filter='*ReadBytes*:*WriteBytes*:*FileSize*'`
  零报错；全量 lpc_tests 424/424 零 runtime error（docs/evidence/
  ubsan-enumerate.txt）

### P2 — 测试惯用法统一（L2，commit 3）

**审计事实**：`current_object = master_ob` 惯用法 3 种形态、~46 处、8 文件：
- 无守卫裸赋值：test_lpc.cc 36 处 + main_lpcc.cc 3 处（120/147/157）+
  main_symbol.cc:28 + main_fuzz_compile.cc:160 + main_fuzz_restore.cc:124
- 带守卫 `if (current_object == nullptr && master_ob != nullptr)`：
  test_lpc.cc 3 处（4770/4790/4812，同文件两形态共存）+ bench 3 文件各 2 处
  （lpc_vm_bench 71/93、owner_runtime_bench 117/139、object_store_bench 70/92）
- 手动 saved/restore：test_lpc.cc:4768-4774（try/catch 逐路径恢复）
- RAII 恢复重复：test_lpc.cc 内 7 份局部 `struct FixtureGuard`
  （4425/4454/4486/4508/4572/4614/4658）
- 根因：Kimi Security Fix（31d91eb76）只给 bench 加守卫，漏掉 test_lpc.cc
  主体——同文件两形态共存

**修复形状（已完成，commit 3）**：
- 新建 `src/vm/internal/base/scoped_current_object_as_master.h`（非
  src/tests/——消费者含 src 根目录非 gtest 工具 lpcc/fuzz_compile/
  fuzz_restore/main_symbol，工具依赖 tests 头是方向倒置；放 current_object
  的归属层 vm/internal/base；零 gtest 依赖、自包含）：
  ```cpp
  // RAII: temporarily set current_object to master_ob for the scope; restores
  // the previous value on destruction (destructor runs on any exit path).
  class ScopedCurrentObjectAsMaster { ... };  // 无条件 + 类内 conditional_t{} 两构造
  ```
- 替换全部点位：无守卫裸赋值 → 用 RAII 包住作用域；带守卫形态 → RAII
  （守卫语义保留在 helper 内：`master_ob != nullptr` 时才切换）
- **6 份重复局部 FixtureGuard 的实际形态**：收敛为 test_lpc.cc 匿名命名空间
  内 2 份共享守卫（PathCleanupGuard 文件清理 ×4 + ExternalCommandGuard
  命令恢复 ×2）——守卫仅 test_lpc.cc 使用，TU 局部封装优于进共享头
  （共享头保持零 gtest 依赖、不向 tools 暴露测试专用类型）；socket guard
  （多资源监听器/套接字/fd）特殊形态保留为真多资源守卫（析构内
  `ScopedCurrentObjectAsMaster inner;` 设 master 供 socket_close）
- **注意**：守卫不解决 UBSan（null-store 检查目标是地址）——helper 解决
  重复，TLS 构建旗标解决 sanitizer，两件事独立提交
- **退出条件（已满足）**：裸赋值仅存在于 helper 头内部（:35/:39 实现）；
  socket guard 析构改用 `ScopedCurrentObjectAsMaster inner;` 收口（三种旧
  惯用法全消灭）；6 份重复局部 FixtureGuard 收敛为 2 份共享定义
  （PathCleanupGuard / ExternalCommandGuard，test_lpc.cc 匿名命名空间）；
  lpc_tests + lpcc + symbol + fuzz_compile + fuzz_restore + 3 bench 构建通过
  （docs/evidence/l2-tools-bench-build.txt）；`lpc_tests` 424/424（build-sync，
  docs/evidence/l2-lpc-tests-final.txt）；ftest 全量 0 Check failed
  （docs/evidence/l2-ftest-buildsync.txt）

### P3 — ASan 全矩阵（L5，commit 4）
> 状态：**L1 验证阶段已完成主体**（lpc_tests 全量 424/424 + ftest 全量 +
> recompile 定向均在最终配置下跑完并落盘 docs/evidence/）；剩余
> lpcc/ofile_tests/ctest 补跑

按 v0.4 §16.2 全量跑（L1 修复后）：
```bash
# ASan+UBSan driver 全量 ftest
cd testsuite && timeout 3000 ../build-recompile-asan/bin/driver etc/config.test -ftest
# ASan lpc_tests 全量
../build-recompile-asan/src/tests/lpc_tests
# ASan lpcc + ofile_tests
cmake --build build-recompile-asan --target lpcc ofile_tests -j$(nproc)
ctest --test-dir build-recompile-asan --output-on-failure
# recompile 定向（E3 合同回归）
../build-recompile-asan/bin/driver etc/config.recompile -ftest:single/tests/efuns/recompile_object
```
- **退出条件**：ftest 0 Check failed 0 Segmentation；lpc_tests 424/424 零
  sanitizer 报错；ctest 全绿；recompile 定向 Checks succeeded
- **证据**：日志落盘 `docs/evidence/asan-*.txt`（本会话已多次出现 /tmp 证据
  消失导致复核困难，本批强制落盘）

### P4 — TSan 独立构建（L6，commit 6）

- TSan 与 ASan 互斥（src/CMakeLists.txt:103 `_SAN_COUNT > 1` FATAL）——必须
  独立 build 目录：
  ```bash
  cmake -S . -B build-recompile-tsan \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DENABLE_TSAN=ON -DENABLE_LTO=OFF -DMARCH_NATIVE=OFF
  cmake --build build-recompile-tsan --target driver lpc_tests -j$(nproc)
  ```
- 定向先行：`lpc_tests --gtest_filter='*Owner*:*Future*'`（owner 并发路径是
  E3 P1 quiescence 的竞争高发区）；再全量 lpc_tests；再 driver 全量 ftest
- TSan 发现必须**分类**到目标代码 / 已有基线 / 第三方库，保存完整栈；
  不能以"疑似误报"关闭（v0.4 §16.3 纪律）
- **退出条件**：owner 定向零 race；全量 lpc_tests 无目标代码 race；
  driver 全量 ftest 无目标代码 race；分类表落盘 docs/evidence/tsan-*.txt

### P5 — owner 压测（L7，commit 7）

- bench 工具已在盘（src/tests/CMakeLists.txt）：
  - `owner_runtime_bench`（owner 调度/并发基线）
  - `lpc_vm_bench`（VM 吞吐基线）
  - `object_store_bench`（对象存储基线）
- 新增：多 owner 重复热重载压测（E3 专项）——N 个 owner 并发任务 + 主线程
  循环 recompile_object（每轮 200 次 × M 轮），验证 quiescence 不超时、
  admission 拒绝计数单调、无泄漏（配合 ASan）
- **退出条件**：三个 bench 基线落盘；热重载压测 M 轮零失败、零超时、
  ASan 零报错；owner_quiesce_* 指标在 runtime status 可观测且合理

### P6 — E3 v2 设计（L8，commit 8，文档产出）

- v2 能力：master/simul_efun 热重载、`__INIT`/`create()` 执行、失败回滚
- 已确认扩展点（v1 架构审计结论）：
  - snapshot 走 obj_list 天然覆盖 master/simul_efun（无需新遍历）
  - v1 拒绝点在 efuns_main.cc 特判（master/simul_efun）——v2 移除特判
  - 需补：master 缓存态失效语义（apply_cache/master_applies 表重建、
    simul_efun dispatch table 重建）、__INIT/create 的失败原子性
    （create 抛错时回滚到旧 program）、commit 段扩展（create 不能在
    no-fail 段内执行——需拆分 commit 阶段）
- **产出**：`docs/recompile-object-v2-design-2026-08.md`（参照 v0.4 格式：
  审计、合同、阶段、门禁、测试矩阵）
- **退出条件**：设计文档完成；**实施不并入本批**，走单项授权

### P7 — E4 `read_source_line()` 移植评估（L9，commit 9，评估产出）

- 现状：本地 src 树零匹配（该函数不存在，属移植而非修复）
- 上游对照：#1343a（read_source_line 独立优化）；本地诊断栈
  （disassembler.cc 等）是否具备等价能力需先 diff
- 验收门（optimization-plan §6.1 既定）：输出逐字节一致 +
  `compile_diagnostic_ns_per_case` 中位数 ≥10% 改善（7 样本；5%-10% 或
  p95 回退 >5% 时扩 15 样本）；scratchpad arena 所有权单元保持 deferred
- **产出**：移植评估文档（可行性 + 差异清单 + 性能基准结果）
- **退出条件**：评估文档完成；实施需单独授权

### P8 — T3 lpcshell 前置基建立项（L10，commit 10，立项产出）

- 现状：lpcshell 依赖上游 #1343 scratchpad/结构化诊断基建（本地不存在）
- **产出**：`docs/lpcshell-prerequisite-plan-2026-08.md`——诊断渲染基建
  的设计范围（结构化诊断输出、scratchpad arena、lpcshell REPL 交互合同）、
  与 E4 的共享依赖（read_source_line 属诊断栈一部分）、阶段拆分
- **退出条件**：立项文档完成；基建实施需单独授权

## 3. 执行纪律（沿用 v0.4）

- 每阶段独立原子 commit，顺序执行，退出条件满足才进入下一阶段
- 修改代码前先说明方案；本方案 P0-P5 属已授权范围（P7 门禁 + 收尾），
  P6-P8 仅产出文档
- 证据落盘 `docs/evidence/`（原始日志，非 /tmp），commit 内绑定
- 提交后 grep 验证（本会话多次"以为改了实际没改"，硬要求）
- 验证命令保留真实退出码，不用 `|| true`、不过滤失败
- 本方案文档自身只由用户/GPT 修订；我负责验证与执行

## 4. 风险与备选

| 风险 | 影响 | 备选 |
|---|---|---|
| P1.1 实验不解决 UBSan | L5 全矩阵阻塞 | P1.2-alt：lpc_tests `-fno-sanitize=null`；仍不行则 no_sanitize attribute 包 helper |
| TSan 全量超时/误报多 | L6 延迟 | 分类表 + 定向先行；第三方库条目单独记录 |
| 热重载压测暴露 quiescence 超时 | P5 不通过 | 调 `__RECOMPILE_OBJECT_QUIESCE_TIMEOUT_MS__`（CFG_INT 71）；回 v1 审计 |
| E4 性能改善 <10% | 验收门不过 | 按既定扩样本（15）；不达标则 deferred 记录，不硬推 |
| E3 v2 的 create 失败原子性复杂 | 设计周期长 | 拆两期：先 master/simul_efun（无 create），再 __INIT/create + 回滚 |

## 5. 验证矩阵总表

| 阶段 | 验证 | 期望 |
|---|---|---|
| P0 | build-sync 构建 + 424 lpc_tests | 通过 |
| P1 | ASan 定向 filter（ReadBytes/WriteBytes/FileSize） | 零 runtime error |
| P2 | 全量 lpc_tests（build-sync）+ lpcc/fuzz 构建 | 424/424 + 构建通过 |
| P3 | ASan ftest 全量 + lpc_tests + ctest + recompile 定向 | 0 failed + 424/424 + 全绿 |
| P4 | TSan owner 定向 + 全量 | 零目标代码 race |
| P5 | 三 bench + 热重载压测 | 基线落盘 + M 轮零失败 |
| P6-P8 | 文档产出 | 审阅 + 单项授权 |

## 6. 交付物清单

- commit 1：**L1+L3 合并**（4830d2ba）——UBSan null-check 全局关闭 +
  证据文档 L3 改写（L3 依赖 L1 机制定案；旧排序已废弃）
- commit 2：L4 lex.cc include 清理（edf5b8bf）
- commit 3：L2 RAII helper 统一（scoped_current_object_as_master.h +
  全点位替换，进行中）
- commit 4：L5 ASan 全矩阵证据（docs/evidence/）
- commit 6：L6 TSan 构建 + 分类表
- commit 7：L7 压测基线 + 热重载压测
- commit 8：L8 E3 v2 设计文档
- commit 9：L9 E4 移植评估
- commit 10：L10 T3 前置基建立项文档
