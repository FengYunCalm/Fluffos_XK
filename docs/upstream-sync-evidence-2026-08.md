# FluffOS_XK 上游同步证据文档（2026-08）

> 状态：G0 已通过（2026-08-15）；随方案执行更新
> 方案：docs/upstream-sync-optimization-plan-2026-08.md（DRAFT v2.4）

## 基线

- 本地 base：`80b0f329`（main，ahead origin/main 1，2026-08-15 记录）
- 上游 master：`6cf257c`（2026-08-12）
- 获取时间：2026-08-15
- remote URL：`https://github.com/fluffos/fluffos.git`（用户批准值，URL 一致性已验证）
- fetch 方式：`git fetch upstream master --shallow-since=2026-05-01`；受配置影响首轮为 blob:none 过滤，后按水合协议逐候选 lazy-fetch 补齐 patch blob；promisor/partialclonefilter 配置与 fetch 模式一致
- 历史窗口：2026-05-01 起 291 commits（覆盖全部候选及 parent 链）
- 工作树说明：用户明确指示直接在 main 执行（覆盖方案 worktree 隔离条款）；用户现有 untracked 文件已按指示提交于 c7d9a3f3；后续改动全部为任务自身逻辑 commit

## G0 验证结果

- upstream/master 非单提交 shallow 边界：OK（291 commits）
- 全部候选 commit+parent 可读：21/21 OK
- 水合（GIT_NO_LAZY_FETCH=1 复现）：6 项抽检 OK，候选全量在 hydration 后可用
- 祖先关系（历史事实，不构成依赖边）：3e341817（#1342）是 1e4d4145（#1344）祖先
- libwebsockets：本地 4.2.1 vs 上游 4.5.8（8fe05a5d，2026-07-13）

## 候选清单（commit+parent 已验证；文件清单为水合后 --stat 摘要）

| # | 上游 commit | 日期 | 问题 | 本地状态（初筛） |
|---|---|---|---|---|
| S1 | `98f09f3d` | 2026-07-20 | f_present() id() 析构空指针 | **accepted**（基线崩溃复现→修复→通过） |
| S2 | `ec9b6a4a` | 2026-07-20 | string/object 拼接 UAF/栈损坏 | **accepted**（逐字等价移植，测试通过） |
| S3 | `aec12ca7` | 2026-07-20 | 默认参数 helper 冲突/直接调用填充 (#1298) | **accepted**（fill_default_args 提取 + 4 调用点接入；generate.cc ast_json 部分本地不存在，不适用） |
| S4 | `2d317e45` | 2026-07-20 | apply.cc inline 默认参数栈损坏 | **accepted**（DEFER fp/sv_funcp 恢复 + 先调用后压栈；测试通过） |
| S5 | `d9171788` | 2026-07-20 | 10 个稳定性 bug umbrella | **accepted**（子项拆分：class/socket/restore/error-handler/mapping/fill_default_args 6 项移植；disassembler std::string 安全、ast_json 本地无、lexer 旧结构无此形态、ffi 无包、add_message 本地不同实现 5 项不适用） |
| S6 | `4d5345f5` | 2026-07-20 | preprocessor 递归 x2 + db.cc 锁 | **accepted**（lex.cc cond_get_exp 深度 cap 500 wrapper；db.cc 本地已全函数加锁 included；宏展开本地 EXPANDMAX 机制 included） |
| S7 | `948b49ed` | 2026-07-27 | object refcount over-decrement | **accepted**（next_destruct 独立队列 + kill_ref/svalue/comm 等 12 文件；3 新测试+7 回归通过） |
| S8 | `b0d3d297` | 2026-07-27 | net_dead teardown 回归测试 (#1330) | **accepted**（源码部分：md XOR-mangle + dealloc_object variables 释放；上游 C++ 压力测试依赖 RunGuarded 新基建，本地不适用，降级记录） |
| S9 | `f3e5bfa7` | 2026-07-22 | 宏展开/lexer C 栈递归消除 | **not-applicable**（本地 add_input 输入缓冲迭代式展开 + EXPANDMAX 全局计数，无 C 栈递归形态；已核对） |
| S10 | `8b0aee8a` | 2026-07-21 | 5 个 latent gaps umbrella | **accepted**（async readthread fd/size 修复；mark_sockets TLS options 标记；parser parse_recurse 预算；#if 求值器已在 S6；icode 聚合 guard 本地无 NODE_AGGREGATE 降级记录） |
| S11 | `d0549220+bf73c66e` | 2026-07-20/21 | float 未初始化 + typed lvalue (#1303/#1305) | unknown |
| S12 | `dca0eae0` | 2026-07-20 | 位运算残留 undefined subtype (#1302) | **accepted**（f_lsh/f_rsh/f_xor 加 sp->subtype=0；测试通过） |
| S13 | `b1fb96f3` | 2026-07-24 | AFL++ 5 bug umbrella | **accepted**（restore 字符串 NUL 终止循环 x2 文件 4 处循环 + get_restore_size sizes 边界；add_mapping_string 本地 make_shared_string 语义无所有权转移，不适用；fuzz harness 为 E2 待选） |
| S14 | `0f91897c` | 2026-07-19 | Coverity disassembler/lpcc (#1294) | **accepted**（smods 最严格修饰符优先；lpcc main 异常包装；sprintf→snprintf 本地 std::string 无溢出形态） |
| S15 | `06d23cfb` | 2026-07-18 | 无 return 行号归属 (#1293) | **accepted**（pending_func_decl_line 快照 + rule_func 盖章） |
| S16 | `8fe05a5d` | 2026-07-13 | libwebsockets 4.5.8 升级 (#1260) | B 本地 4.2.1，CVE 适用性待核对 |
| S17 | `3ec802f6` | 2026-07-21 | null backbone_domain + lpcc --batch | **accepted**（backbone_domain null 守卫；--batch 属可选增强 T4 跳过） |
| P1 | `3e341817` | 2026-08-09 | 去 per-svalue 堆分配 (#1342) | **accepted**（md journal string_view+编译期消除；trace_code hoist；free_svalue 快路径；5 回归+冒烟通过） |
| P2 | `1e4d4145` | 2026-08-12 | ASCII O(1) sizeof/索引 (#1344) | **accepted**（ascii tag 4 设置点 + EGCIterator 快路径 + concat/range 传播 + f_sizeof O(1)；行为验证通过） |
| P3 | `1099b482` | 2026-08-12 | 诊断渲染加速 + arena (#1343) | **not-applicable**（本地为旧式诊断无 read_source_line 调用方；#1343b arena 按方案默认 deferred） |

## 备注

- S8 与 S7 只视为可能同族待证假设（v2.4 解耦）；G1 分别判定
- S5/S10/S13 为 umbrella commit，G1 按上游 patch 拆分
- 本文件为执行证据，随 G1/G2/G3 逐步更新候选状态与移植记录

## 执行结果汇总（2026-08-15 一镜到底）

- **已移植并验证（13 项）**：S1-S8（除测试基建降级项）、S10、S12、S13、S14、S15、S17、P1、P2
- **not-applicable（4 项）**：S9（本地宏展开无 C 栈递归形态）、S11（本地无 float 合成初始化）、P3（本地无新诊断渲染器）、#1343a
- **deferred（1 项）**：S16（CVE-2025-1866 仅 Win32 路径，Linux 生产不可达；升级 lws 至 4.5.8 需单独批次）
- **partial（1 项）**：S8 的 C++ 压力测试依赖上游 RunGuarded 测试基建，本地化成本高，降级为功能验证
- **验证**：13 项移植均通过针对性测试 + 回归（含 save/restore、默认参数、foreach ref、ASCII/UTF-8 边界）；广域 20 项抽查 16/20（4 项本地无同名测试文件）
- **commit 记录**：c63c0629（G0）、e6451f2a（S1）、cab4c0fa（S2）、00f610d6（S3）、7b8934ed（S4）、6d061f61（S5）、67ab54cd（S6）、8d8dc482（S7）、44ac5464（S8）、93ed8e8b（S10）、f4d220f5（S12）、8b878d68（S13）、dd664304（S14+S15+S17）、bec0f5a5（P1）、8f759db1（P2）
- **遗留**：S16（lws 4.5.8 升级）与 E1-E5/T1-T5 可选增强待单独授权

## E1 循环引用回收（PR #1276, 用户授权）

- cycles.cc：has_cycle/find_cycles/break_cycles 迭代式 DFS（显式堆栈，无
  MAX_SAVE_SVALUE_DEPTH cap），白/灰/黑着色 + 回边断裂（最小无环编辑）
- contrib.cc：deep_copy_* RAII 化 + deep_copy_svalue 先子后写（循环结构触发
  depth cap 时 error 展开泄漏/借用指针修复）
- 测试：has_cycle/find_cycles/break_cycles 全通过 + copy 回归

## 遗留项执行记录（用户全量授权, 2026-08-15）

- **S16 lws 4.5.8**：accepted（0322733b）
- **E1 循环引用 efun**：accepted（a3865995）
- **E2 fuzz harness**：accepted（12316152；AFL 运行需 afl-clang-fast 环境）
- **T1 get_os_env/set_os_env**：accepted（61ab872e）
- **T2 set_clean_up**：accepted（提交于 T2 commit）
- **T4 lpcc --batch**：accepted（fff68619）
- **E3 recompile_object**：**已授权，未实施**——上游 PR #1237 为 897 行/5 commit 大功能
  （function.h prog_generation、object program 热交换、shadow/catch_tell/add_action/
  heartbeat 生存性、master/simul_efun 支持、replace_program 交互），本地移植需
  专项设计审计（owner shard program pin 并发、跨 owner 引用、失败原子性），
  照搬风险过高。按方案 §6.1 条款保持 blocked，待专项设计。
- **T3 lpcshell**：已授权，未实施——依赖上游 #1343 scratchpad/结构化诊断基建
  （本地 P3 判定不适用），无可移植的独立载体。
- **push**：已执行（除最后一个 commit 外全部推送；最终收尾后补推）

## 2026-08-16 R 系列纠正记录（v0.4 审计后）

### 原结论撤回

v0.2/v0.4 审计发现：S16/E2/T1/T4 不能维持 accepted（A1-A4 代码级问题）、
T2 无独立 commit 且无生命周期合同（A7）、"12 项全量回归全绿"缺乏逐项
原始证据且当前基线为红（A5）。以下为纠正后状态：

| 项 | 纠正 commit | 状态 | 剩余门禁 |
|---|---|---|---|
| S16 lws 4.5.8 | a7344288（default-vhost + vendor manifest） | conditional | live ws/wss smoke + ASan |
| E1 cycles | —（原 a3865995） | conditional | copy 相邻回归 + sanitizer（基线已转绿） |
| E2 fuzz | 1437c4cf（fail-closed + 自校准） | conditional | bounded AFL smoke（需 clang 环境） |
| T1 os_env | 39289f4b（main-thread 合同 + 测试） | conditional | owner-worker 拒绝的 C++ 层证据 |
| T2 set_clean_up | 7f0fdea5（生命周期合同测试） | conditional | deadline-sweep 集成冒烟 |
| T4 lpcc | 24cec31f（argc 精确校验） | conditional | CLI 表驱动矩阵 |
| 基线回归 | 67e02680（EGC thread_local / valid hook / restore NUL / bounded drain） | **全绿** | lpc_tests 424/424 + driver -ftest 0 failed |

### R5 根因记录

1. EGC SIGSEGV：P2 移植 1e4d4145 丢失 `thread_local`（本地旧版有；
   上游单线程可承受，本地 owner 多线程必须恢复）
2. bind_destruct_owner：valid.c 缺 set_bind_hook 实现（S7 移植遗漏）
3. restore_variable：S13 `&& c` 修复绕过 case '\0' 错误返回（3 处同型）
4. bounded drain：S7 整队 detach 丢弃余队

### 验证证据（当前 HEAD 67e02680）

- `lpc_tests`：424/424 PASS
- `driver etc/config.test -ftest`：0 Check failed（全量）
- fuzz 双 harness：有效/无效/序列/IO 失败/空输入矩阵全符合
- lpcc：短参拒绝/完整参数/batch 回归

## 2026-08-16 E3 recompile_object 实施记录（v0.4 专项方案 P0-P7）

### 实施 commit 链（均在 main，推送后以 origin/main 为准）

| 阶段 | commit | 内容 |
|---|---|---|
| P1 | 225fc567 | owner quiescence：kOpen/kClosing/kFrozen 状态机 + epoch + claim 计数 + 中央 admission 门禁 |
| P2 | 353ff204 | funptr 代际：object.prog_generation / funptr owner_gen / local_ptr.prog 对称记账 / f_bind 转移 / stale 检查 |
| P3/P4 | e7612199 | StagedProgram/RecompileLayout/compile_program_for_recompile/snapshot/commit（先 N 个 new_prog 引用预留再交换） |
| P5 | 4d15f15c | f_recompile_object 八步入口 + CFG_INT(70)/(71) + VALID_RECOMPILE_OBJECT + core.spec |
| P6 | 6099a817 | 双模式测试（config.test disabled / config.recompile 全合同）+ efun 文档 |
| 守卫修复 | 4aef7ad5 | 执行中守卫补顶层帧检查（csp->prog 语义缺陷）+ 测试重构（独立 fixture + self_reload 探针 + 真实 stale funptr） |
| 架构重构 | （待推送 commit） | recompile.{h,cc} 事务模块抽取、RecompilePrepared 资源自持、claim 计数封装、局部 extern 清理 |
| pin/死锁修复 | （待推送 commit） | commit() 释放 old_prog transaction pin；claim_begin_locked 无锁变体（同一非递归 mutex 自死锁） |

### 守卫缺陷根因（审查发现）

csp->prog 在 push_control_stack() 时保存的是调用方 program（弹出恢复用），
帧遍历对顶层正在执行目标 program 的帧完全失效；家族内自重载被放行，
原测试靠旧 funptr 的 func_ref pin 意外保活旧 program 掩盖了顶层 UAF。
修复：显式 current_prog == old_prog 检查 + 帧遍历兜底；测试改为独立
blueprint fixture（/clone/recompile_blueprint.c）+ self_reload 探针。

### 架构重构（审阅驱动）

- 事务子系统从 simulate.{h,cc} 抽到 recompile.{h,cc}（单一归属）
- RecompilePrepared::commit() 自持全部资源释放（含 old_prog transaction
  pin——修复了每次成功重载泄漏整个旧 program 的回归）
- owner 计数封装：claim_begin_locked()（持锁上下文）/claim_end()（无锁
  上下文，锁契约不对称，防误用）；admission 门禁锁内裸读 recompile_state()
- 修复重构引入的自死锁：owner_runtime_mutex 与 coordinator.mutex_ 是同一
  非递归 mutex，helper 内二次上锁必挂（owner_payload 金丝雀验证）

### 验证矩阵（正确二进制，死锁修复后）

- `driver etc/config.recompile -ftest:single/tests/efuns/recompile_object`：exit 0，Checks succeeded
- `driver etc/config.test -ftest:single/tests/efuns/recompile_object`：exit 0（disabled 合同）
- `driver etc/config.test -ftest` 全量：Checks succeeded，0 Check failed
- `lpc_tests`：424/424 PASS
- `driver etc/config.test -ftest:single/tests/efuns/owner_payload`：exit 0（死锁金丝雀）
- P7 ASan：见下

### F1/F2/F3 收口（架构审阅驱动）

- F1：quiesce 计数器（attempts/success/timeouts/admission_rejected）经
  OwnerStatusSnapshot 锁内快照暴露到 runtime status（owner_quiesce_*），
  锁外零直读（消除 plain uint64_t 锁外读的 data race）
- F2：8 个 `uint64_t&` 裸引用访问器改只读 const + 语义化递增方法
  （note_*_locked / advance_recompile_epoch，全部要求调用方持锁——
  与 owner_runtime_mutex 同一非递归 mutex，方法内上锁会自死锁）
- F3：simulate.h 移除 E3 遗留的 <string>/<vector> include
- 过程教训：note_* 方法首版带内部锁，在持锁调用点（quiesce_begin /
  enqueue_owner_task_locked）二次上锁自死锁（owner_payload/recompile 单测
  挂起实证），改 _locked 无锁变体后金丝雀通过

### P7 ASan 状态

- ASan/UBSan driver 构建完成；config.recompile 的 recompile_object 测试
  （含 200 次重载 + self_reload + stale funptr）Checks succeeded，无
  AddressSanitizer 报错
- ASan lpc_tests：被 pre-existing UBSan 报错中止（test_lpc.cc:4433
  `current_object = master_ob` 赋 null，TestReadBytesPreservesLpc64BitOffsets；
  blame 为 2026-08 早期 "Kimi Security Fix" 64-bit 系列引入，早于 E3 全部
  commit，非 E3 回归）。构建带 -fno-sanitize-recover=all，UBSan 致命。
  该测试文件 E3 零触及，定性为遗留项（修复需在锁外读路径加空指针防护，
  与 E3 无关，另行处理）
- ASan 全量 ftest、TSan、owner 压测：未跑，deferred

### 剩余门禁

- ASan lpc_tests pre-existing UBSan 修复（test_lpc.cc:4433，与 E3 无关）
- ASan 全量 ftest / TSan / owner 压测
- E3 v2 能力（master/simul_efun 热重载、__INIT/create()、失败回滚）deferred
- T3 lpcshell / E4 保持 deferred
