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
- ASan lpc_tests 曾被 UBSan 报错中止（test_lpc.cc:4433 / efuns_main.cc:231
  "store/load of null pointer"）。**根因定案（2026-08-17，实验证伪链 +
  全量矩阵经验确认）**：GCC 13.3 的 UBSan null-check 对
  `FLUFFOS_VM_THREAD_LOCAL`（thread_local）访问的编译侧误报——
  插桩证实 master_ob/&current_object/TLS 基址全部非 null；报错点随
  lpc_tests 二进制布局在 test_lpc.cc 与 efuns_main.cc 之间移动（libdriver
  逐字节未变）；非 sanitizer 构建同一启动路径全绿。修复：
  src/CMakeLists.txt ENABLE_UBSAN 分支加 `-fno-sanitize=null`（全局，
  ASan 仍捕获真实 null 解引用）。修复后验证：ASan 构建全量 lpc_tests
  424/424 PASS、零 sanitizer 报错（docs/evidence/ubsan-enumerate.txt）；
  ASan driver 全量 ftest Checks succeeded（`ASAN_OPTIONS=detect_leaks=0`，
  docs/evidence/asan-ftest-final.txt）；recompile 定向全绿
  （docs/evidence/asan-recompile-final.txt）。证据：docs/evidence/ubsan-*.txt
  系列
- **LSan 泄漏说明（归因实验定案，2026-08-17）**：driver ftest 全量退出时
  LSan 报 24 个 allocation（8 个 LPC mapping 字面量 + 16 个
  vm_owner_runtime_status 48B mapping）；逐测试定向验证
  （docs/evidence/asan-*-lsan.txt）：纯同步测试（os_env /
  owner_executor_contract / recompile）**零泄漏**（退出清理正常）；
  async 定向 6 分配 200KB（async_read 请求 state + 数据 buffer，
  async.cc add_read，最后改动为 S10 审计 93ed8e8b）；socket_tls_server
  定向 389 分配 23KB（SSL_CTX + libevent event）。**归因：既有异步资源
  （async req / TLS ctx / socket event）退出清理缺口，与 E3 无关**
  （E3 相关测试 recompile/owner_executor_contract 定向零泄漏）。上游 CI
  sanitizer 步骤只跑 ctest（gtest），从不跑 driver ftest，故该缺口上游
  从未暴露。异步资源退出清理修复单独立项
- TSan、owner 压测：deferred（见 docs/recompile-followup-plan-2026-08.md
  L6/L7）

### 剩余门禁

- TSan / owner 压测（L6/L7）
- E3 v2 能力（master/simul_efun 热重载、__INIT/create()、失败回滚）deferred
- T3 lpcshell / E4 保持 deferred

---

## #1247 同步矩阵（A-S0，2026-08-18）

> 上游输入：PR #1247（四轮审计 61 修复）。补丁 `/tmp/pr1247.diff` SHA-256 `79d4648dec2b4b83173d2d2ee9336469e4d94ad5829b138b11a109ccaad2d2d9`；`git apply --numstat` 实测 47 src 路径 + 19 testsuite 路径（2 clone fixture + 17 runnable），130 hunk。本地基线 HEAD `2785c8a6165eab7d32842306468cd0b48eab17aa`。
> 状态取值：`未移植` / `已覆盖` / `等价保护` / `不适用`。标记约定：移植点落 `// #1247 <hunk_id>`，等价保护点落 `// #1247-equivalent`。

### 已覆盖 / 等价保护（12 hunk，无需移植）

| hunk_id | 上游 hunk | 缺陷 | 本地落点 | 状态 | 证据 |
|---|---|---|---|---|---|
| SYS-1 | sys.cc:54-64 | external_port 按 sizeof 越界索引 | sys.cc:76-80 | 已覆盖 | std::size + INT64_MIN-1 保护（更强） |
| MATH-1 | math.cc:176-186 | norm 用 sp->u.arr->size 而非 a->size | math.cc:212 | 已覆盖 | `LPC_INT len = a->size` |
| OBJ-1 | object.cc:66-84 | restore 错误路径泄漏 sizes/脏 depth | object.cc:70-74,939,1050 | 已覆盖 | reset_restore_scratch 已移植 |
| RECLAIM-2 | reclaim.cc:52-56 | funptr owner 双重递减 | reclaim.cc:52-56 | 已覆盖 | E3 P2 已修（v0.4 §10.3） |
| PARSE-1 | ops/parse.cc:1060-1072 | living_parse 非对象解引用 | ops/parse.cc:991 | 已覆盖 | `type != T_OBJECT → continue` |
| CALLOUT-1 | call_out.cc:557-558 | reclaim owner NULL 解引用 | call_out.cc:693 | 已覆盖 | `!hdr.owner \|\|` 检查 |
| SOCK-1 | socket_efuns.cc:accept | accept_fd 未设 closeonexec | socket_efuns.cc:720 | 已覆盖 | `evutil_make_socket_closeonexec(accept_fd)` |
| PCRE-1/2 | pcre.cc:921-1010 | pcre_get_replace 长度发散 | pcre.cc:128-143 | 等价保护 | pcre_build_replace_segments 非重叠构建 |
| MUDLIB-1..4 | mudlib_stats.cc | strcpy 越界 | mudlib_stats.cc:367,465 | 等价保护 | std::string 返回值，无固定缓冲 |
| COMM-2 | comm.cc:902-912 | bad_init_call 检查 | comm.cc:2022-2033 | 已覆盖 | 由 COMM-1 吸收（严格更强：teardown 释放 sent）；detach 路径检查已删除（不可达） |
| SIMULATE-1 | simulate.cc:880-894 | recompile fd 泄漏 | recompile.cc:52 | 等价保护 | 本库 v2 事务架构：非法路径显式 close(f)，编译路径 FileLexStream RAII 持有 fd（成功与 throw 均释放）；上游 DEFER close 不需要 |
| SOCK-4 | socket_efuns.cc:SC_* | SC_* 标志移头文件（external 包依赖 sockets 导出标志，未来 socket 重构须保持标志稳定） | socket_efuns.h:111-113 | 编译测试 | 已覆盖（batch4 4056b8a2） |

### 不适用（8 hunk，6 文件本库不存在）

| hunk_id | 上游 hunk | 理由 |
|---|---|---|
| GRAMMAR-EXPRS-1 | grammar_rules_exprs.cc:1886 | 上游 #1210 Flex 重构产物，本库无此文件（旧 lexer 保留） |
| GRAMMAR-TYPES-1 | grammar_rules_types.cc:121 | 同上 |
| LEXER-PP-1/2 | lexer_rules_pp.cc:985,993 | 同上 |
| LEXER-UTIL-1/2 | lexer_utils.cc:1412,1424 | 同上 |
| TRANSPORT-1/2 | transport_libevent.cc:374,410 | 本库无此文件；clamp 等价物在 comm.cc:88,98（kMudPortMaxPayload） |
| FFI-1/2 | ffi.cc:632 | 本库无 FFI package（上游 #1235 未移植） |

### 未移植（A-S1：安全/UB，约 60 hunk）

| hunk_id | 上游 hunk | 缺陷 | 本地落点 | 回归测试 | 目标提交 |
|---|---|---|---|---|---|
| PORT-1/2 | port.cc:20-40 | random_number n≤0 UB | port.cc:29,42 | 不可单测（内部 uniform_int_distribution 调用点），以代码审阅 + 编译为证据 | c065ca74 |
| STRALLOC-1 | stralloc.cc:97-104 | htable 无 2^30 cap | stralloc.cc:102 | 不可单测（配置级容量），以代码审阅为证据 | c065ca74 |
| STRUTILS-1 | strutils.cc:111-122 | rfind pos==0 死循环 | strutils.cc:91-94 | strsrch_reverse_egc.lpc | c065ca74 |
| COMPILER-1 | compiler.cc:821-829 | yywarn 格式串注入 | compiler.cc:580 | 新增 % 文件名测试 | c065ca74 |
| DISASM-1 | disassembler.cc:678-692 | etable-4 短偏移越界 | disassembler.cc:669 | 新增反汇编测试 | c065ca74 |
| TREES-1 | trees.cc:184-194 | INT_MIN % -1 SIGFPE | trees.cc:215-219 | a2_grammar.lpc（expr0 % -1 编译期） | 0d3f8ed8 |
| TELNET-1/2 | telnet.cc:360-381 | LINEMODE buf[1] 越界读 | telnet.cc:324-331 | TestTelnetLinemodeShortSubnegotiation（C++ 层，2026-08-19） | 0d3f8ed8 |
| TELNET-3 | telnet.cc:712-735 | ZMP off-by-one 越界写 | telnet.cc:668-673 | TestTelnetZmpArgcVariants（C++ 层，2026-08-19） | 0d3f8ed8 |
| ASYNC-2..4,9 | async.cc:76-130,589-623 | current_work(s) 多飞行记账 | async.cc:81-86,104-110,124-138,776-789 | 未落地（需多 worker 并发环境）；run.py async 用例已有常规覆盖 | 028955dd |
| ASYNC-5 | async.cc:273-283 | getdirthread dirent 大小 | async.cc:356-363 | 未落地（需多条目目录 + 并发）；以代码审阅为证据 | 028955dd |
| ASYNC-6..8 | async.cc:306-355 | 拒绝路径 callback 泄漏 | async.cc:388-391,403-406,415-420 | 未落地（需 valid_read/write 拒绝配置） | 028955dd |
| PARSER-1..9 | parser.cc:78-88,626-638,713-716,738-748,2877-2890,3399,3450,3515 | verb node UAF + 深度防护 | parser.cc:84-92,619-626,644,707,733-740,2903-2909,3441,3492,3557 | parser_handler_destruct.lpc | 538e2531 |
| OBJ-2..5 | object.cc:257-270 等 | restore 深度无上限（栈溢出 DoS） | object.cc:275 | restore_variable.lpc | 9565ccb4 |
| ARRAY-1/2 | array.cc:125-144 | allocate_array2 T_FUNCTION 泄漏 | array.cc:128 | allocate.lpc | A-S1-array-leak |
| BUFFER-1 | buffer.cc:44-67 | write_buffer 有符号溢出 | buffer.cc:46-64 | write_buffer_bounds.lpc、buffer_range_assign.lpc | 9565ccb4 |
| INTERP-1 | interpret.cc:976 | memcpy from->u.buf 头部垃圾 | interpret.cc:1081,1244 | 新增 buffer 复制测试 | 0d3f8ed8 |
| INTERP-2..4 | interpret.cc:3314-3324,3700-3707 | INT_MIN 除法/取模 SIGFPE | interpret.cc:3511,3837 | a2_runtime.lpc（INT64_MIN / -1 与 % -1 运行时） | 0d3f8ed8 |
| OPS-1/2 | ops.cc:48-58,387-397 | f_div_eq/f_mod_eq INT_MIN | ops.cc:74-82 | a2_runtime.lpc（运行时 / -1 与 % -1） | 0d3f8ed8 |
| CONTRIB-1 | contrib.cc:743-753 | terminal_colour raw apply 泄漏 | contrib.cc:710 | terminal_colour_error_replace.lpc | A-S1-contrib-colour |
| CONTRIB-2 | contrib.cc:replaceable | 空 ignore 数组 NULL 写 | contrib.cc:1615-1680 | replaceable_empty.lpc | A-S1-contrib-replaceable |
| CONTRIB-3 | contrib.cc:repeat_string | 乘法溢出 | contrib.cc:1942 | 新增长度极值测试 | A-S1-contrib-repeat |
| CONTRIB-4 | contrib.cc:query_replaced_program | current_object 误用 | contrib.cc:1960 | 新增测试 | b121f6e0 |
| ED-1..4 | ed.cc:658-669,869-885,1057-1069,1267+ | prntln/getfn/getrhs/optpat 越界 | ed.cc:713-717,922-953 | 未落地（需 ed 会话驱动）；以代码审阅为证据 | 9565ccb4 |
| FILE-1..3 | file.cc:242-253 等 | get_dir strcat 无边界 | file.cc:337 | a2_runtime.lpc（长路径不崩） | 9565ccb4 |
| CALLOUT-2 | call_out.cc:606-632 | 秒×1000 溢出 | call_out.cc:777-782 | a2_runtime.lpc（巨/负延迟饱和） | c065ca74 |
| TIME-1/2 | time.cc:136-148 | strftime 栈 VLA | time.cc:146 | a2_runtime.lpc（200×%Y 长格式） | 9565ccb4 |
| DB-1/2 | db.cc:664-733 | BLOB 按列宽读行 | db.cc:772-773 | 新增短 BLOB 测试 | A-S1-db-rowlen |
| SPRINTF-1..7 | sprintf.cc:1093 等 | 精度/列/边界 | sprintf.cc（多处） | sprintf.lpc、sprintf_column_object.lpc | A-S1-sprintf-bounds |
| MATRIX-1..7 | matrix.cc:47 等 | 6 个 transform 缺 16 元素 | matrix.cc:52,102,145,185,225,270,314 | 新增 16 元素测试 | 4056b8a2 |
| SOCK-2/3 | socket_efuns.cc:host | lpcaddr_to_sockaddr host 长度 | socket_efuns.cc:189-195 | socket_long_host.lpc | 4056b8a2 |
| APPLY-1/2 | apply.cc:89-132 | error(buf) 格式串 + 边界 | apply.cc:75-145 | 等价保护（本地已 error("%s")）；无独立测试 | 4056b8a2 |
| MAPPING-1 | mapping.cc:1154-1164 | compose_mapping key 泄漏 | mapping.cc:1200-1203 | a2_runtime.lpc（mapping * join 语义） | 4056b8a2 |
| TRACE-1 | trace.cc:43-51 | debug_message 格式串 | trace.cc:46 | 等价保护（本地已 debug_message("%s")）；无独立测试 | 4056b8a2 |
| COMPRESS-1 | compress.cc:309-315 | uncompress 错误路径泄漏 | compress.cc:292-294 | a2_runtime.lpc（垃圾 buffer 错误路径） | c065ca74 |
| ADDACTION-1 | add_action.cc:435-447 | sprintf 越界 | add_action.cc（无 snprintf） | 新增长 verb 测试 | c065ca74 |
| EFUNS-1 | efuns_main.cc:2069-2079 | f_replace_string 快速路径越界 | efuns_main.cc:2063 | 新增长替换测试 | c065ca74 |
| CHECKMEM-1 | checkmemory.cc:680-688 | dfm strcpy 越界 | checkmemory.cc:684 | 新增长 dfm 测试 | 4056b8a2 |
| DWLIB-1 | dwlib.cc:832-841 | 用 one 长度检查 two 写入 | dwlib.cc（无） | 新增替换测试 | 4056b8a2 |
| EXTERNAL-1 | external.cc:124-136 | posix_spawn 失败槽位泄漏 | external.cc:100-110 | 新增失败路径测试 | 4056b8a2 |
| RECLAIM-1 | reclaim.cc:26-29 | nested 提前 return 不平衡 | reclaim.cc:26-29 | reclaim_funptr_owner.lpc | 4056b8a2 |
| COMM-1 | comm.cc:875-895 | bad_init_call STACK_INC 前保护 | comm.cc:1908-1913 | input_to 清理测试 | 7a005dce |

### A-S2（正确性/资源清理）——2026-08-19 核对说明

pr1247.diff 共 66 文件 = 47 C++ + 19 测试。47 个 C++ 文件的覆盖明细分布在 A-S1 表（batch1-9 各批）与本表（A-S2 特有项：grammar_rules_exprs/types 移植、lexer_rules_pp/lexer_utils/transport_libevent 等价保护、ffi N/A、SPRINTF-8..12/MUDLIB-5..8/TIME-2/ASYNC-1 已覆盖）；本表列出 A-S2 归属的 hunk（正确性/资源清理）。

| hunk_id | 上游 hunk | 缺陷 | 本地落点 | 回归测试 | 目标提交 |
|---|---|---|---|---|---|
| MUDLIB-5..8 | mudlib_stats.cc:restore | fscanf 越界 | mudlib_stats.cc:566-570 | std::ifstream + f.width 流读取，无固定缓冲 | 等价保护（锚点已补） |
| SPRINTF-8..12 | sprintf.cc:cst/owned | cst 泄漏/owned 复制 | sprintf.cc:1113,1139 | sprintf.lpc | 已覆盖（batch6 b121f6e0） |
| ASYNC-1 | async.cc:6 | include <set> | async.cc:79 | 编译测试 | 已覆盖（batch7 028955dd） |
| TIME-2 | time.cc:4 | include <vector> | time.cc:6 | 编译测试 | 已覆盖（batch2 9565ccb4） |
| grammar_rules_exprs | grammar.y expr0 '/' 常量折叠 | INT_MIN/-1 SIGFPE | grammar.y:1943-1953 | a2_grammar.lpc（switch case + expr0） | 682f7703 |
| grammar_rules_types | grammar.y `foo(void ...)` | type_of_locals_ptr[-1] OOB | grammar.y:432-449 | a2_void_dots.lpc + a2_grammar.lpc | 682f7703 |
| lexer_rules_pp | 宏参数表 stray 字符死循环 | #define 挂起 | 本 fork 无 dispatch_directive | handle_define 各分支消费或返回，无死循环路径（GETALPHA 消费≥1 否则 lexerror+return） | 等价保护（无锚点，属不同实现） |
| lexer_utils | alloc_local_name >4096 | 堆块溢出 | 本 fork 无 lexer_utils | 手写 lexer SAVEC 4091 cap + 固定 4096 块（见 batch9 long_local_name 适配） | 等价保护（已知差异） |
| transport_libevent | get_user_data 长度前缀 | text_space 负/溢出 | fork 无 transport_libevent | comm.cc decode_mud_port_payload_length kMudPortMaxPayload 钳制 + length==0 拒绝 | 已覆盖（TRANSPORT-1/2 锚点 comm.cc:88） |
| ffi | ffi_address/read offset | int 截断溢出 | fork 无 ffi package | — | N/A（fork 未含该子系统） |
| 其余 | 各文件 | 见 A-S1 表同文件未列 hunk | — | — | — |

> 注：grammar.autogen.cc（无 bison 时的回退源）不含新增防护属既定策略（CMakeLists 声明 generated files never copied back），无 bison 构建会静默丢失防护。



## #1247 A-S1 实施契约与惯例（2026-08-18 追加）

### PARSER-1..9 移植契约（deferred verb nodes）

- deferred 列表 + parse_active_depth 作为**单一状态单元**（一组相邻 static 或一个 struct），所有 verb node 释放收敛到同一 helper，不在 destruct/parse_remove/clear_result 各处散落条件。
- drain 点**必须同时覆盖正常返回与 error() 异常两条路径**（本库 error() 抛 C++ 异常，simulate.cc:2325，异常展开时跨栈帧析构执行）；移植前先读上游 hunk 确认其 drain 位置，上游只在正常完成处 drain 时须补错误路径 drain。

### OBJ-2 约束

- restore_internal_size 预扫描与实际 restore（restore_svalue）是两遍独立遍历，深度防护依赖两者解析一致；**两遍历必须保持同语法**，任何一侧改动须同步另一侧。

### lpc_tests 手工链接惯例

- CMake 目标在静态库变化后不自动重链 lpc_tests（batch3/batch4 均需手工执行 link.txt 命令）。重建后若 lpc_tests 为 0 字节，执行 `build-sync/src/tests/CMakeFiles/lpc_tests.dir/link.txt` 中的命令；后续若修 CMake 依赖（add_dependencies）则删除本条。

### 方案文档外部更新检查清单

- 每次方案文档被外部更新后，grep 验证三项固定契约未被回退：C 阶段为 begin + DEFER end() 单点 RAII（error() 抛 C++ 异常，simulate.cc:2325）；不引入只拥有 arena 的半套 CompileSession；chunk 几何 1MB（对齐上游 9fba6cd3）。

### PARSER-1..9 移植设计（2026-08-18 架构审阅实测确认）

- 上游把 deferred drain 放在 `free_parse_globals()` 末尾（pr1247.diff:1335-1343）；本库 `free_parse_globals` 经 T_ERROR_HANDLER 机制注册（parser.cc:3395-3396, 3445-3446），error() 异常展开时该 handler 确实执行（svalue.cc:175-177，同 unique_array 模式）——**上游 drain 设计在本库天然覆盖 error() 异常路径**，可直接照抄。
- 本地 `free_parse_globals`（parser.cc:687-708）无 early return，drain 追加在末尾；其 free_object(loaded_objects) 循环期间触发的 verb node 释放先入 deferred 列表、末尾统一 flush。
- 本地恰好 2 处 verb node 释放点需改 `free_verb_node(old)`：`parse_free`（parser.cc:621）和 `f_parse_remove`（parser.cc:3511）。
- 移植清单：2 个 static + free_verb_node helper + 两处替换 + clear_result 加 `num = 0`（parser.cc:683-685）+ we_are_finished 的 O_DESTRUCTED 分支（free_parse_result + best_result=nullptr + best_match=0）+ f_parse_sentence/f_parse_my_rules 各一处 parse_active_depth++。

### batch9：.lpc 加载器与测试基础设施（2026-08-19，d8ef20b0）

- simulate.cc `filename_to_obname` 幂等剥离 `.lpc`/`.c`；`load_object` 对原始 pname 做 explicit_ext 探测 + `.lpc` 优先、`.c` 回退（stat 探测，683-687 注释记录 actualname 遮蔽陷阱）；real_name 扩到 sizeof(name)+5 容纳 4 字符扩展名。
- recompile.cc 的 `compile_program_for_recompile` 从 `prog->filename` 推导 src_ext（access R_OK 回退探测，与 load_object 的 stat 探测语义略不同）；simul_efun.cc 不再硬编码 `.c`。
- testsuite/command/tests.c 枚举 `*.lpc` + 跳过被 .lpc 孪生遮蔽的 .c 文件。
- **拼写解析规则原四处内联（simulate.cc filename_to_obname / load_object、recompile.cc、replace_program.cc）+ tests.c LPC 层；已收敛为单一 owner `resolve_source_spelling()` + `source_name_matches()` + `source_spelling_strip_len()`（src/vm/internal/source_spelling.{h,cc}，幂等 strip 归一化同时供 filename_to_obname 与匹配使用），load_object / recompile_object / replace_program 三方共用（tests.c 为 LPC 层独立实现保留）。**
- **replace_program 缺陷（batch9 遗留，随收敛修复）**：旧实现硬编码追加 `.c` + 精确 strcmp，.lpc 源编译出的 prog->filename 携带 ".lpc"，三种拼写（/foo、/foo.lpc、/foo.c）全部匹配失败；现由 source_name_matches 双侧剥后缀比较。已补测试：efuns/replace_program.lpc（三拼写断言 + 继承可达性断言；fixture 置于 crasher/rp_base.lpc，因无 do_tests 不可入常规目录）。
- recompile 探测从 access(R_OK) 统一为 stat+S_ISDIR（目录不再算可回退，语义更严，有意为之）；load_object 显式 .lpc 不回退而 recompile 恒回退（recompile 无法得知请求显式性）为已知取舍。
- PARSE-1 修正落点：living_parse（parse.cc:1064）而非 single_parse（991 锚点为等价保护）；CALLOUT-1 修正落点：reclaim_call_outs（call_out.cc:727-731）。
- object.cc OBJ-2 升级为 nest 语义：restore_internal_size(str, is_mapping, depth, nest)，nest 为真实嵌套深度，grow_restore_sizes() 按需扩容（128 起，INT_MAX/2 兜底）——修复 restore_variable.lpc 深嵌套用例。

### 已知编译器差异：词法数字字面量不支持科学计数法（2026-08-19）

- lex.cc 数字循环（2518-2548）只消费 `0-9 . _`，无 `e`/`E` 分支；`1.0e300` 被切为 `L_REAL("1.0")` + 标识符 `e300` → "syntax error, unexpected L_IDENTIFIER"（sprintf.lpc 曾因此消耗数十轮调试）。
- 紧随其后的 `strtod(yytext,&endptr)` + `endptr != yyp` 检查证明作者本意支持指数（strtod 能解析 e300）——fork 重写 lexer 时的**意外能力回归**，非有意简化。
- 现状：上游 sprintf.lpc 的 `1.0e300` 已改为长十进制字面量（断言只要求 >1000 字符，强度等价），测试注释记录缘由。
- 若日后修复：只改共享 lexer 数字循环（消费 e/E + 可选 +/- + 至少一个数字；无数字则回退让 strtod 报 "Invalid float literal"，错误路径已存在），**禁止给 driver/lpcc 编译入口加条件分支**（compile_file compiler.cc:2018 仍是唯一共享入口）。
- 移植任何含科学计数法字面量的上游测试前先确认本差异。

### C-S1 清单补充：expand 状态每文件复位

- lex.cc:108-109 全局 `expands[EXPANDMAX]`/`expand_depth`；`start_new_file()`（lex.cc:3328-3365）只复位 `nexpands = 0`，**不复位 expand_depth 与 expands[] 内容**（正常展开路径递减）。batch9 加载器每进程编译几十个文件且 crasher/fail 目录故意制造编译错误，属潜伏跨文件污染源。
- C-S1 显式 begin/end 双清理点设计时必须把"每文件复位 expand 状态"显式列入清单（batch9 语法错误已实证与状态无关，不紧急但须覆盖）。
- C-S1 须把 `num_varargs` 隐式协议并入调用帧：interpret.cc:114 的 thread-local 由 codegen（icode.cc:260-268）写入、恰好 6 个 opcode 消费并复位（interpret.cc:3254/3270/3376/3411/4154/4251），与 expand_depth/scratchpad 同类全局旁路状态；新增变参消费 opcode 若漏 `+= num_varargs; num_varargs = 0;` 即静默错参。

### ASan 复验（2026-08-19，A-S1 + A-S2 首批后）

- build-recompile-asan（ENABLE_ASAN=ON + UBSan）全量 -ftest：**0 Check Failed、0 runtime error（UBSan 零报）**；留存 docs/evidence/asan-ftest-a1-a2-2026-08-19.txt。
- 泄漏：`SUMMARY: 17984 byte(s) leaked in 24 allocation(s)`——与基线 docs/evidence/asan-ftest-leaks-full.txt（2026-08-17，batch9 前）**同量同型**（mapping 小块 + owner runtime 大块；构成微差源于 .lpc 测试集差异）。按计划 A 门禁规则"基线已有报告必须单独列出"，**该泄漏集合为基线存量，非 #1247 新增**；本次运行无新增报告。
- 单文件子集（如 sprintf.lpc 1056B/12）泄漏量随执行子集变化，属正常形态差异，非独立缺陷。

### C-S1 实施记录：scratchpad → compile_arena 迁移（2026-08-19）

- 新模块 `src/compiler/internal/compile_arena.{h,cc}`：编译作用域单调 bump 分配器。1MB 标准 chunk（BSS 静态 base + malloc 链），>1MB 请求走 oversize 独立 chunk；end() 释放 live 链、保留至多 8 个标准 chunk 进 retained 池（C-S2 稳态门禁的观测基础）；`begin()` 检测上次 error() 异常（simulate.cc:2325 throw）残留的 live 链并先 drain（compile_file 的 DEFER end() 已覆盖异常展开路径，drain 仅为安全网）。
- `scratchpad.{h,cc}` 降为兼容层：scratch_copy/scratch_alloc/scratch_free(no-op)/scratch_join/scratch_realloc 保留历史名字（grammar.y 十余处调用点不动）；**scratch_destroy/scratch_join2/scratch_large_alloc/scratch_copy_string 删除**（零调用点；scratch_copy_string 的 text-block 路径已并入 lex.cc 共享收集器）；旧导出游标 scr_last/scr_tail/scratch_end 与 scratch_free_last 宏**彻底移除**（直接游标操作是旧边界无法闭合的根因）。
- `lex.cc`：parseStringLiteral 重写为 std::string 收集（无 255 字节窗口截断、无 MAXLINE 上限）+ arena 复制；转义集完整保留（\n\t\r\b\a\e\"\\ 八进制 \x \u 代理对 \U）；text-block 路径复用共享收集器 `collect_string_body(out, count_lines)`（text block 的换行已由 get_text_block 计数，传 false 防行号双计）。
- `compiler.cc`：compile_file 入口 `compile_arena::begin()` + `DEFER { compile_arena::end(); }` 单点 RAII 收口（compiler.cc:2048）；error() 抛 C++ 异常（simulate.cc:2325），异常展开时 DEFER 析构运行，scope 正常释放；begin() 的 drain-if-live 降为纯安全网。
- `mud_status()`（efuns_main.cc:1401-1406，verbose 分支）接线 6 个观测 getter（cycle/peak/chunk_mallocs/reset_count/retained_chunks/retained_heap_bytes）；reset_count 语义为"end 调用次数"，非编译次数。
- 修复记录：scratch_realloc 曾丢 NUL（grammar.y function_name 移位惯用法依赖 NUL 随 payload 搬移，`::do_tests` 变 `do_testst`，TestLPC_FunctionInherit 失败）——改 memcpy(len+1)；text-block 路径曾因 collect_string_body 在开引号处立即返回而恒得空串（@TEXT 测试全挂）——调用点 `outp++` 跳开引号；oversize chunk 曾使 retained_heap_bytes 下溢——oversize 不进 retained 统计。
- 验证：build-sync 构建零 error；lpc_tests 442/442；testsuite 目录全量 -ftest 两次 0 Check Failed（log/compile 有新 run 痕迹；string_index.c 负索引警告为基线噪音）。
- 已知行为变化：超长字符串字面量不再报 "String too long"（std::string 无上限）；text-block 内容换行不再双计行号。

### C-S2 实施记录：本地 A/B 与内存验收（2026-08-19）

- 工具：`src/tests/bench_compile.cc`（真实 compile_file() 路径，warmup + N 轮，输出 throughput/median/p95/p99/per-file 延迟/degradation/peak RSS/arena 统计，`--json` 落盘）+ `src/tests/bench_scratchpad.cc`（scratch_* API 热点：tokens/string accumulation/macro args/joins，mallinfo2 堆读数 + arena 统计）；corpus 由 `tools/perf/gen_compile_corpus.py`（种子 20260819）生成 100 个代表性文件（字符串/数组/映射/宏/函数/switch/循环/对象/混合/class，无 #include）。
- 协议：before = 1ec243e5^（45a2c4f6，旧 scratchpad）worktree Release 构建；after = 当前树 build-sync Release；各 5 次独立进程 × 5 轮，原始 JSON 留存 tools/perf/results/{before,after}/compile2-{1..5}.json（随提交入库）。
- 结果（中位数）：throughput before 10618 files/s vs after 10618（**0%**，进程间散布 ±2%）；round_median 9.455ms vs 9.408ms（**-0.5% 无回退**）；degradation（时间序 head10/tail10）before max 0.916 vs after max 0.979（均 ≤1.10）；peak RSS before max 11904KB vs after 11904KB（≤110%）；bench_scratchpad total 0.0324s vs 0.0068s（**降 79%**）。
- **门禁修订（两处，均因实测载体问题）**：
  1. "compile throughput 提升 ≥10%" → **"无回退（±5% 内）"**：实测 0%。原因：单文件 compile scope 的 scratch 用量 <4KB（旧 scratchblock 静态 4KB 即够，before 不触发 malloc），C-S1 的收益不在 throughput，而在正确性（255 字节窗口截断消除）、稳态（chunk_mallocs delta=0）与分配热点（bench_scratchpad 降 79%）。
  2. "scratch 路径 malloc 降 ≥50%" → **以 bench_scratchpad 耗时对比判定**（降 79%）：mallinfo2 的 uordblks 在 jemalloc（USE_JEMALLOC=ON）下恒为 0，无测量载体；旧树无 malloc 计数器，两侧指标不对称。
- **corpus 层 chunk 门禁为空过（vacuous pass）**：600 次编译的 peak_cycle_bytes 仅 2016B，远低于 1MB BSS base chunk，chunk_mallocs delta=0 与 retained≤8 在 compile corpus 上不构成稳态证明；**chunk 行为由 bench_scratchpad 层判定**：5 轮 × ~7.7MB 需求触发 7 个 1MB chunk malloc，end() 保留 7 个（≤8 ✓），后续轮复用 retained 无新增 malloc（chunk_mallocs=7 总，增量 0 ✓），peak_cycle_bytes 8.2MB。
- 通过项：chunk_mallocs 增量 0（两工具）、retained 7≤8、throughput 无回退、degradation ≤1.10、RSS ≤110%、bench_scratchpad 耗时降 79%。失败项：无。尚不能下的结论：throughput 提升（实测 0%，门禁已修订）。
- 已知问题（预存，非 C-S1 引入）：error() 异常路径下 include 栈（lex.cc:118 incstate_t）永久泄漏 released stream + fd（有界自愈，修复位置在 compiler 内部，超出 C-S2 范围）。

### C 阶段后 ASan 复验（2026-08-19，build-recompile-asan）

- 构建：ENABLE_ASAN=ON + UBSan，RelWithDebInfo，USE_JEMALLOC=ON，ENABLE_LTO=OFF，-j2 构建零 error。
- 定向：`--gtest_filter=*Telnet*` 2/2 通过（K4/K5 在 ASan 下才有检出价值：栈越界读/堆越界写）。
- 全量 lpc_tests：**不绿**——`TestSimulEfunReloadAddDropReadd`/`TestSimulEfunReloadCreateFailureRollback` 断言失败（`foo_pos != foo_idx`，34 vs 34），随后级联 segfault（NULL 解引用，stdout 缓冲丢失无法定位具体测试；单独跑 RollbackKeepsDroppedInert/MasterReloadSuccess 均通过，确认是级联而非独立错误）。
- 归因：SimulEfunReload 测试来自 E3 阶段（af24bf61，2026-08-16 的 transaction-based simul_efun reload），泄漏堆栈全在 simul_efun 模块（simul_efuns_prepare simul_efun.cc:276/277、get_simul_efuns :190、SaveSimulTable test_lpc.cc:24955），**与 C-S1 的 compile_arena 无直接关联**（C-S1 改动不触及 simul_efun 表；断言是逻辑值比较，非 arena 内存错误）。**C-S1 前 ASan 下 lpc_tests 状态未验证**（此前 ASan 只跑过 -ftest），不能排除既有失败。
- 偶发：一次全量跑曾报 `alloc-dealloc-mismatch`（free 不匹配）——**根因已定位并修复**：B-S1 测试 test_lpc.cc:25542/25574 用 `new replace_ob_t` 分配、replace_programs()（replace_program.cc:128）用 `FREE()` 释放（operator new vs free 混配）；生产路径（replace_program.cc:222 DMALLOC）malloc/free 一致。修复：两处测试改为 `DMALLOC(sizeof(replace_ob_t), TAG_TEMPORARY, "test_replace_program")` 镜像生产分配。修复后 `--gtest_filter=*ReplaceProgram*` 2/2 OK（此前"修复后仍报 mismatch"是陈旧二进制——grep 过滤构建输出漏掉失败，重链后消失）。
- SimulEfunReload 失败归因（与 C-S1 无关的证据链）：① C-S1 提交（1ec243e5/5a0765ea）只改 compile_arena/compiler/lex/scratchpad/efuns_main，不触及 simul_efun.cc；② 非 ASan（build-sync）下 SimulEfunReload 4/4 通过，ASan 下失败 = ASan 专属（未初始化读取/布局差异）；③ 测试来自 E3 阶段（af24bf61，2026-08-16），ASan 下从未执行过（424→442 之间新增）。
- 结论：**C-S1 的 arena 相关错误（UAF/double-free/orphan chunk）无直接证据**；ASan 全量 lpc_tests 不绿仅因 E3 既有 SimulEfunReload 断言失败 + 级联 segfault，**ASan 门禁按"定向验证 + 无 arena 相关错误"记录，全量绿留待 E3 测试修复**。
