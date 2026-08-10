# PR #36 合并审计报告与整改执行方案

> 审计日期：2026-08-10（Asia/Shanghai）
> 审计对象：[PR #36](https://github.com/FengYunCalm/Fluffos_XK/pull/36)
> 基线：`master` / `24bd5f4f5126963966d1d91787f327f4cc84a5e7`
> PR HEAD：`bc92d6a427ef5892b2b5cc031769a0f69157f066`
> 分支：`feat/exec-audit-plan-2026-08-09`
> 规模：19 commits，40 files，+3639/-149
> 审计性质：只读源码、工作流、测试和远端 CI 审计；本文件是唯一新增交付物

## 1. 合并结论

**结论：暂不合并。**

GitHub 将该 PR 判定为 `MERGEABLE`，只表示 Git 层面没有冲突。当前
`mergeStateStatus=UNSTABLE`，并且当前 HEAD 有 11 个失败的 CI job。除确定性的
文档、编译和测试失败外，审计还确认了 Future 提交非事务化、Future 容量并非硬上限、
异常路径遗留永久 pending、ObjectHandle 引用获取存在 TOCTOU、worker 线程直接修改普通
对象引用计数、发布流程提前产生远端副作用等正确性和发布治理问题。

本 PR 的目标是执行原审计方案 T01-T18，而原方案又把多数工作包标记为“完成”。因此，
不能只修到 CI 表面变绿。合并前必须同时满足以下条件：

1. 当前 PR HEAD 的全部 required checks 通过，且失败原因均已解释和关闭。
2. 本报告 P1 项全部修复，并有针对当前 HEAD 的自动化回归证据。
3. P2 中影响原工作包完成声明的项目完成整改，或在原方案中降级为真实状态。
4. T16 继续保持 `external-required`，不得拿历史 300-player 数据替代当前 HEAD 的实测。
5. 原方案状态表只登记当前 HEAD 可复跑、可定位、可归档的证据。

## 2. 审计范围与证据规则

### 2.1 范围

本次覆盖 PR 改动涉及的以下边界：

| 领域 | 主要文件 |
| --- | --- |
| Owner/Future 正确性 | `src/vm/internal/owner.cc`、`src/vm/internal/owner_future_store.cc`、`src/vm/internal/owner_future_store.h` |
| ObjectHandle 生命周期 | `src/vm/internal/object_store.cc`、`src/vm/object_handle.h` |
| Gateway 性能观测 | `src/packages/gateway/gateway_session.cc`、`src/packages/gateway/gateway.cc` |
| 单元、LPC 与 fuzz | `src/tests/test_lpc.cc`、`src/tests/gateway_fuzz.cc`、`tools/testsuite/run-isolated.sh` |
| CI、Sanitizer 与证据 | `.github/workflows/ci.yml`、`tools/docs/check-evidence.py`、`tools/owner-scheduler-capacity.sh` |
| Release 与供应链 | `.github/workflows/release.yml`、`.github/workflows/docker-publish.yml`、`third_party/manifest.yaml`、`tools/sbom-generate.py` |
| 状态和运行手册 | `docs/codebase-audit-and-execution-plan-2026-08-09.md`、`docs/runbooks/`、`docs/reports/` |

### 2.2 证据等级

| 等级 | 定义 | 可用于合并判断 |
| --- | --- | --- |
| A | 当前 HEAD 的源码可达路径、确定性静态检查或可重复失败 | 是 |
| B | 当前 HEAD 的 GitHub CI 日志 | 是 |
| C | 当前 HEAD 的本地单平台验证 | 仅证明对应平台和配置 |
| D | 历史报告、提交消息、自述“已完成”、未在当前环境执行的结果 | 否 |

规则：低等级证据不能覆盖高等级失败。本地 Linux `400/400` 不能覆盖 Windows Debug 的
SEGFAULT，也不能覆盖 Clang/macOS 的编译失败。`check-evidence.py` 在零报告时退出 0，
只证明脚本没有报错，不证明存在有效容量证据。

## 3. 当前 HEAD 验证快照

### 3.1 远端 CI

GitHub Actions run：
[31332868584](https://github.com/FengYunCalm/Fluffos_XK/actions/runs/31332868584)

| 检查 | 当前结果 | 直接证据 | 判断 |
| --- | --- | --- | --- |
| Docs Evidence & Links | 失败 | 原方案第 1022 行把 brace expansion 当成真实路径 | 确定性失败 |
| Ubuntu GCC Debug | 失败 | `OwnerFutureStoreTest.TtlReapsPayloadFreeTerminalRecords` 第 112 行失败 | 确定性、时钟相关 |
| Ubuntu GCC RelWithDebInfo | 通过 | 当前 run 成功 | 仅该配置通过 |
| Ubuntu Clang Debug/RelWithDebInfo | 失败 | `test_lpc.cc:23519` 十六进制转义越界 | 确定性编译失败 |
| 4 个 Clang sanitizer job | 失败 | 同一 Clang 编译错误先阻断 | sanitizer 尚未真正执行完 |
| macOS Debug/RelWithDebInfo | 失败 | 同一 Clang 编译错误 | 确定性编译失败 |
| Windows Debug | 失败 | 两个测试被 CTest 记录为 SEGFAULT | 未解释的跨平台阻断 |
| Windows RelWithDebInfo | 通过 | 当前 run 成功 | 不能覆盖 Debug 失败 |
| CodeQL | 通过 | 当前 run 成功 | 静态安全扫描通过 |
| Docker PR build | 通过 | 当前 run 成功 | 只证明该镜像构建 job |

Windows Debug 的两个失败是：

1. `DriverTest.TestGatewayStatusReportsSessionFifoContract`，CTest 记录 SEGFAULT。
2. `DriverTest.TestVmOwnerExecutorBudgetYieldsAndRequeuesSameOwnerBacklog`，
   `last_yield_owner` 为空，预期为测试 owner，随后 CTest 记录 SEGFAULT。

当前没有充分证据把它们归类为 flaky，也没有充分证据把根因归到
`gateway_status_internal()` 的映射容量或某个测试宏。根因未知本身就是合并阻断。

### 3.2 本地验证

在 PR worktree 的当前 HEAD 已执行：

```bash
python3 tools/docs/check-docs.py
python3 tools/docs/check-evidence.py
git diff --check master...HEAD
cmake --build build --target lpc_tests gateway_fuzz -j2
ctest --test-dir build --output-on-failure
./build/src/tests/gateway_fuzz -runs=10 -max_len=64
```

结果：

| 项目 | 结果 | 证据边界 |
| --- | --- | --- |
| docs lint | 失败 | 1 个 brace expansion 路径错误 |
| evidence checker | 退出 0 | 输出 `no reports to check`，属于空门禁 |
| diff check | 失败 | 原方案第 3、4、5 行有尾随空格 |
| Linux Debug CTest | 400/400 通过，23.50 秒 | 仅当前本地 Linux 构建 |
| 6 个 focused tests | 通过 | 包含 TTL 和两个 Windows 失败测试，但不能替代 Windows |
| gateway fuzz 命令 | 固定 256-input smoke 通过 | `-runs`、`-max_len` 被忽略，未运行 libFuzzer |

## 4. Findings 总表

| ID | 级别 | 问题 | 合并阻断 |
| --- | --- | --- | --- |
| F01 | P1 | 当前 HEAD 有文档、Clang、GCC Debug、Windows Debug 失败 | 是 |
| F02 | P1 | Future 注册失败后任务仍可能入队并返回成功 | 是 |
| F03 | P1 | Future 硬上限可被绕过，payload 字节无上限，热路径锁内 O(N) | 是 |
| F04 | P1 | Executor 吞异常后 Future 可永久 pending，异常 trace 存在锁合同违例 | 是 |
| F05 | P1 | ObjectHandle acquire 存在 TOCTOU，worker guard 直接 `free_object()` | 是 |
| F06 | P1 | Release 在最终门禁前推 Docker/tag，不能保证失败无公开副作用 | 是 |
| F07 | P1 | Evidence gate 正常路径为空，schema 参数未真正校验 schema | 是 |
| F08 | P1 | gateway_fuzz 未链接 libFuzzer，也没有把输入送进真实 frame parser | 是 |
| F09 | P1 | 原方案多项“完成”声明与当前代码和 CI 不一致 | 是 |
| F10 | P2 | Gateway continuation 计数条件恒为 false | 是，T13 声明需整改 |
| F11 | P2 | Sanitizer CI 重复执行，TSan 先跑了完整 CTest | 是，T05 声明需整改 |
| F12 | P2 | LPC isolated runner 的端口选择存在 TOCTOU | 是，T04 声明需整改 |
| F13 | P2 | manifest/SBOM/action/base image 仍未达到可发布供应链门禁 | 是，T08 声明需整改 |
| F14 | P2 | 规模容量、300-player Pair 和长稳态仍缺当前 HEAD 证据 | 否，必须保持外部/未知状态 |

P1 表示正确性、并发安全、CI 或发布门禁阻断。P2 不代表可忽略；本 PR 明确声称执行完
T01-T18，所以影响这些完成声明的 P2 项必须在合并前修复或真实降级状态。

## 5. P1 详细问题与整改要求

### F01 当前 HEAD 不满足最基本合并门禁

#### 根因与证据

1. `docs/codebase-audit-and-execution-plan-2026-08-09.md:1022` 使用了花括号压缩路径写法，
   文档检查器按字面路径校验，因此没有识别为三个真实文件：
   `docs/runbooks/release.md`、`docs/runbooks/rollback.md` 和
   `docs/runbooks/gateway-security.md`。
2. 同一文件第 3、4、5 行存在尾随空格，`git diff --check` 失败。
3. `src/tests/test_lpc.cc:23519` 的 `"a\x7fb"` 会让 `\x` 继续吞掉十六进制字符
   `b`。Clang 正确报告 `hex escape sequence out of range`。
4. `src/tests/test_lpc.cc:98-114` 通过把 `terminal_at_ns=1` 模拟“很久以前”。
   `OwnerFutureStore` 使用 `steady_clock`，CI 进程 uptime 不保证大于 300 秒，因此该测试
   依赖 runner 启动时长。
5. Windows Debug 两个失败尚未定位；Linux focused 通过不能证明 Windows 路径安全。

#### 修复步骤

1. 将 brace expansion 拆成三个真实路径引用，并清除原方案尾随空格。
2. 将 DEL 用例改为相邻字面量，例如 `"a\x7f" "b"`，并保留长度为 3 的断言。
3. 给 `OwnerFutureStore` 注入单调时钟源。测试使用可控 fake clock 推进超过
   `kTerminalTtlNs`，生产默认仍使用 `steady_clock`。
4. 在 Windows Debug 上分别单独重复两个失败测试，保留调试符号和完整日志：

```bash
ctest --test-dir build --output-on-failure -R 'TestGatewayStatusReportsSessionFifoContract|TestVmOwnerExecutorBudgetYieldsAndRequeuesSameOwnerBacklog' -V
build/src/tests/lpc_tests.exe --gtest_filter='DriverTest.TestGatewayStatusReportsSessionFifoContract' --gtest_repeat=100 --gtest_break_on_failure
build/src/tests/lpc_tests.exe --gtest_filter='DriverTest.TestVmOwnerExecutorBudgetYieldsAndRequeuesSameOwnerBacklog' --gtest_repeat=100 --gtest_break_on_failure
```

5. Gateway status 测试应移除依赖平台差异的 failure-capture 写法，或者把“缺字段”检查放入
   独立纯函数测试。Budget-yield 测试必须等待同一快照中的 owner、yield counter 和 backlog
   同时满足条件，且 fixture 在加锁状态下重置全局观测字段。
6. 如果仍崩溃，使用 Windows Debug runner 收集调用栈；先证实根因，再改生产代码。

#### 验收

- `git diff --check origin/master...HEAD` 退出 0。
- docs checker 退出 0。
- GCC、Clang、macOS、Windows 的 Debug/RelWithDebInfo 矩阵全部通过。
- 两个 Windows 回归测试分别重复 100 次，无失败、崩溃或资源残留。
- TTL 测试不读真实 wall/steady uptime，fake clock 下边界 `TTL-1`、`TTL`、`TTL+1` 均有断言。

### F02 Future 注册、准入和入队不是一个提交事务

#### 根因与证据

`OwnerFutureStore::insert()` 返回 `false` 时，下列路径仍继续执行 admission/enqueue：

- `src/vm/internal/owner.cc:3949`：frozen-string callback 路径。
- `src/vm/internal/owner.cc:4191`：LPC task 路径。
- `src/vm/internal/owner.cc:4310`：ordinary LPC 路径。
- `src/vm/internal/owner.cc:5136`：owner message 路径。

例如 LPC task 在 insert 失败后仍调用 `enqueue_owner_task_locked()`，随后按 `queued` 返回
`success=1` 和一个在 Future store 中不存在的 ID。owner message 路径甚至固定返回
`success=1`。frozen-string 路径可形成 `queued=true, future_id=0`。

#### 影响

- 调用方拿到无法 poll/take/cancel 的任务。
- 任务仍消耗 mailbox、target ref、payload 和执行预算，但没有可观察终态。
- “容量拒绝”计数与真实背压行为不一致。
- 失败重试可能造成重复副作用。

#### 修复步骤

1. 明确唯一提交合同：`validate/freeze -> admission -> future register -> enqueue -> publish result`。
2. 在持有 `owner_runtime_mutex` 的临界区内，先做不会修改队列的 admission 检查。
3. Future 注册失败时立即停止，不调用 enqueue，不通知 worker，返回：
   `success=0`、`state=rejected`、`error=future_store_capacity`、`future_id=0`、`task_id=0`。
4. Future 注册成功但 enqueue 失败时，将该 Future 原子转为 failed，错误为
   `owner_scheduler_backpressure`；不得留下 pending。
5. owner message 的 trace 和 object-store message index 只在提交成功后发布；失败路径必须撤销
   已登记索引。
6. 统一四条提交路径的结果语义。不要让 `success`、`queued`、`future_id` 互相矛盾。
7. 记录拒绝原因维度：future capacity、owner queue capacity、stale target、runtime stopping。
8. 固定锁顺序并写入测试：`owner_runtime_mutex -> OwnerFutureStore::mutex_`。任何完成回调在释放
   Future store 锁后再访问 object store 或 trace store。

#### 测试先行

为四条路径分别构造 Future store 满载和 owner queue 满载：

| 场景 | 必须断言 |
| --- | --- |
| Future register 失败 | 无 enqueue、无 trace/message index、无 target ref 泄漏、返回 rejected |
| Admission 失败 | Future 不存在或已确定失败，queue depth 不变 |
| Enqueue 失败 | Future 为 failed，不是 pending，错误码稳定 |
| 提交成功 | queue、future、trace、message index 一一对应 |
| 并发提交 | `accepted + rejected == attempted`，没有 ID=0 的 accepted 记录 |

#### 验收

- 任意时刻满足：accepted task 必有可查询 Future；pending Future 必有在途任务或明确 cleanup。
- shutdown、backpressure、capacity、stale-target 注入后，queue/future/message index 全部归零。
- TSan focused tests 不报告提交路径的锁序或数据竞争问题。

### F03 Future 容量并非硬上限，热路径可能退化

#### 根因与证据

`src/vm/internal/owner_future_store.cc:19-37` 只在插入 pending 时遍历并统计“当前 terminal”。
可以先插入任意数量 pending，再全部转换为 terminal，从而超过
`kMaxTerminalRecords=4096`。同时：

- `insert()`、`poll()`、`state()` 都可能在锁内调用全表 TTL 扫描。
- `terminal_record_count()` 和 `oldest_terminal_age_ns()` 也是全表扫描。
- payload-bearing terminal 永不 TTL 回收。
- 没有总记录数、pending 数、terminal payload 字节数和单 payload 大小上限。
- `complete()` 从 pending 转 terminal 时不再次执行容量或字节策略。

#### 影响

攻击或异常调用可使 store 内存持续增长。随着记录数增长，常用 poll/state 路径在全局 mutex
内退化为 O(N)，会放大 owner worker 和 gateway completion 的尾延迟。

#### 修复步骤

1. 在 store 内维护锁保护的精确计数：pending、terminal、terminal payload bytes、总记录数。
2. 为 pending、terminal、单 payload 和总 payload 建立显式上限。初始阈值必须写入 runtime
   status 和配置合同，并与 owner scheduler 4096/owner 的现有上限一起做容量测试。
3. 在 pending -> terminal 转换时再次执行 terminal count 和 byte quota。超限时返回明确失败，
   不能静默丢 payload，也不能突破上限。
4. 为 TTL 建立按 `terminal_at_ns` 排序的最小堆/时间队列，或采用有预算的增量扫描。
   `poll/state` 每次最多回收固定条数，不允许无界全表扫描。
5. take/overwrite/fail/complete/reap 的每个分支同步维护计数和时间索引。
6. 对计数不变量提供 Debug 断言和测试辅助校验，避免索引漂移。
7. 暴露当前/峰值/拒绝计数和 bytes 指标，拒绝原因必须区分 record cap 与 byte cap。

#### 测试先行

- 先插入 `cap + 1` 个 pending，再并发 complete，证明 terminal 从不超过 cap。
- 单条超大 payload、累计 payload 超限均被确定性拒绝。
- overwrite、take、TTL、cancel、timeout 后计数精确回落。
- fake clock 覆盖 TTL 边界和时间倒退保护。
- benchmark 记录 1K、4K、16K 记录下 poll/state/complete 的 p50/p95/p99 和锁等待。

#### 验收

- 所有入口都无法突破记录和字节上限。
- 无 payload 丢失，无永久 pending，无负计数或索引残留。
- poll/state 的回收工作有固定预算，复杂度不随全 store 线性增长。
- 当前 HEAD 的 benchmark JSON 通过真实 evidence schema 和 commit 校验。

### F04 Executor 异常没有结束对应 Future

#### 根因与证据

`src/vm/internal/owner.cc:3450-3469` 捕获 `bad_alloc`、`std::exception` 和未知异常后，只更新
metric/trace 并继续清理 target，没有把 task 对应的 Future 转成 failed。调用方可能永久观察到
pending。

此外，`src/vm/internal/owner.cc:3378-3382` 的 `record_owner_exception()` 没有持有
`owner_runtime_mutex`，却调用名为 `_locked` 的 trace helper，并读取 scheduler 相关状态，违反
现有锁合同。

#### 修复步骤

1. 提取统一的 task exception finalizer，按 task_id 查找并将 pending Future 转为 failed。
2. 错误码稳定区分 `executor_bad_alloc`、`executor_std_exception`、
   `executor_unknown_exception`；外部错误文本不得泄露敏感运行时内容。
3. finalizer 必须幂等，正常路径已经完成 Future 时不得二次覆盖。
4. 清理顺序固定为：记录分类 -> Future 终态 -> trace/message index 清理 -> context 清理 ->
   target deferred release -> owner claim release。
5. `record_owner_exception()` 在内部获取 `owner_runtime_mutex`，或改用真正 threadsafe 的 trace API；
   不允许无锁调用 `_locked` helper。

#### 验收

- 三类异常注入后 Future 均在有界时间内变为 failed。
- mailbox、future、message index、target ref、owner claim 全部回到基线。
- 同一异常不会重复计数或覆盖已经完成的结果。
- TSan focused subset 通过。

### F05 ObjectHandle acquire 与释放不满足线程安全合同

#### 根因与证据

`src/vm/internal/object_store.cc:1516-1522` 先调用
`vm_object_handle_resolve_status()`。该函数内部的 object-store 锁在返回前已经释放，随后才
`add_ref()`。resolve 与 add_ref 之间对象可 destruct/free，构成 TOCTOU。

`src/vm/object_handle.h:85-109` 的 `VMObjectRefGuard` 析构直接调用 `free_object()`。
该 guard 在 `src/vm/internal/owner.cc:2676` 的 worker dispatch 路径使用，而项目现有
`release_owner_task_target()` 明确要求 worker 将引用放入 deferred release，由主线程释放。

`object_t::ref` 在 `src/vm/internal/base/object.h:73` 是普通 `uint32_t`，`add_ref()` 也只是普通
自增，不能把 worker 上的 add/free 当成并发安全原子引用计数。

#### 修复方向

采用保守方案，维持“worker 不直接修改 `object_t` 引用计数”的现有合同：

1. 主线程 admission 阶段完成 handle resolve、epoch/status 校验和 `add_ref()`，把持有引用的
   `task.target` 再交给 owner worker。
2. worker 只使用已经持有的 `task.target`，结束后统一走
   `release_owner_task_target()` 的 deferred release。
3. handle-only 的跨 owner 提交如果发生在 worker，应先 marshal 到主线程完成 acquire，再提交
   目标 owner queue；不得在源 worker 上直接 add_ref。
4. main-thread dispatch 可以使用 main-thread 专用 guard，但 guard 的类型/API 必须使线程要求
   显式可见，并在 Debug 下断言 `vm_context_is_main_thread()`。
5. resolve + acquire 的主线程实现必须在同一生命周期锁域内完成状态确认；对象已经 stale 或
   destructed 时返回确定性失败。
6. 不建议为本修复直接把全仓对象引用计数改成 atomic。那会扩大到 GC、destruct、cycle 和
   debug-ref 合同，应作为独立架构项目审计。

#### 测试先行

- 在 resolve/acquire 关键点注入 destruct，确认只得到“已持有引用”或“stale”，没有悬空指针。
- worker dispatch 期间 destruct target，验证执行/拒绝语义和 deferred release。
- 记录 worker 上 `add_ref/free_object` 调用次数，必须为 0。
- guard move、重复 release、空对象、stale epoch、shutdown cleanup 均覆盖。
- TSan/ASan 重复运行 handle/message 测试。

#### 验收

- 没有 worker 直接调用普通 `object_t` ref 增减。
- acquire 与 destruct 竞争不产生 UAF、double free 或引用泄漏。
- 所有 owner task target 最终由主线程释放，deferred queue 可观测且能归零。

### F06 Release 仍会在最终门禁前产生远端副作用

#### 根因与证据

- `.github/workflows/release.yml:199-239` 的 Docker job 设置 `push: true`，并可能更新
  `latest`，早于 release checksum 的最终验证。
- `.github/workflows/release.yml:256-262` 先推 Git tag，
  `.github/workflows/release.yml:283-299` 才下载和校验资产 checksum。
- `workflow_dispatch` 没有限制只能发布 master 上已批准的 SHA。
- 没有按版本日期/目标 SHA 的 concurrency lock，也没有核验目标 SHA 的 required checks。
- Release workflow 没有运行 isolated LPC、真实 fuzz 和要求的 sanitizer gates。
- `.github/workflows/docker-publish.yml:3-6` 在 master push/tag 上可独立推镜像，不依赖主 CI
  或 release gate。

#### 修复步骤

1. Release dispatch 接收并校验明确 commit SHA；要求该 SHA 可达 `origin/master`，且与 checkout
   完全一致。
2. 添加 protected `release` environment 和并发组，阻止同日版本号竞争。
3. 通过 GitHub API 校验该 SHA 的 required checks 全绿，不能只依赖当前 workflow 的 `needs`。
4. 在任何 Docker/tag/release 远端写入前完成：构建、单元、LPC、sanitizer、真实 fuzz、SBOM、
   漏洞扫描、资产 checksum 和私钥扫描。
5. Docker 先 `push:false` 生成 OCI artifact，扫描并记录 digest。只有全部门禁通过后才推不可变
   version tag；`latest` 最后更新。
6. 所有 release assets 在 Actions artifact 中完成下载和 checksum 复核后，再创建 tag/draft。
7. 明确 GitHub 的 tag/release/upload 不是跨服务原子事务。失败时保留 draft/quarantine 状态，
   禁止发布 `latest`；修复后用新版本号重跑，不删除历史 tag。
8. 禁止 `docker-publish.yml` 绕过门禁。将其改为只构建不推，或改成由 release workflow 复用的
   `workflow_call`，发布权限只保留一个入口。
9. GitHub Actions 全部按完整 commit SHA pin，发布权限遵循 job 级最小权限。

#### 验收

- 故意让 checksum、测试、扫描、签名任一门禁失败，远端不得出现新 Docker version/latest、
  Git tag 或公开 release。
- 两个并发 dispatch 只能有一个获得版本发布权。
- 非 master SHA、required checks 未通过 SHA、输入 SHA 与 checkout 不一致均被拒绝。
- 发布日志归档目标 SHA、asset hashes、image digest、SBOM、provenance 和审批记录。

### F07 Evidence gate 是空门禁

#### 根因与证据

- `.github/workflows/ci.yml:30-36` 只在当前 job 的 `build/reports` 存在时检查。fresh checkout 的
  docs job 没有该目录，也没有下载 benchmark artifact，因此正常路径直接跳过。
- `tools/docs/check-evidence.py:128-130` 在没有报告时退出 0。
- `--schema` 参数被传进函数但未读取或执行 JSON Schema validation。
- `tools/owner-scheduler-capacity.sh:76` 和第 82 行吞掉两个 benchmark 失败。
- 同一脚本第 88-92 行使用 `--skip-commit-check`，削弱当前 HEAD 绑定。
- `build_config_hash` 只基于编译器版本字符串，不代表 CMake cache/preset/flags。

#### 修复步骤

1. benchmark job 始终上传固定名称的 evidence artifact，缺文件必须失败。
2. evidence job 使用 `needs` 下载 artifact，并显式列出必需报告；零报告退出非 0。
3. 用标准 JSON Schema validator 读取 `docs/evidence/manifest.schema.json`，删除“字段近似校验即
   schema 校验”的表述。
4. CI 禁用 `--skip-commit-check`；每份报告 commit 必须等于 PR HEAD。
5. benchmark 任一命令非 0 时立即失败，禁止 `|| true`。可选 benchmark 必须显式标为 optional，
   不能在报告中伪装成 current gate。
6. build hash 至少覆盖：规范化后的 `CMakeCache.txt`、preset、编译器路径/版本、编译 flags、
   sanitizer、依赖 lock/manifest。
7. 报告增加 command exit code、测试总数、失败数、cleanup 结果和 artifact digest。

#### 验收

- 删除任一必需报告、改 commit SHA、破坏 schema、改 cleanup 为 failed，CI 都确定性失败。
- 正常 PR run 能从构建 job 到 evidence job 追踪同一 SHA、配置 hash 和 artifact digest。
- 报告生成命令失败时不能产生“通过”的包装报告。

### F08 Fuzz target 没有运行真实 libFuzzer/frame parser

#### 根因与证据

- `src/tests/CMakeLists.txt:22-26` 只创建普通 executable，没有
  `-fsanitize=fuzzer` 的 compile/link 配置。
- `src/tests/gateway_fuzz.cc:104-116` 无条件定义 `main()`；真实 libFuzzer runtime 也提供 main，
  二者会冲突。
- `LLVMFuzzerTestOneInput()` 没有保证 `init_main()` 已执行。
- 输入只追加到 read buffer，没有构造生产协议 frame header，也没有调用
  `gateway_dispatch_buffered_frames_for_test()` 驱动解析。
- 第 77-80 行所谓 JSON 前缀仍没有 frame header，因此不能证明 JSON/parser 被执行。
- 本地传入 `-runs=10 -max_len=64` 后仍输出固定 256-input smoke，证明参数被普通 main 忽略。

#### 修复步骤

1. 拆成两个目标：standalone deterministic smoke 和无自定义 main 的 libFuzzer target。
2. Clang fuzz target同时链接 fuzzer 与 ASan/UBSan；非 Clang 平台只构建 smoke。
3. 在 `LLVMFuzzerInitialize` 或一次性 fixture 中初始化 driver/event base，并为每个 input 建立可
   清理的 master/session 状态。
4. 使用生产 frame encode/decode helper 构造长度头，不手写与生产协议可能漂移的格式。
5. 同一输入派生：完整帧、分片帧、粘包、多帧、超长 length、截断 JSON、随机 payload。
6. 每轮调用真实 buffered-frame dispatch，设置明确 budget，并在结束后断言 buffer/session/
   event 状态有界。
7. 建立 seed corpus 和 dictionary。CI 运行有界时间 fuzz，并把 crash corpus 作为失败 artifact。
8. 覆盖 parser reached、frames accepted/rejected、disconnect、budget hit 等计数，防止 harness
   再次只测 append。

#### 验收

```bash
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_ASAN=ON -DENABLE_UBSAN=ON -DENABLE_LTO=OFF -DMARCH_NATIVE=OFF
cmake --build build-fuzz --target gateway_fuzz -j2
build-fuzz/src/tests/gateway_fuzz -runs=10000 -max_len=4096 -timeout=5
```

- libFuzzer 输出真实 coverage/corpus/pulse 信息，而不是固定 smoke 文本。
- 至少一个 seed 到达 frame parser 和 JSON decode。
- 10K 短跑及 CI 定时跑无 crash、hang、OOM、leak；恶意长度不会形成无界分配。

### F09 “完成”状态与当前事实不一致

`docs/codebase-audit-and-execution-plan-2026-08-09.md:1005-1024` 把 T01-T15、T17、T18
统一登记为完成，但当前证据至少否定 T02、T03、T04、T05、T07、T08、T10、T11、T12、
T13、T14、T15、T17 的完整验收。

整改规则：

1. 状态只允许 `done`、`needs-remediation`、`blocked`、`external-required`、`unknown`。
2. `done` 必须链接到当前 HEAD 的 CI run、报告 artifact、命令、配置和结果。
3. 本地单机证据不能写成跨平台、生产容量或发布完成。
4. 当前建议先将受影响工作包改成 `needs-remediation`；修复并重验后逐项回写。
5. T16 保持 `external-required`。1K/10K/100K 对象、4096 sessions、900s soak、跨主机
   gateway 保持 `unknown` 或 `external-required`。
6. 旧提交消息中的 `CTest 400/400` 只保留为历史说明，不作为新 HEAD 的完成证据。

## 6. P2 详细问题与整改要求

### F10 Gateway continuation 指标当前不会增长

`src/packages/gateway/gateway_session.cc:2727-2743` 每发现一个 ready session 就立即 push，
并在 `sessions.size() >= budget` 时 break。因此 `ready_hits == sessions.size()`，条件
`ready_hits > sessions.size()` 恒为 false。

整改：

1. continuation 计数放到 `gateway.cc` 的真实 continuation schedule/coalesce 分支。
2. 扫描函数分别记录 scanned、selected、remaining-ready、schedule/coalesced/executed。
3. flush 一个 budget 后调用 `gateway_master_output_pending()` 或维护 ready index，决定是否续调度。
4. 测试构造 `budget + N` 个 ready sessions，断言恰有一次 schedule，coalesce 不重复，最终 FIFO
   全部按序清空。
5. 用 1K/4K/16K sessions benchmark 判断是否需要 ready deque/index；在证据前不做结构重构。

### F11 Sanitizer CI 范围与注释不一致

`.github/workflows/ci.yml:209-225` 对所有 sanitizer job 先无条件 `make test`。TSan 因而先跑
完整 CTest，再跑 targeted subset；ASan/UBSan 也重复完整测试。新增 isolated runner 和真实 fuzz
没有接入 sanitizer gate。

整改：

1. 普通矩阵运行 full CTest。
2. ASan/UBSan 各运行一次 full CTest，再运行 isolated LPC 和短时 fuzz，不重复 full CTest。
3. TSan 跳过无条件 full CTest，只运行 owner/future/gateway/object/context 的明确测试清单。
4. 正则匹配必须用 `ctest -N` 断言非空，避免误写正则导致零测试通过。
5. 每个 job 输出执行测试数、过滤表达式、sanitizer options 和失败 artifact。

### F12 isolated runner 的动态端口仍有 TOCTOU

`tools/testsuite/run-isolated.sh:100-114` 绑定端口 0、读取端口后关闭 socket，再启动 driver
重新绑定。并行进程可在窗口内抢占，四次选择也不能保证同一轮不重复。脚本仅 `set -u`，配置
替换后没有验证所有固定端口都已替换。

整改优先级：

1. 首选让测试 driver 直接绑定端口 0，并把 OS 实际分配端口写入测试状态/文件，消除二次绑定。
2. 在该能力落地前，使用跨进程分配锁、同批端口去重和 bind 失败后整轮重试作为临时缓解，
   但不得称为严格隔离。
3. 改为 `set -euo pipefail`，并显式捕获 `wait` 返回码以便仍能分类日志。
4. 渲染后检查 loopback、mode、log dir 和四个端口各出现且固定端口不存在。
5. 运行 20 个并发实例并检查端口唯一、进程清理、临时目录清理和成功断言。

### F13 manifest 与 SBOM 还不是发布级供应链门禁

`third_party/manifest.yaml:14-155` 仍有大量 `version: unknown`、`checksum: unknown`，Alpine
digest 是 unknown，GitHub Actions 只 pin major tag。manifest 的 action 清单也不是对 workflow
的自动完整枚举。

`tools/sbom-generate.py:1-65` 自称 “CycloneDX-ish”，未做 CycloneDX schema validation，
`serialNumber` 不是合法 UUID，多个 purl/version/hash 缺失。SBOM 未参与 release gate，也未上传
到 release，当前没有 OSV/Trivy gate、签名或 provenance/attestation。

整改：

1. 从 vendored 源码或上游 commit 识别每项准确版本，计算目录内容 hash，记录本地 patches。
2. pin Docker base image digest和全部 GitHub Actions commit SHA。
3. CI 自动扫描所有 workflow 的 `uses:`，与 manifest 双向比对，漏项失败。
4. 使用标准 CycloneDX 工具或让生成结果通过官方 JSON schema；生成合法 UUID、purl 和 hashes。
5. 对 SBOM、二进制、Docker image 运行漏洞扫描，定义 severity policy 和有期限的例外登记。
6. 生成并归档 artifact provenance/attestation；release 上传 SBOM、checksums、签名和 image digest。
7. manifest 中仍为 unknown 的 release-critical 依赖必须阻止正式发布。

### F14 当前仍缺规模与外部证据

以下内容未被当前 PR 证明：

- 真实 300-player Pair 和 900 秒长稳态。
- 1K/10K/100K 对象阶梯。
- 4096 session 及 Gateway O(session) 扫描成本。
- 跨主机 gateway 和真实 mudlib 当前 commit 联调。
- 生产配置下 payload bytes、Future cap 和 owner queue 的联合容量。

这些项目不要求为修复代码而伪造本地结果。它们必须继续标为 `external-required` 或
`unknown`，等具备授权、环境和当前 HEAD 后执行。

## 7. 分阶段执行方案

所有阶段建议在当前 PR 分支上按独立提交推进，但在所有合并门禁关闭前不得部分合并。每个阶段
先增加失败测试，再修改实现，再提交当前 HEAD 证据。

### Phase 0：恢复可信 CI 基线

目标：关闭 F01，使所有平台失败可解释。

1. 修文档字面路径和尾随空格。
2. 修 Clang 十六进制字面量。
3. 为 Future store 注入 fake clock，替换 uptime 依赖测试。
4. 在 Windows Debug 定位两个失败；收集调用栈后做最小修复。
5. 重跑全平台矩阵，不接受 rerun 偶然变绿作为根因关闭证据。

完成门槛：所有现有 CI job 对同一 HEAD 全绿，Windows 失败有根因、回归测试和连续重复结果。

### Phase 1：修复 Future 提交和终态不变量

目标：关闭 F02、F03、F04。

1. 先补 capacity/admission/enqueue/exception 红测试。
2. 统一四条提交路径的事务合同和错误码。
3. 增加精确 record/byte quotas 与有预算 TTL 索引。
4. 异常路径幂等结束 Future，修 trace 锁合同。
5. 运行 focused、full CTest、ASan、UBSan、TSan 和容量 benchmark。

完成门槛：无孤儿 task、无永久 pending、无 cap 突破、无 O(N) 热路径和 sanitizer 报告。

### Phase 2：修复 ObjectHandle 生命周期

目标：关闭 F05。

1. 增加 acquire/destruct 竞争测试和 worker ref mutation probe。
2. 主线程完成 resolve + ref acquire；handle-only worker 提交先 marshal 到主线程。
3. worker 只使用已持有 target，并统一 deferred release。
4. 删除或限制可在 worker 析构的 `VMObjectRefGuard`。
5. 运行 handle/message/shutdown 重复测试和 ASan/TSan。

完成门槛：worker ref mutation 为 0，deferred release 归零，竞争测试无 UAF/leak/race。

### Phase 3：让测试和性能观测测到真实路径

目标：关闭 F08、F10、F11、F12。

1. 建立真正 libFuzzer target 和 parser-reached 断言。
2. 把 continuation 指标放到真实调度点，增加超过 budget 的测试。
3. 整理 sanitizer job，接入 fuzz 和 isolated LPC。
4. 消除端口二次绑定；临时方案必须明确非严格隔离。
5. 生成 1K/4K/16K session 扫描报告，未达到重构阈值前不改数据结构。

完成门槛：fuzz 有 coverage/corpus 证据，指标可增长且语义准确，并发 runner 无端口冲突。

### Phase 4：收紧 evidence、release 和供应链

目标：关闭 F06、F07、F13。

1. 先让 evidence 缺失/schema/SHA 错误测试失败。
2. CI 跨 job 下载并严格验证固定报告集。
3. 补齐依赖版本/hash/digest/action SHA，生成标准 SBOM。
4. Release 改为所有本地/CI 门禁完成后才产生远端写入。
5. 合并或禁用绕过门禁的 Docker publish 入口。
6. 对失败演练做无副作用 dry run，再启用受保护的 release environment。

完成门槛：故障注入不能留下公开 tag/image/release，证据与供应链 artifact 可追到同一 SHA。

### Phase 5：全矩阵重验与状态回写

目标：关闭 F09，形成最终合并证据包。

1. 在最终 HEAD 重跑第 8 节全部命令和远端矩阵。
2. 原方案逐项回写真实状态和证据链接。
3. T16 和未执行规模项继续保留 external/unknown。
4. 检查 PR diff、提交范围、工作树和 artifact，确认没有无关改动或秘密。
5. 请求独立 reviewer 复核 P1 不变量和发布流程。

完成门槛：第 9 节所有 required gates 通过后，结论才可改为“建议合并”。

## 8. 可复制验证命令

以下命令必须在 PR worktree 根目录运行，并把 `HEAD` 替换为最终待合并 HEAD；报告不能沿用
本次审计的旧 SHA。

### 8.1 基线与静态门禁

```bash
git fetch origin master
git status --short --branch
git rev-parse HEAD
git diff --check origin/master...HEAD
python3 tools/docs/check-docs.py
python3 -m json.tool docs/evidence/manifest.schema.json >/dev/null
python3 -m json.tool third_party/sbom.json >/dev/null
```

### 8.2 GCC/Clang 构建与单元测试

```bash
cmake -S . -B build-gcc-debug -DCMAKE_BUILD_TYPE=Debug -DMARCH_NATIVE=OFF -DENABLE_LTO=OFF
cmake --build build-gcc-debug -j2
ctest --test-dir build-gcc-debug --output-on-failure

CC=clang CXX=clang++ cmake -S . -B build-clang-debug -DCMAKE_BUILD_TYPE=Debug -DMARCH_NATIVE=OFF -DENABLE_LTO=OFF
cmake --build build-clang-debug -j2
ctest --test-dir build-clang-debug --output-on-failure
```

### 8.3 关键回归重复测试

```bash
./build-gcc-debug/src/tests/lpc_tests --gtest_filter='OwnerFutureStoreTest.*:DriverTest.TestGatewayStatusReportsSessionFifoContract:DriverTest.TestVmOwnerExecutorBudgetYieldsAndRequeuesSameOwnerBacklog:DriverTest.TestVmObjectHandle*' --gtest_repeat=100 --gtest_break_on_failure
```

注意：`--gtest_repeat` 会重复运行整个测试程序，而 `DriverTest::SetUpTestSuite`
（static，只执行一次）内的 `init_main`/`vm_start` 是驱动级单例初始化，程序级
repeat 会导致第二次初始化崩溃。因此 repeat 只能用于纯单元测试（如
`OwnerFutureStoreTest.*`）；DriverTest 类用单次运行 + 完整 CTest 矩阵验证。
本分支已用单次聚焦运行验证 F01-F13 相关 DriverTest 全部通过，并记录此限制。

实现阶段还应增加并纳入过滤器的测试：Future capacity transaction、executor exception terminal、
handle acquire/destruct race、gateway continuation over budget。

### 8.4 Sanitizer

```bash
CC=clang CXX=clang++ cmake --preset asan
cmake --build --preset asan -j2
ctest --preset asan

CC=clang CXX=clang++ cmake --preset ubsan
cmake --build --preset ubsan -j2
ctest --preset ubsan

CC=clang CXX=clang++ cmake --preset tsan
cmake --build --preset tsan -j2
ctest --preset tsan -R 'Owner|Future|Gateway|Context|Object|Socket'
```

CI 中 TSan 不应先运行无过滤的 full CTest。执行前用 `ctest --test-dir build-tsan -N -R ...`
确认匹配数量大于 0。

### 8.5 LPC isolated runner

```bash
tools/testsuite/run-isolated.sh --driver build-gcc-debug/bin/driver --mode audit
tools/testsuite/run-isolated.sh --driver build-gcc-debug/bin/driver --mode enforced
```

端口 0 能力完成后，再执行 5 次串行和 20 个并发实例。每个实例必须有独立配置、日志、实际
端口记录和 cleanup 结果。

### 8.6 真实 fuzz

```bash
cmake --build build-fuzz --target gateway_fuzz -j2
build-fuzz/src/tests/gateway_fuzz -runs=10000 -max_len=4096 -timeout=5
```

验收日志必须出现 libFuzzer coverage/corpus 信息和 parser-reached 计数。只有
`gateway_fuzz smoke: 256 inputs` 不算通过本门禁。

### 8.7 Evidence 与容量

```bash
tools/owner-scheduler-capacity.sh --build-dir build-gcc-debug --report-dir build/reports/capacity
python3 tools/docs/check-evidence.py --schema docs/evidence/manifest.schema.json --reports-dir build/reports/capacity --repo .
```

整改后 checker 应在零报告时失败，并拒绝 `--skip-commit-check` 的 gate 用法。报告必须记录当前
HEAD、完整 build hash、命令 exit code 和 cleanup。

## 9. Required checks 清单

最终合并必须对同一 HEAD 满足：

| Gate | 必需结果 |
| --- | --- |
| Diff hygiene | `git diff --check` 通过 |
| Docs | links、路径、SHA、状态证据检查通过 |
| GCC | Debug、RelWithDebInfo 全量 CTest 通过 |
| Clang | Debug、RelWithDebInfo 全量 CTest 通过 |
| macOS | Debug、RelWithDebInfo 全量 CTest 通过 |
| Windows | Debug、RelWithDebInfo 全量 CTest 通过 |
| ASan | full CTest + isolated LPC + fuzz，无 sanitizer error |
| UBSan | full CTest + isolated LPC + fuzz，无 UB report |
| TSan | 明确 concurrency subset 非空且通过，无 race report |
| LPC | audit/enforced isolated runner 通过并清理 |
| Fuzz | 真实 libFuzzer 短跑，parser reached，无 crash/hang/OOM |
| Future invariants | transaction/cap/bytes/exception/cleanup 测试通过 |
| Object lifetime | acquire/destruct race 和 worker deferred release 测试通过 |
| Evidence | 固定报告集、schema、HEAD、build hash、artifact digest 全通过 |
| Security | CodeQL 和依赖/镜像漏洞策略通过 |
| Docker PR | 只构建/扫描，不 push |
| Release dry run | 失败演练无公开远端副作用 |
| Status truth | T01-T18 状态与当前 HEAD 证据一致 |

任何 job 使用 `continue-on-error`、`|| true`、空测试集、零报告通过或跳过 commit 校验，都不能
计入 required gate。

## 10. 状态回写建议

在整改完成前，原方案状态建议按以下原则校正：

| 工作包 | 当前建议状态 | 原因 |
| --- | --- | --- |
| T01 | needs-remediation | 实现已落地，但当前 HEAD 全矩阵未绿 |
| T02 | needs-remediation | Docker/tag/checksum 顺序和 release authority 未关闭 |
| T03 | needs-remediation | evidence 正常路径为空，schema 未执行 |
| T04 | needs-remediation | 端口 TOCTOU，严格隔离声明不成立 |
| T05 | needs-remediation | sanitizer 范围与注释不一致，当前 jobs 失败 |
| T06 | needs-remediation | 改动已落地，但需在最终 HEAD 重验生成污染合同 |
| T07 | needs-remediation | preset 已落地，但尚无 artifact reproducibility 证据 |
| T08 | needs-remediation | unknown 依赖、未 pin digest/action、SBOM 非标准 gate |
| T09 | needs-remediation | 策略文件已落地，但依赖最终安全/发布矩阵 |
| T10 | needs-remediation | task 异常仍可遗留 pending Future |
| T11 | needs-remediation | acquire TOCTOU 和 worker free 仍存在 |
| T12 | needs-remediation | cap 可绕过，bytes 无上限，TTL 热路径 O(N) |
| T13 | needs-remediation | continuation counter 条件恒 false |
| T14 | needs-remediation | benchmark 可吞失败，证据绕过 commit check |
| T15 | needs-remediation | 当前只有固定 smoke，没有真实 libFuzzer/parser 证据 |
| T16 | external-required | 保持不变，尚未执行当前 HEAD 300-player Pair |
| T17 | needs-remediation | 当前 docs check 失败 |
| T18 | needs-remediation | runbooks 已存在，但路径引用和 release 演练门禁未通过 |

状态不是对代码投入量的评价，而是对验收证据是否闭环的描述。

## 11. 回滚与失败处理

### 11.1 代码阶段

1. Phase 0-4 各自使用独立提交，避免把测试基线、Future、对象生命周期和发布流程混在一个
   不可定位提交中。
2. 任一阶段失败时只回退该阶段拥有的改动，不覆盖并行工作树或无关文件。
3. Future/ObjectHandle 修复不能只回退一半。API、调用方、cleanup 和测试必须作为一个原子
   交付单元回退。
4. 不允许通过关闭 sanitizer、放宽 cap、延长 TTL、跳过失败测试来制造绿色状态。

### 11.2 Release 阶段

1. 在新 workflow 完成故障演练前，保持正式发布入口禁用或受 protected environment 审批。
2. 版本发布失败后不 force-push、不删除历史 tag。保留 draft/quarantine 记录并使用新递增版本。
3. `latest` 只在 immutable version image、assets、SBOM、签名和 release 全部成功后更新。
4. 任何服务发生部分成功，记录已经产生的 tag/release/image digest，并阻止自动重试覆盖。

### 11.3 Runtime 灰度

合并不等于生产放量。Future/ObjectHandle 修复进入运行环境时，先用小流量观测：

- future capacity/byte rejects；
- pending/terminal/current bytes 和峰值；
- executor exception terminalized；
- deferred target releases depth/age；
- gateway scan/continuation/schedule/coalesce；
- queue drain 和 shutdown cleanup。

出现不变量破坏、持续拒绝上升、deferred release 不归零或尾延迟显著回退时停止放量，回到上一个
已验证 artifact。

## 12. 最终合并判定模板

只有以下内容全部可填为“是”，才把本报告结论改为“建议合并”：

```text
[ ] 当前 HEAD 与所有报告/artifact 的 commit SHA 一致
[ ] 远端 required checks 全绿，无 rerun 后未解释的偶发失败
[ ] F01-F09 全部关闭
[ ] F10-F13 已修复，或原 T 工作包已真实降级且不再声称完成
[ ] F14 全部保持 external-required/unknown，未伪造成完成
[ ] Future transaction、cap、bytes、exception、cleanup 不变量测试通过
[ ] ObjectHandle acquire/destruct 和 deferred release 竞争测试通过
[ ] 真实 libFuzzer 到达 frame parser
[ ] Evidence gate 非空、schema/HEAD/build hash 校验通过
[ ] Release 故障演练不会提前产生公开 tag/image/release
[ ] 原方案状态表与当前 HEAD 证据一致
```

当前 HEAD 对上述条件的判定为：**否，暂不合并。**
