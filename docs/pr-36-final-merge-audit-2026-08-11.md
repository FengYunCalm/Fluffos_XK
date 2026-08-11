# PR #36 最终轮合并审计报告

> 审计日期：2026-08-11（Asia/Shanghai）
> 审计对象：[FengYunCalm/FluffOS_XK PR #36](https://github.com/FengYunCalm/FluffOS_XK/pull/36)
> Base：`24bd5f4f5126963966d1d91787f327f4cc84a5e7`
> 已审实现提交：`04088aa90fd6c12dfb597b9dccbce7585a87a93f`、`3fa46cf46106e83aeb30fb4a117496823c7df6a3`、`e588262ba71e4922f24d07852299f5a225cfd9e6`、`f45778ff7f2894fbdd0291d1b62d7a9b73a943cb`
> 上一版审计文档提交：`87732d7c31cfa814f021140f72488f41fbc01ec7`
> 分支：`feat/exec-audit-plan-2026-08-09`

## 1. 当前结论

本轮兼容性修复与 Evidence Gate artifact 修复均已完成。代码修复提交
`f45778ff7f2894fbdd0291d1b62d7a9b73a943cb` 的完整 required checks 已成功，且当时 PR
merge state 为 `CLEAN`/`MERGEABLE`。本报告闭环提交会形成新的 PR HEAD，必须对新 HEAD
重跑完整 required checks；重跑成功且保持无冲突后，结论为 **可合并**。审计开始时旧 HEAD
`8dcd2e0d` 的 Docker/Evidence Gate 失败，以及中间 HEAD `e588262b` 的 Evidence Gate
失败，均不代表当前 HEAD。

合并结论只允许按以下规则转换：

- 最终 PR HEAD 与本报告审计的实现/文档提交一致；
- Workflow Lint、Docs、Evidence、GCC/Clang、ASan/UBSan/TSan、macOS、Windows、
  libFuzzer、CodeQL、Docker 全部成功；
- Future、ObjectHandle、release artifact/digest 三组人工合同复核无回退；
- 工作树没有未提交任务改动，PR 可合并状态无冲突。

任一 required check 后续回退为失败、取消或缺失，或 merge state 变为冲突，必须回到 §7
处理，不允许跳过门禁。

## 2. 本轮新增发现与修复

### F14：required-check 分页会破坏 release 裁决

旧实现使用 `gh api --paginate` 将多页对象直接写入一个文件，而解析器只接受单个 JSON
对象。当同一提交累积多页 check-runs 或多次重跑记录时，校验可能无法正确选择最新结果。

已修复：

- workflow 使用 `--paginate --slurp` 与 `per_page=100`；
- `common.sh` 同时接受单页对象和分页数组，跨页按 `started_at/created_at + id` 选择最新记录；
- `release-fault-injection.sh` 增加“旧页失败、新页成功”和“新重跑仍进行中”合同；
- `check-workflows.py --self-test` 强制分页查询不可被删回。

### F15：Future 配额拒绝返回了错误的目标状态

Future 配额拒绝本身会正确生成可查询的 failed tombstone，但三个完成入口曾把返回的
`target_status` 无条件写成 `current`。这会让无效或过期 handle 的诊断字段失真。

已修复：所有完成路径都先释放 Future store 锁，再调用同一 `target_status()` 解析真实状态；
`PayloadByteCapsRejectDeterministically` 增加 invalid handle 回归。

### F16：隔离 runner 依赖 GNU `timeout`/`stdbuf`，macOS 会直接退出 127

旧 runner 在没有 GNU `timeout` 的 macOS 环境调用 `timeout`，并依赖 `stdbuf -oL` 获取实时
日志，导致 Debug/RelWithDebInfo job 在真正运行 driver 前失败。

已修复：按 `timeout`、`gtimeout`、仓库内 `portable-timeout.py` 顺序选择监督器；移除
`stdbuf`，依赖 driver 自身逐条 flush；加入最小 PATH 合同，覆盖 timeout/stdbuf 均不存在的
环境。测试只断言运行前后 sandbox 集合不新增，不会误删保留的审计目录。

### F17：无 `flock` fallback lock 的释放状态不闭合

旧 runner 在 fallback `mkdir` lock 释放后仍保留 `LOCK_FD=mkdir`，退出 trap 可能再次进入释放
路径，且释放逻辑通过外部 `head` 读取 owner，增加最小 PATH 和重复清理场景的不确定性。

已修复：用 shell 内建 `read` 读取 owner PID，释放后清空 `LOCK_FD`，并保留 owner-PID 校验；
可移植性合同验证 lockdir 与 sandbox 均无新增残留。

### F18：eval-limit 状态和 POSIX timer 原先跨线程共享

旧实现使用全局 `outoftime` 与单一 `timer_t`。owner worker 首次 `set_eval()` 会覆盖主线程
timer，信号也可能写入错误执行线程，造成误终止或数据竞争。

已修复：`outoftime` 改为 VM thread-local `volatile sig_atomic_t`；Linux timer 按线程惰性
创建，使用 `SIGEV_THREAD_ID` 投递到目标线程，并在线程退出时删除；增加三项线程隔离/到期
信号合同。

### F19：`mudlib_stats` 共享计数更新存在丢增量和衰减覆盖

owner worker 与 main thread 可同时更新 `moves`、`heart_beats`、`size_array`、`errors`、
`objects`；普通 `+=` 和衰减写回会丢失并发增量。

已修复：保持 `mudlib_stats_t` ABI 字段布局，使用 C++17 可用的 `__atomic_*` relaxed 操作；
衰减改用 CAS 循环，快照/恢复使用原子读写；增加 8 线程数组计数合同。

### F20：owner message worker LPC 会修改主线程对象 reset 状态

`dispatch_owner_message_in_current_context()` 执行 `safe_apply()` 前没有设置
`controlled_lpc_active`，`apply_low_impl()` 因而写入 `object_t::time_of_ref` 并清除
`O_RESET_STATE`。TSan 记录为 `apply.cc:218` owner/main 并发读写。

已修复：owner.cc 增加异常安全的 `OwnerControlledLpcScope`，覆盖 owner message 的 LPC 执行
范围并恢复原状态；target-message 合同固定 `time_of_ref` 与 flags，证明 worker 调用不触发
主线程 reset 维护。

## 3. 关键代码合同复核

### 3.1 ObjectHandle 与 owner worker

- main-thread admission 在同一 object-store 锁域内完成 resolve + add_ref，关闭裸指针
  resolve 后再引用的时间窗口；
- worker 只消费提交时已持有的引用，释放统一回到 main deferred queue；
- worker resolver 只读取 owner-local 生命周期记录和指针索引，不读取可变 `object_t` 生命周期
  字段，也不回退到 compatibility/global bridge；
- compatibility-only 对象仍可被 generic resolver 观察，worker-local resolver 保守拒绝；
- ref-mutation 探针先执行一次非零自校准，再证明 owner worker 负载期间 off-main 变更为 0。

这复用了项目 canonical owner-runtime 模式：main admission、frozen/held input、owner-local current
check、单一终态消费者和 main-thread release。未引入请求时等待 Future、跨玩家缓存或 global
fallback 伪快路径。

### 3.2 OwnerFutureStore

- pending admission 预留终态槽位，成功 admission 不会因完成时容量不足变成 unknown；
- payload-free terminal 可按 TTL 回收，带 payload 记录只由 take/cap 管理；
- 单条/总 payload byte cap 使用饱和与无溢出比较；
- frozen mapping 的 key/value、array/mapping 结构、counted string 长度均计量；
- all-terminal 与 reapable-terminal 使用分离时间索引；
- quota rejection 保留失败 tombstone，并返回真实 target status。

### 3.3 统计、字符串与调试分配器

- owner worker 可触达的 mapping/string 统计改为 relaxed atomic；
- `svalue_strlen_size` 改为 VM thread-local；
- 字符串宏保证 length 表达式只求值一次，并保留 `UINT_MAX + 1` 的旧有无符号环绕语义；
- counted string 缩短使用有符号逻辑 delta，避免无符号下溢造成超大增量；
- debug allocator 的表/计数更新有统一互斥，状态输出读取一致快照。

### 3.4 Gateway fuzz fixture

- 每个场景独立建立并销毁 master/bufferevent pair；
- master 被移除后只按 fd 重新解析，不复用悬空指针；
- peer endpoint 由 fixture 明确释放；
- Windows 使用 `winsock2.h` 与 `_chdir`；
- CI 使用绝对 corpus 与 artifact 路径，避免 Driver 初始化切换工作目录后路径漂移。

### 3.5 Release 输入与远端写入边界

- binary artifact 与 OCI 验证 artifact 分开下载；
- release bundle 内的 manifest/SBOM 必须与 target checkout 精确一致；
- Linux/Windows 二进制 checksum、provenance target SHA、archive digest 与 scan report 专用字段
  必须一致；
- tag、draft、image promotion 只在所有只读门禁后执行，且写权限只存在于 protected jobs；
- 镜像推广消费被扫描的同一 archive，不允许第二次构建替换输入。

## 4. 本地验证证据

| 范围 | 结果 |
| --- | --- |
| GCC Debug CTest | 424/424 |
| GCC ASan Debug | 424/424 |
| GCC UBSan Debug | 424/424 |
| GCC TSan focused subset | 360/360；WSL 下构建和运行均使用 `setarch x86_64 -R` |
| eval-limit、owner-message、mudlib_stats 定向合同 | Debug 5/5；TSan 5/5 |
| runner portability 合同 | 2/2；最小 PATH 下无 GNU `timeout`/`stdbuf` 通过，lock/sandbox 无新增残留 |
| TSan LPC isolated runner | LPC 断言通过；四个实际 loopback 端口唯一；Driver 退出 0；保留日志无 TSan 报告 |
| ASan LPC isolated runner | LPC 断言通过；四个实际 loopback 端口唯一；Driver 退出 0；保留日志无 ASan/LSan 报告 |
| UBSan LPC isolated runner | LPC 断言通过；四个实际 loopback 端口唯一；Driver 退出 0；保留日志无 UBSan 报告 |
| 端口隔离压力 | 5 次串行 + 20 次并发通过，无 Driver/sandbox/lockdir 残留 |
| runtime/bench smoke | `lpc-modern-runtime-stress.sh smoke` 通过；owner-local fast path 8192、global fallback 0 |
| 构建卫生 | 连续两次全目标构建，第二次无 C++ 编译/链接 |
| workflow/release | check-workflows self-test、action pins self-test、release fault injection、actionlint 1.7.12 通过 |
| docs/evidence/SBOM | check-docs、evidence negative suite、CycloneDX validate 通过 |

| 诊断日志 | 本地保留的 TSan、ASan、UBSan isolated 日志均已检查；目录为运行时临时证据，不纳入仓库 |

上述是实现提交 `3fa46cf46106e83aeb30fb4a117496823c7df6a3` 上的本地证据，不等价于最终 PR HEAD 的 Clang/macOS/Windows/CodeQL/Docker
结果，也不等价于真实 registry 演练。

## 5. 性能与架构结论

- owner-local ObjectHandle 诊断路径不再访问 global compatibility index；smoke 中 8192 次解析
  全部走 owner-local fast path，global fallback 为 0；
- same-owner 串行、different-owner 并行、future/queue cleanup 等既有容量 envelope 未被本轮
  改动破坏；
- T13 的 1K/4K/16K session 扫描阶梯仍为 `needs-remediation`，因此本 PR 不声称 ready-index
  重构已经有数据依据；
- 1K/10K/100K object、4096 session、300-player 900s Pair 继续保持 unknown/external-required，
  不用小规模 smoke 外推生产容量。

## 6. 合并门禁

- [ ] 最终 PR HEAD 已推送且本地/远端 SHA 一致。
- [ ] Workflow Lint、Docs Evidence、Evidence Gate 全绿。
- [ ] GCC/Clang Debug 与 RelWithDebInfo 全绿。
- [ ] ASan Debug/RelWithDebInfo、UBSan、TSan focused 全绿。
- [ ] macOS Debug/RelWithDebInfo、Windows Debug/RelWithDebInfo 全绿。
- [ ] libFuzzer、CodeQL、Docker build 全绿。
- [ ] PR merge state 无冲突，review 中没有未解决的 P0/P1 finding。
- [ ] Future quota tombstone/target status、ObjectHandle owner-local-only、release digest binding 人工复核通过。

## 7. 失败时的可执行处理方案

1. 记录失败 job、run id、最终 SHA 和最小失败日志；禁止用旧 HEAD 日志替代。
2. 按类别运行最小本地复现：
   - C++/sanitizer：对应 build preset + 单个 gtest filter；
   - Windows：优先检查平台头文件、路径和 shell 差异；
   - workflow：`actionlint` + `check-workflows.py --self-test`；
   - release：`release-fault-injection.sh` + `verify-release-inputs.sh` fixture；
   - fuzz：对应 sanitizer smoke，再跑 bounded libFuzzer。
3. 为真实缺口先加失败合同，再做最小修复；不缩减矩阵、不改 required check 名、不忽略失败。
4. 重跑受影响定向集，再跑 424/424 Debug 与相关 sanitizer 集。
5. 更新本报告的 finding、证据和剩余风险，提交并推送新 HEAD。
6. 等待新 HEAD 全部 required checks，旧 HEAD 的绿色结果不继承。

## 8. 非本 PR 阻断的后续项

- 真实 registry 的 protected-environment dry-run/推广演练；
- 1K/4K/16K session 扫描报告与是否引入 ready index 的数据裁决；
- 1K/10K/100K object 与 4096 session 阶梯；
- 300-player、900 秒 single/owner Pair；
- 跨主机 gateway 与真实 mudlib 当前 commit 联调。

这些项目必须继续保持 `needs-remediation`、`unknown` 或 `external-required`，但不应用缺失的
生产容量证明否定本 PR 已完成的代码正确性门禁，也不能反过来把本地 smoke 写成生产证明。

## 9. 2026-08-11 增量复核：Alpine/musl `sigevent` 兼容性

### F19：Docker Alpine 构建依赖 glibc 私有 `sigevent` 字段

远端 Docker job `31484501403 / 93756692241` 在 Alpine 3.18（musl）编译
`src/vm/internal/posix_timers.cc:65` 时失败：musl 的 `struct sigevent` 没有 glibc 私有字段
`_sigev_un`。直接替换为 `sigev_notify_thread_id` 又会在 Ubuntu glibc 的当前头文件下失败，
因为 glibc 没有公开该别名。

已执行的最小修复：

- 增加 `set_eval_timer_thread_id()` helper；
- glibc 使用其 Linux ABI 中的 `_sigev_un._tid`；
- 提供 `sigev_notify_thread_id` 宏的 libc（Alpine/musl）使用公开宏；
- 其他 Linux libc 在编译期明确报错，不静默创建错误的定时器目标。

该修复不改变 `SIGEV_THREAD_ID`、`SYS_gettid`、信号处理器或计时器时钟回退顺序。

### F19 验证证据

| 检查 | 结果 |
| --- | --- |
| Ubuntu GCC Debug 增量构建 | 通过 |
| Debug eval/mudlib/owner 定向合同 | 6/6 |
| TSan eval/mudlib/owner 定向合同 | 6/6；`setarch x86_64 -R` |
| TSan focused subset | 360/360；`setarch x86_64 -R`；无 TSan 报告 |
| Alpine 3.18 Docker build | 通过；musl 编译、静态链接和镜像生成均通过 |
| Docker entrypoint smoke | 通过；`/fluffos/bin/driver --version` 返回 0 |
| Docs/workflow/action pin self-test | 全部通过 |

### F19 远端处理

本地修复完成前，PR#36 仍指向旧 SHA `8dcd2e0db945eef2b3b83b0df0c503f739367953`，
merge state 为 `UNSTABLE`。提交并推送本修复后，必须等待 Docker、Evidence Gate 及全部
required checks 针对新 SHA 重跑；旧 SHA 的失败或成功都不继承。远端全部 required checks
通过且无冲突后，才可将 §1 结论改为 **可合并**。

## 10. 2026-08-11 增量复核：Evidence Gate raw artifact 下载边界

### F20：Evidence Gate 未下载 envelope 绑定的 raw 报告

PR HEAD `e588262ba71e4922f24d07852299f5a225cfd9e6` 的 CI Run `31487695555` 中，
`capacity-evidence-envelope` 只包含三份 `*_capacity.json`，而三份 `*_raw.json` 被保存在
独立的 `lpc-modern-runtime-bench-raw` artifact。Evidence Gate 只下载前者；校验器按
`raw_report` + `raw_sha256` 绑定规则正确拒绝了缺失 raw 文件的 envelope。

### F20 修复

- 保持 envelope 与 raw artifact 分离，避免 raw JSON 被当作 envelope 扫描；
- Evidence Gate 继续把 envelope 下载到 `build/reports/capacity`；
- 新增 raw artifact 下载步骤，并将目标设为 `build/reports`。该 artifact 的内部
  `capacity/*_raw.json` 路径因此恢复到校验器要求的 `build/reports/capacity/*_raw.json`；
- 不放宽 `check-evidence.py` 的 raw 文件存在性或 SHA-256 校验。

### F20 验证结果

| 检查 | 结果 |
| --- | --- |
| 本地 artifact 布局复现 + `check-evidence.py --mode gate` | 通过；3 envelopes，raw 文件存在且 SHA-256 全部匹配 |
| `check-workflows.py --self-test` | 通过；含 Evidence Gate 双 artifact 下载契约负例 |
| `check-docs.py`、`check-actions-pins.py --self-test`、`test-evidence-gate.py` | 全部通过 |
| 代码修复提交 `f45778ff` CI Run `31490583896` | 成功；Evidence Gate job `93783872067` 成功 |
| Docker Run `31490583878` | 成功 |
| CodeQL Run `31490583917` 与 CodeQL check-run | 成功 |
| 代码修复提交当时的 PR merge state | `CLEAN` / `MERGEABLE` |

F20 的 artifact 缺失阻断已关闭；当前没有遗留的 P0/P1 代码阻断。文档闭环提交后的
required checks 仍是最终合并门禁。
