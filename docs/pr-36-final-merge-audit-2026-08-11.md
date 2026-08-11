# PR #36 最终轮合并审计报告

> 审计日期：2026-08-11（Asia/Shanghai）
> 审计对象：[FengYunCalm/FluffOS_XK PR #36](https://github.com/FengYunCalm/FluffOS_XK/pull/36)
> Base：`24bd5f4f5126963966d1d91787f327f4cc84a5e7`
> 已审实现提交：`04088aa90fd6c12dfb597b9dccbce7585a87a93f`
> 分支：`feat/exec-audit-plan-2026-08-09`

## 1. 当前结论

实现层面的本地阻断项已经关闭，可以进入最终远端门禁；在最终 PR HEAD 的完整 required
checks 返回前，结论保持 **暂不合并**。这不是发现了新的未修代码阻断，而是避免把旧 HEAD
的失败或本地单平台结果误写成最终跨平台结论。

合并结论只允许按以下规则转换：

- 最终 PR HEAD 与本报告审计的实现/文档提交一致；
- Workflow Lint、Docs、Evidence、GCC/Clang、ASan/UBSan/TSan、macOS、Windows、
  libFuzzer、CodeQL、Docker 全部成功；
- Future、ObjectHandle、release artifact/digest 三组人工合同复核无回退；
- 工作树没有未提交任务改动，PR 可合并状态无冲突。

满足以上条件后，建议改为 **可合并**。任一 required check 失败则继续按 §7 修复，不允许跳过。

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
| GCC Debug CTest | 420/420 |
| GCC ASan Debug | 420/420 |
| GCC UBSan Debug | 420/420 |
| GCC TSan focused subset | 360/360；WSL 下构建和运行均使用 `setarch x86_64 -R` |
| 定向 Future/ObjectHandle/string 回归 | 19/19 |
| Gateway fuzz smoke | 普通、ASan、UBSan 均通过；256 inputs、1024 accepted、256 length rejects、512 JSON rejects、零残留 |
| LPC isolated runner | LPC 断言通过；四个实际 loopback 端口唯一；Driver 退出 0 |
| 端口隔离压力 | 5 次串行 + 20 次并发通过，无 Driver/sandbox/lockdir 残留 |
| runtime/bench smoke | `lpc-modern-runtime-stress.sh smoke` 通过；owner-local fast path 8192、global fallback 0 |
| 构建卫生 | 连续两次全目标构建，第二次无 C++ 编译/链接 |
| workflow/release | check-workflows self-test、action pins self-test、release fault injection、actionlint 1.7.12 通过 |
| docs/evidence/SBOM | check-docs、evidence negative suite、CycloneDX validate 通过 |

上述是实现提交上的本地证据，不等价于最终 PR HEAD 的 Clang/macOS/Windows/CodeQL/Docker
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
4. 重跑受影响定向集，再跑 420/420 Debug 与相关 sanitizer 集。
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
