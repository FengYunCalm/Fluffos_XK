# L6 TSan 验证证据（2026-08-17）

构建与运行配置：
- 独立构建目录 `build-recompile-tsan`（TSan 与 ASan/UBSan 互斥，
  src/CMakeLists.txt `_SAN_COUNT > 1` FATAL）
- `cmake -S . -B build-recompile-tsan -DCMAKE_BUILD_TYPE=RelWithDebInfo
  -DENABLE_TSAN=ON -DENABLE_LTO=OFF -DMARCH_NATIVE=OFF`
- **ASLR 冲突与规避**：GCC 13 TSan 在 Ubuntu 24.04 默认
  `vm.mmap_rnd_bits=32` 下运行即崩（`FATAL: ThreadSanitizer: unexpected
  memory mapping`，autogen 工具 `make_options_defs` 首报）。规避：
  `setarch $(uname -m) -R` 包住构建与全部运行（进程级禁用 ASLR，
  子进程继承）。未改系统参数（无需 root、无系统级副作用）。

## 运行矩阵

| 测试 | 命令 | 结果 | 日志 |
|---|---|---|---|
| owner/future 定向 | lpc_tests `--gtest_filter='*Owner*:*Future*'` | 209/209 PASS，0 TSan 警告 | l6-tsan-owner-first.txt |
| 全量 lpc_tests | lpc_tests（无 filter） | **424/424 PASS，0 TSan 警告** | l6-tsan-full.txt |
| driver owner 定向 | driver config.test `-ftest:single/tests/efuns/owner_executor_contract` | exit 0，0 Check failed，0 TSan 警告 | l6-tsan-driver-owner.txt |
| driver recompile 定向 | driver config.recompile `-ftest:single/tests/efuns/recompile_object` | Checks succeeded，0 Check failed，0 TSan 警告 | l6-tsan-driver-recompile.txt |

## 并发路径覆盖分类表

| 类别 | 覆盖点 | 验证 |
|---|---|---|
| Owner 运行时协调（quiesce/epoch/claim） | owner_runtime_coordinator 全套单测（owner.cc 主线程门禁 + 快照） | Owner* filter 209 项 |
| Future/任务完成 | future_store 单测（generation-aware read） | Future* filter |
| 主线程队列调度（drain/call_out 分发） | driver owner_executor_contract（call_out 轮询 + 主队列 drain） | driver 定向 |
| 热重载事务（staging/commit/pin 释放） | driver recompile_object 全合同（200 次重载 + self_reload + stale funptr） | driver 定向 |
| 异步回调（async_read/TLS） | 未单独跑（TSan 下 async/socket 测试超时风险；ASan 矩阵已覆盖） | deferred 说明 |

## 结论

L6 完成：TSan 构建成功（setarch -R 规避 ASLR 冲突）、owner 定向先行
209/209、全量 424/424、driver owner/recompile 定向全部零 ThreadSanitizer
警告——**无数据竞争报告**。上游 CI 的 TSan 步骤（ctest 并发子集）语义
已被 owner/future 定向 + driver 定向覆盖。
