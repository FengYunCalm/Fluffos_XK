# TSan 全量 ftest 报告（#1247 A 阶段门禁）

日期：2026-08-19
构建：build-recompile-tsan（ENABLE_TSAN=ON，setarch -R 禁用 ASLR 后构建/运行——WSL2 默认
mmap_rnd_bits 过高导致 TSan 运行时 `FATAL: unexpected memory mapping`，属环境兼容问题）
命令：`setarch $(uname -m) -R driver etc/config.test -ftest`（testsuite/ 下）

## 结果

- 全量 -ftest：**Checks succeeded**（0 Check Failed）
- ThreadSanitizer 报告：**1 个 data race，全部帧在 libevent 内部**（见下）

## 竞态详情（基线，非 #1247 引入）

```
WARNING: ThreadSanitizer: data race
  Write of size 4 ... event_debug_note_setup_ src/thirdparty/libevent/event.c:267
    #1 event_assign event.c:2224
    #2 event_new event.c:2280
    #3 add_walltime_event src/backend.cc:421
    #4 drain_game_tick_slice backend.cc:298 (main thread)
  Previous write ... thread T9
    #3 add_walltime_event backend.cc:421
    #4 thread_func src/packages/async/async.cc:219 (async worker)
```

- 竞态对象：libevent `event_debug_note_setup_()` 的 debug 记账计数器（`event_debug_mode_on`
  下的无锁递增），主线程 backend 与 async worker（async.cc:219 thread_func → event_new）
  并发调用时触发。
- 全部栈帧落在 `src/thirdparty/libevent/`（第三方库源码），**无任何帧在 #1247 改动代码
  内**；#1247 的 ASYNC 移植改的是 async.cc 的请求记账（current_works 等），不涉及
  event_new 的调用方式。
- 判定：**基线存量竞态**，按 A 工作流"基线已有报告单独列出"规则登记，不作为 #1247
  门禁失败项；与 ASan 基线（asan-ftest-leaks-full.txt，17984B/24 泄漏）同类处理。

## 与 ASan/UBSan 复验的关系

- ASan/UBSan 复验（12dec936e）：0 Check Failed、0 runtime error，泄漏与基线同量同型。
- 本报告覆盖 a2_runtime.lpc（91a5e446 提交后）之前的所有 #1247 代码路径；a2_runtime.lpc
  新增路径（compress 往返/垃圾 buffer、200×%Y strftime、40 级长路径 get_dir）在 ASan 下
  的独立复验见后续提交（如未单独跑，则本报告为其 TSan 视角覆盖）。
