# FluffOS_XK 项目规则

## 构建与磁盘（WSL2）

- 本仓库在 WSL2 环境下开发；**WSL2 的 vhdx 磁盘会在大量写入时占用飙升**（曾因全并行构建导致宿主机磁盘占满、WSL 被迫重启）。
- 构建时**不要使用 `-j$(nproc)` 全并行**，固定限制并行度（如 `cmake --build build-xxx -j4` 或 `-j8`）。
- 构建前检查磁盘余量（`df -h /`）；同一时刻只跑一个构建目录，避免多个 build-* 目录同时编译。
- 磁盘紧张时优先删除可重建的旧构建目录（`build-*` 均可由 CMake 重建，仓库不依赖其内容）。

## 构建与内存（WSL2）

- **WSL2 总内存约 6GB，pi 环境（Java/next-server 等）常驻占用 ~2.5GB**，可用内存常不足 3.5GB；构建（尤其 LTO 链接）会瞬间吃满并触发 OOM/swap 颠簸。
- 构建前检查内存（`free -h`）：可用 < 2GB 时先清理（删旧 build-* 目录、停无关进程）再构建；构建期间不并行跑 driver/-ftest/bench 等内存大户。
- **LTO 链接是内存大户**：`lpc_tests` 的链接（`-flto=auto`，产出 ~98MB 二进制）在内存紧张时改用 `-flto=2` 手动链接（link.txt 命令加 `-flto=2` 覆盖 auto），或先删其他 build 目录腾出内存。
- 构建失败/无输出时先查 `free -h` 与 `dmesg | grep -i oom`，确认不是内存打爆再排查编译错误。

## 验证粒度

- 验证手段与对象匹配：行为改动用针对性测试，文案/文档/注释改动用一致性检查（grep/读文件），**轻量改动不跑全量门禁**（lpc_tests 全量、-ftest 全量、ASan 只留给实质代码改动）；只有实质代码改动才跑全量构建 + 对应测试。
- **默认不全测**：验证必须定量、针对性——只跑与改动相关的测试（`--gtest_filter` 定向、`-ftest:路径` 定向、单目标构建），用数字证据（通过/失败计数、耗时、diff 行数）报告；全量门禁只在用户明确要求或阶段验收需要时跑。
- 全量 -ftest 必须从 `testsuite/` 目录跑（`cd testsuite && ../build-sync/bin/driver etc/config.test -ftest`）；从仓库根跑会因 mudlib 目录错误空转，`grep -c "Check Failed"` 得 0 不代表通过。

<comet-ambient-resume>
<!-- Managed by Comet. Edits inside this block may be replaced by comet init/update. -->
<!-- Contract: comet.resume_probe.v2 -->

## Comet Ambient Resume

在这个仓库中，开始处理需要改动或调查的任务前，如果可能存在活跃 Comet workflow，把当前用户请求传入只读探针：`comet resume-probe . --stdin --json`。

- 如果用户通过宿主明确调用任意 Comet Skill（例如 `@comet`、`/comet`、`@comet-native` 或 `/comet-hotfix`），显式调用优先于本恢复协议；不要运行 resume probe，直接进入被调用的 Skill。
- 只信任返回的 `workflow`、`skill` 和 `entrySource`；它们只由项目配置或无配置兼容回退决定。不得扫描或切换另一套 workflow。
- 如果 probe 返回 `auto_resume`，简短说明选中的 active change，并进入 `nextCommand` 指向的永久入口。不要把状态命令当作恢复入口直接推进。
- 如果 probe 返回 `ask_user`，只问一个简短问题并等待用户回复。
- 如果当前请求未明确调用 Comet Skill，且 probe 返回 `out_of_scope` 或 `none`，不要进入 Comet workflow。
- 如果配置或状态无效且没有 `nextCommand`，停止并报告原因；不要猜测另一个 workflow。
- 不能只因为存在 active change 就把无关任务挂到该 change。Native 的未提交改动由 Native 入口检查，不由探针自动归因。
</comet-ambient-resume>
