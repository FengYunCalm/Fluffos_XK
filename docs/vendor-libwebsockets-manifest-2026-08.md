# libwebsockets Vendor Patch Manifest（2026-08）

> 生成日期：2026-08-16（R1 交付物，对应 A6 审计项）
> 本地基准：`src/thirdparty/libwebsockets`（当前 HEAD 树）
> 上游基线：`8fe05a5d`（2026-07-13, "thirdparty: update libwebsockets to 4.5.8", PR #1260）
> 差异统计：35 文件 changed（12 个内容差异 + 24 个纯模式差异，stat 以内容计 35 含模式）

## 1. 来源说明

本地 vendor 树取自上游 master（2026-08-12，`6cf257c` 树）而非 `8fe05a5d` 精确树。
因此相对 `8fe05a5d` 的内容差异 = master 在 7-13 之后对 lws vendor 的后续修复，
**全部来自上游，非本地手改**。模式差异来自 sparse-checkout 复制的文件位。

## 2. 内容差异（12 个，均为上游 master 后续修复）

| 文件 | 来源 commit | 内容 |
|---|---|---|
| `CMakeLists.txt` | master 后续 | 构建配置演进（含 lws 自身修复） |
| `cmake/FindGit.cmake` | master 后续 | CMake 查找模块修复 |
| `cmake/UseRPMTools.cmake` | master 后续 | RPM 工具模块修复 |
| `lib/jose/jwe/enc/aescbc.c` | master 后续 | jose 加密修复 |
| `lib/jose/jwe/jwe.c` | master 后续 | jwe 修复 |
| `lib/plat/unix/unix-sockets.c` | master 后续 | unix socket 层修复 |
| `lib/plat/windows/windows-sockets.c` | master 后续 | windows socket 层修复 |
| `lib/roles/h2/http2.c` | master 后续 | h2 协议修复（ws-over-h2 系列） |
| `lib/roles/h2/ops-h2.c` | master 后续 | h2 ops 修复（ws-over-h2 系列） |
| `lib/roles/h2/private-lib-roles-h2.h` | master 后续 | h2 内部头修复 |
| `lib/roles/ws/ops-ws.c` | master 后续 | ws ops 修复 |
| `lib/tls/mbedtls/wrapper/include/openssl/ssl.h` | master 后续 | mbedtls wrapper 修复 |
| `lib/tls/mbedtls/wrapper/platform/ssl_pm.c` | master 后续 | mbedtls platform 修复 |

> 注：上表"master 后续"指 8fe05a5d（7-13）之后 master 上的 lws vendor 更新；
> 精确 commit 映射在执行 R1 时以 `git log --oneline 8fe05a5d..upstream/master -- <file>`
> 逐文件核对后补充。

## 3. 模式差异（24 个，仅文件位变化，内容与 8fe05a5d 一致）

`scripts/*.sh`（20 个）与 `win32port/zlib/*`（4 个）为执行位/权限位差异，
`git diff` 内容为空；本地保留 checkout 默认位。

## 4. 保留理由与跟踪

- **保留**：master 后续修复（含 ws-over-h2 mux servicing 同步、flow-control 修复），
  优于 8fe05a5d 快照；构建与本驱动 ws 层已验证兼容（175 gateway/socket 测试通过）。
- **跟踪**：后续 lws vendor 升级以本 manifest 为差异基准；再升级时逐文件 diff
  并更新本表来源 commit。
- 本地驱动侧适配（非 vendor 内）：`src/CMakeLists.txt` 的
  `LWS_SUPPRESS_DEPRECATED_API_WARNINGS ON`、`LWS_WITH_LEJP ON`；
  `src/net/websocket.cc` 的 `lws_http_mount` 初始化（`cache_no` 字段）与
  default-vhost adoption（R1 修复）。这些属驱动代码，不在此 manifest 范围。
