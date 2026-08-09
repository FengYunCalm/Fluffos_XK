# Gateway 安全运行手册（T18）

> 覆盖：gateway master transport 信任边界、external bind 拒绝、测试秘密与部署检查。

## 1. 信任边界（不可妥协）

- gateway master transport **没有认证与加密**。driver 固定
  `kGatewayExternalBindAllowed=false`：外部绑定（`bind_all`）在运行时被拒绝，
  只监听 loopback（`127.0.0.1`）。
- 不要通过修改该布尔值来“开放跨主机 master”。若未来需要跨主机 master，
  必须另立协议认证、加密、密钥轮换、重放保护与兼容性项目。

## 2. 部署检查（每次部署执行）

```bash
# 1. 监听地址必须是 loopback
ss -ltnp | grep <gateway_port>        # 期望 127.0.0.1:<port>
# 2. 启动日志包含 loopback 监听行
grep "Accepting \[Gateway\] connections on 127.0.0.1" <log>
# 3. 拒绝计数可观测（runtime status）
#    gateway_external_bind_rejected 在尝试外部绑定时递增
# 4. 若需对外提供，前面必须有受保护代理（TLS + 认证）转发到 loopback
```

## 3. 误配置处置

- 若配置尝试 `bind_all`：driver 打日志“external listen rejected: authenticated
  transport is not available; use a secured proxy”，计数递增，listener 不建立。
- 运维应改用代理方案；禁止为兼容性重新开放未认证外部 transport。
- 回滚只允许回到 loopback/上一安全配置。

## 4. 测试秘密

- `testsuite/etc/cert.pem` 与 `testsuite/etc/key.pem` 是**测试专用 fixture**，
  非生产凭证。
- 发布资产必须不含 `*.pem`/`*.key` 私钥（release.yml 已有打包前检查，失败即阻断）。
- 仓库扫描器规则应将 `testsuite/etc/` 下的 fixture 标记为测试用途，避免误报。

## 5. 资源耗尽边界（Gate A）

| 边界 | 默认 | 验收 |
| --- | --- | --- |
| packet size | 1 MiB（绝对 16 MiB） | 超限拒绝且可诊断 |
| JSON depth | driver 校验 | 畸形 JSON 拒绝 |
| output FIFO | 每 session/聚合上限 | 慢 peer 不阻塞他人 |
| future watch | 上限 + 拒绝 | 超限返回错误 |
| mailbox | 4096 | 超限入队拒绝 |

## 6. 安全事件流程

1. 保留现场（日志、计数器、core dump、commit）。
2. 按 `SECURITY.md` 报告渠道私密上报；未修复前不公开细节。
3. 按 `rollback.md` 回退到上一安全版本。
4. 复盘后补回归测试与文档，走 PR。
