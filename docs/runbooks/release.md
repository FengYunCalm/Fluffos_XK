# 发布运行手册（T18）

> 目标：在失败、撤回与安全事件中按步骤行动。所有演练只使用候选版本和测试仓库，
> 不触碰生产 release。手册本身版本化，改动走 PR。

## 1. 候选版本与发布流程

1. 从 `master`（或候选分支）发起 `workflow_dispatch` 触发 `.github/workflows/release.yml`，
   `prerelease` 按需设置。版本号由 `generate-version` 生成（`vYYYY.MMDD.N`），只作为候选，
   **不写 tag**。
2. 流水线顺序（artifact-first, tag-last）：
   - `generate-version` → `build-binaries`（Windows + Linux，含 CTest、静态链接断言、资产 sha256）
   - `build-docker` 依赖 `build-binaries` 测试通过
   - `create-release` 仅在全部构建/测试通过后：创建 tag → 创建 **draft** release → 校验 sha256 → 上传资产
   - `finalize-release` 写 release notes，保持 draft 状态
3. **人工审批**：在 GitHub Releases 页面审查资产与 notes 后点击 “Publish release”。
   draft 永不自动转正式。
4. 公告：发布后更新 README 安装说明相关链接与 `CHANGELOG.md`。

## 2. 五类失败场景演练

### 2.1 测试失败不发版

- 现象：`build-binaries` 中 Linux CTest 失败（`make test || true` 已删除，失败即 job 失败）。
- 动作：修复代码 → 重跑 workflow → 新候选版本号（不重跑旧版本号）。
- 验证：远端无新增 tag；`git tag -l "v2026*"` 无本次版本；GitHub Releases 无新条目。
- 恢复时间：以修复周期为准；残留资产无（draft 未创建）。

### 2.2 签名失败不发版

- 前置：签名密钥/环境未配置时，`create-release` 不应被允许执行（environment 保护）。
- 现象：签名步骤失败。
- 动作：修复密钥配置 → 从**新候选版本**重跑；不删除历史 tag、不强推。
- 验证：draft release 不存在或已删除；无部分上传资产。

### 2.3 资产 hash 不匹配

- 现象：`create-release` 的 `sha256sum -c` 失败。
- 动作：job 失败即停；检查打包步骤与上传路径，修复后重跑。
- 验证：所有资产 `sha256sum -c` 通过；release 资产与 CI artifact 一致。

### 2.4 Docker push 成功但 binary 失败

- 现象：`build-docker` 成功但 `build-binaries` 失败（DAG 中 docker 依赖 binaries，
  正常不会发生；若发生说明依赖配置被绕过）。
- 动作：立即检查 workflow 依赖图；修复后重跑。已 push 的镜像 tag 不回滚覆盖，
  新版本号重新发布；如需撤回，按容器仓库策略删除 tag 并通知用户。
- 验证：Docker tag 与 binary release 的 manifest（commit/config/hash）一致。

### 2.5 gateway external bind 误配置

- 现象：运维试图配置 gateway 外部绑定。
- 动作：driver 会拒绝（`kGatewayExternalBindAllowed=false`，loopback-only）；按
  `docs/runbooks/gateway-security.md` 检查部署，改用受保护代理。
- 验证：启动日志显示 loopback 监听；`gateway_external_bind_rejected` 计数上升；
  无 0.0.0.0 监听端口。

## 3. 回滚顺序

1. 保留上一版已签名 release；不删除历史 tag，不强推。
2. 客户端/部署回退到上一版资产（Docker tag 回退到上一版本号）。
3. 记录恢复时间、残留 tag/release、镜像撤回与客户端兼容策略。
4. 每季度复核 action 版本、基础镜像 digest、密钥轮换与支持版本。

## 4. 值班检查

- `git tag -l "v$(date -u +%Y.%m%d).*"` 确认当日发布版本。
- GitHub Actions 中 release workflow 的每个 job 状态。
- 发布后立即验证 `/update.json`、`/app.apk` 等公共端点（如适用）。
