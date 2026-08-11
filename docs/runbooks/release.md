# 发布运行手册（T18）

> 目标：让候选版本在读取、构建、校验与远端写入之间保持可追溯。演练默认使用
> `dry_run=true`，不创建 tag、release 或镜像引用。任何残留处理都不得覆盖历史 tag，
> 不得 force-push。

## 1. 当前发布流程

1. 只从 `.github/workflows/release.yml` 的 `workflow_dispatch` 入口启动，提供完整 40 位
   `target_sha`。`validate-target` 必须证明该提交属于 `origin/master`、checkout 精确命中该
   SHA，并且发布门禁名称完整且全部成功。
2. 只读阶段并行产生两类输入：
   - Windows/Linux 二进制、各自的 SHA-256；
   - 一次构建得到的 Docker archive、独立检查得到的 digest、对同一 archive 的 Trivy 报告。
3. `verify-release-inputs` 下载二进制与 OCI 验证材料，生成 release 专用的 SBOM、manifest、
   provenance 副本，并验证：两平台资产完整、checksum、CycloneDX、manifest 一致性、
   target SHA、scan/digest 绑定。
4. `dry_run=true` 到此结束；所有 job 只有只读权限，不产生远端写入。
5. 非 dry-run 经 `release` protected environment 审批后，按顺序执行：
   - `publish-draft`：tag 精确指向 `target_sha`，创建 draft，上传已经验证的资产；
   - `promote-image`：从同一 archive 推广不可变版本引用，远端复核 digest；
   - 仅稳定版本在不可变 digest 复核通过后更新 `latest`，并再次复核。
6. draft 永不自动发布。人工必须核对 tag、二进制、checksum、SBOM、provenance、镜像 digest
   后，才可在 GitHub Releases 页面发布。

## 2. 无写入故障

以下失败发生在 mutation boundary 之前，不应留下 tag、draft 或镜像版本引用：

- target SHA 格式、祖先关系或 checkout 不一致；
- required check 缺失、排队、取消或失败；
- 任一平台构建/CTest/静态链接断言失败；
- Trivy 阻断，或 archive、digest、scan report 无法绑定；
- checksum、SBOM、manifest、provenance 校验失败。

处置：保留 workflow run 与 artifact 作为诊断证据，修复后重新触发。每次触发重新计算候选
版本；不得为了复用旧候选号而修改或覆盖远端历史对象。

## 3. 部分写入后的恢复合同

### 3.1 tag 已写入，但 draft 创建失败

1. 立即停止后续推广，记录 workflow run、target SHA、tag、失败步骤和时间。
2. 不移动、不覆盖、不删除该 tag，不 force-push。
3. 修复原因后使用新的 `vYYYY.MMDD.N` 版本重新执行完整流水线；不得复用残留 tag。
4. 残留 tag 的人工清理若确有必要，必须单独审批并记录影响，不属于自动恢复流程。

### 3.2 draft 已创建，但资产只上传了一部分

1. 保持 draft，不发布；记录 release id、已上传资产清单及缺失项。
2. 不在同一版本上覆盖或拼接来自另一轮构建的资产。
3. 使用新版本从 target 校验开始重跑，生成完整、同源的一组资产。
4. 旧 draft 标记为失败候选并保留审计记录；删除需要仓库所有者另行明确授权。

### 3.3 不可变镜像已推广，但远端 digest 复核失败

1. 立即停止，禁止更新 `latest`，记录版本引用、预期 digest、远端 digest 和 registry 响应。
2. 不覆盖该不可变版本引用，不用另一次 build 修补同名版本。
3. 核对 archive 与 registry 转换行为，修复后使用新版本重新构建、扫描、推广和复核。
4. 若错误引用可能已被消费，发布告知并引导使用上一已验证版本；具体回退按
   `docs/runbooks/rollback.md`。

### 3.4 `latest` 更新或复核失败

1. 历史不可变版本保持不动；记录 `latest` 更新前后的 digest。
2. 在确认上一稳定 digest 后，经明确审批恢复 `latest`，随后重新 inspect；不得改变历史
   版本 tag。
3. 新候选仍使用新版本号走完整流水线。

## 4. 定期演练与验收

- 每次 workflow 变更：运行 `python3 tools/docs/check-workflows.py --self-test`、
  `bash tools/release/release-fault-injection.sh`、`python3 tools/sbom-generate.py --validate`。
- 合并前：执行 `dry_run=true`，确认 mutation jobs 跳过，且 verified bundle 可下载并复核。
- 正式发布前：确认 protected environment 审批人与权限范围正确。
- 正式发布后：确认 draft 资产完整、版本镜像 digest 等于扫描 digest；仅在人工审批后发布
  draft。

## 5. 值班记录字段

至少记录：workflow run/attempt、target SHA、版本、tag 状态、draft id、资产清单、archive
digest、scan 结论、远端版本 digest、`latest` digest、失败步骤、处置人与恢复版本。
