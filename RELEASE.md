# Release Policy

## Release shape

This fork uses workflow-driven tagged releases for runtime binaries and container images.

## Versioning

- Release tags are generated as `vYYYY.MMDD.N`.
- Use the release workflow to create the tag rather than inventing a second versioning scheme.

## Before release

- Update `CHANGELOG.md` with the fork-specific changes.
- Verify the Windows and Linux build paths you expect the workflow to exercise.
- Keep release notes scoped to the fork changes: build reliability, warning cleanup, and packaging hygiene.
- Evidence checklist（发布前必须逐项确认）：
  - [ ] CTest（Debug 与 ASan 矩阵）全部通过，隔离 LPC testsuite 退出码为 0
  - [ ] benchmark/smoke 报告携带 `fluffos.evidence.manifest.v1` 元数据并通过 `tools/docs/check-evidence.py`
  - [ ] 300-player Pair / 900 秒真实链路容量证据（`external-required`）已按当前 checkout 完成或明确标记未完成
  - [ ] 历史证据（2026-06 压测、mudlib final audit）不单独作为 ready 依据，当前 checkout 证据已重跑
  - [ ] 发布资产不包含测试私钥 fixture（`testsuite/etc/key.pem`）

## Automation

The release workflow creates the tag, builds platform assets, uploads them to the GitHub Release, and publishes container images.

## Reproducible builds

Named CMake presets distinguish the three binary classes (see `CMakePresets.json`):

- `dev-debug` — developer native build (`-march=native`, LTO off, Debug)
- `portable-release` — portable release (`-march=native` off, LTO on)
- `asan` / `ubsan` / `tsan` — sanitizer profiles (Debug, LTO off, native off)

Release binaries must never be built with the developer-native profile. Every
release build records its full configure command in the CI log; the
`fluffos.evidence.manifest.v1` report schema pins `build_config_hash`,
`compiler` and `platform` so a binary's configuration can be replayed.

Security flags on non-sanitizer builds include `-D_FORTIFY_SOURCE=2` and
stack protector (`-fstack-protector-strong` for Release,
`-fstack-protector-all` for Debug); sanitizer builds add
`-fno-omit-frame-pointer` and disable FORTIFY/stack-protector to avoid
interference.

## Runbooks

- Release/approval/drill: `docs/runbooks/release.md`
- Rollback and incident handling: `docs/runbooks/rollback.md`
- Gateway trust boundary and deployment checks: `docs/runbooks/gateway-security.md`
- 300-player capacity acceptance (external-required): `docs/runbooks/capacity-300-player-pair.md`

## Notes

- Use prerelease mode when the build is not yet final.
- Do not describe upstream history as if it were a fork-specific release change.
