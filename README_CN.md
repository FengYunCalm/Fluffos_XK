# FluffOS（本仓库分支）

[English](README.md) | 简体中文

<<<<<<< HEAD
本仓库是 FluffOS 的分支，目标是提升现代编译工具链下的构建稳定性与告警清理，并重点优化 Windows/MSYS2 的安装体验。
=======
本仓库是 FluffOS 的分支，目标是提升现代编译工具链下的构建稳定性与告警清理，
并重点优化 Windows/MSYS2 的安装体验。

## 仓库定位

- 维护供下游 MUD 运行树使用的 FluffOS 源码级分支改动
- 重点放在构建稳定性和定向告警清理，而不是功能分叉
- 与消费该驱动的游戏仓库分离维护上游同步关系

## 本分支的优化点

- **Windows 安装稳定性**：`cmake --install` 在 Windows 下通过 `bash cp -f` 安全覆盖二进制，避免覆盖 `driver.exe` 等文件时出现“Permission denied”。
- **核心告警清理**：针对 scratchpad、preprocessor、ed、telnet_ext、external、socket_efuns 等模块的告警修复。
- **第三方告警控制**：对 libevent/crypt/libwebsockets 进行告警抑制并关闭 IPO；调整 filesystem 的 CMake 最低版本以增强兼容性。
- **许可对齐**：补齐 LICENSE/NOTICE，并在 README 中引用官方许可来源。

## 获取源码

```bash
git clone https://github.com/FengYunCalm/fluffos-src.git
cd fluffos-src
```

这个 README 只停留在源码仓库层面，不声明打包分发或托管部署路径。

## 文档

- 官方文档：https://www.fluffos.info
- 本地文档入口：`docs/index.md`
- 本分支变更记录：`CHANGELOG.md`
- 完整功能列表与历史说明请参考上游文档。

## 贡献指南

请查看 `CONTRIBUTING.md`（英文）了解范围与提交规范。

## 安全

请负责任地报告漏洞，详见 `SECURITY.md`。

## 行为准则

参见 `CODE_OF_CONDUCT.md`。

## 许可与引用

- MIT 许可，见 `LICENSE`。
- 官方许可文本引用：
  - https://www.fluffos.info（License & Copyright）
  - `docs/index.md`
- 历史 LPmud/MudOS 限制仍适用于遗留组件，见 `Copyright`。
- 第三方许可：见 `NOTICE` 与 `src/thirdparty/*`。

## 上游

- https://github.com/fluffos/fluffos
