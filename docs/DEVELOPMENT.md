# 构建与发布

JustConnect 的主仓库是 [wtalioy/JustConnect](https://github.com/wtalioy/JustConnect)。
`origin` 用于自己的开发和发布；`upstream` 等 remote 仅用于查看上游变更，保留原有历史和致谢。

## 分支与 Actions

- 日常开发使用 `develop`。每次推送到该分支，`Tests` 工作流在 Windows、macOS、Linux 上编译并运行 CTest，不打包、不发布。
- 向 `main` 或 `develop` 提交 PR 同样运行 `Tests`。本地提交需推送到 GitHub 才会触发 Actions。
- 合并并推送到 `main` 后，`Build packages` 工作流为 Windows、macOS、Linux 的 x64/ARM64 构建、测试并打包，产物在该次 Actions 的 Artifacts 中保留 14 天。
- Windows 产物为 ZIP，内含 `JustConnect.exe` 和依赖；macOS 为 DMG；Linux 为 AppImage。
- 在本仓库发布 `vX.Y.Z`（可带 `-beta.1` 等后缀）的 GitHub Release 后，工作流重建该版本，全部成功后将安装包附加到该 Release。推送 `main` 仅生成 Actions 产物，不自动发布正式版本。
- 可从 `main` 手动运行打包工作流；关闭 `nightly` 时必须提供有效的版本号。手动运行只生成产物，不创建 Release。
- 开发预览：进入 Actions → `Build packages` → `Run workflow`，分支选择 `develop`。此时手动构建六组预览包并运行测试，产物名为 `JustConnect-preview-提交SHA-平台-架构`，在该次运行的 Artifacts 下载，保留 14 天。预览始终使用 nightly 应用版本（忽略 `nightly/version` 输入），macOS 使用临时签名，不执行开发者签名、公证或 Release 上传；普通推送到 `develop` 仍只触发测试。

普通 CI 使用 `contents: read`，仅上传 Release 的 job 使用 `contents: write`，按 [GitHub 工作流权限文档](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions) 配置。无需为普通构建或 Release 上传单独创建 PAT。

## macOS 签名与公证

普通构建不要求任何 Secrets。没有 Apple 凭据时，macOS 包使用临时签名供测试，不能视为已通过 Apple 开发者签名或公证。

如需开发者签名，在本仓库的 Actions Secrets 中配置以下三项：

| Secret | 内容 |
| --- | --- |
| `MACOS_CERT_P12` | 签名证书及私钥导出的 P12 文件，Base64 编码 |
| `MACOS_CERT_PASSWORD` | P12 导出密码 |
| `MACOS_CERT_IDENTITY` | Developer ID Application 签名身份 |

如需公证，再配置以下三项；仅在签名凭据与公证凭据均完整时运行公证：

| Secret | 内容 |
| --- | --- |
| `APPLE_ID` | Apple 开发者账户 |
| `APPLE_APP_SPECIFIC_PASSWORD` | 应用专用密码 |
| `APPLE_TEAM_ID` | Apple 开发者团队 ID |

PR 测试流程不使用签名 Secrets。配置了凭据但签名或公证失败时，构建失败，不降级为成功发布。
Windows 当前未配置代码签名；未维护 JustConnect 的 AUR 包，也不再更新上游的 `ez4connect` 包。

## 本地构建

需要 C++17 编译器、CMake、Qt 6.5 或更新版本，以及 Qt Core、Concurrent、Gui、Widgets、Network、Svg、Core5Compat、WebEngineWidgets。CI 固定使用 Qt 6.10.3。

```sh
cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 3
ctest --test-dir build --build-config Release --output-on-failure
```

无显示服务器的 Linux 环境可设置 `QT_QPA_PLATFORM=offscreen` 运行界面测试。
开发运行时需将 `zju-connect`（Windows 为 `zju-connect.exe`）放在应用旁，或加入 PATH。

## 当前范围

应用名称、更新检查、项目链接和发布均归属 JustConnect。新应用标识使用独立的配置、认证数据和日志路径，不自动迁移上游应用的数据；旧应用的自启动项和网络设置清理仍属于后续恢复功能的范围。

当前打包仍使用上游 zju-connect 的发布版（手动构建可选其 nightly），核心版本查询仍指向上游；固定源码提交、应用补丁和校园网络自动共存尚待按 [计划](../plan.md) 实现。不要以未修改的上游核心替换未来带共存补丁的核心。
