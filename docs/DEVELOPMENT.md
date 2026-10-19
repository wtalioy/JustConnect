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
- 当前 `core_nightly` 输入只控制下载第三方核心的 release 或 nightly，与应用的 nightly 版本独立；固定源码与补丁构建尚待 [S1](../plan.md#s1) 完成，完成后同步更新此处操作。

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
Windows 当前未配置代码签名；未维护额外的软件源包。

## 本地构建

需要 C++17 编译器、CMake、Qt 6.5 或更新版本，以及 Qt Core、Concurrent、Gui、Widgets、Network、Svg、Core5Compat、WebEngineWidgets。

当前本地与 CI 使用 [Qt 6.12.0](https://www.qt.io/blog/qt-6.12-released)，搭配官方为它构建的 [WebEngine 6.140.0 候选版](https://download.qt.io/development_releases/qtwebengine/6.140.0-rc/)，固定二进制构建编号 `6.12.0-0-202609281005`。已确认允许使用这一候选组件以保持三平台统一 Qt 6.12；它尚不能标作 WebEngine 正式版。[WebEngine 从 Qt 6.12 起独立发布](https://www.qt.io/blog/qt-webengine-will-release-separate)，已排除在 Windows 上出现 DLL 接口不兼容的 Qt 6.12／WebEngine 6.11.2 组合。

SDK 操作集中在 [setup-qt](../.github/actions/setup-qt/action.yml)，测试与打包共用。aqt 固定到支持扩展仓库与原生 ARM64 的提交；[组件安装脚本](../scripts/install-webengine.py) 处理新的 `6120/61400` 仓库路径，只下载 WebEngine，保留校验并拒绝未经审核的构建变更，合并后重新定位 SDK。它不下载源码或从源码构建浏览器。

CI 使用当前可用的 Ubuntu 26.04、Windows Server 2025／Windows 11 ARM64 与 macOS 26 镜像；Actions 使用已核对的最新稳定版本。升级时同时验证 SDK、测试和六组预览包，不仅替换版本号。

```sh
cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 3
ctest --test-dir build --build-config Release --output-on-failure
```

无显示服务器的 Linux 环境可设置 `QT_QPA_PLATFORM=offscreen` 运行界面测试。
核心依赖为 [Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)。开发运行时将 `zju-connect`（Windows 为 `zju-connect.exe`）放在应用旁或加入 PATH。

### 当前 Linux／WSL2 开发环境

本机 SDK 位于 `/home/lioy/.local/share/JustConnect/Qt/6.12.0/gcc_64`，编译器为 `/usr/bin/c++`（GCC 16.2.1），CMake 4.4.4，Ninja 1.13.2。所需的字体、XCB 和 xkbfile 依赖单独放在 `/home/lioy/.local/share/JustConnect/sysroot`，包清单与 SHA-256 保存在其中的 `packages.json`；未修改系统软件包或全局 shell 配置。

本地只安装 `qtbase`、`qtsvg`、`qtdeclarative`、`qttranslations`、`qtwayland`、配套 ICU，以及 `qt5compat`、`qtshadertools`、`qtpositioning`、`qtserialport`、`qtwebchannel`、`qtwebengine`。QML／Quick 等是 WebEngine 的依赖。未安装 Qt Creator、Qt Tools、源码、示例、离线文档、独立调试符号或可选的 Vulkan／CUPS 开发包；SDK 静态库中附带的调试信息已移除，保留可链接的库和符号。本地 SDK 约 875 MiB，补充运行依赖约 6 MiB，构建目录另计。CI 额外安装 Qt Tools 以提供部署工具。

已创建仅供本机使用且被 Git 忽略的 `CMakeUserPresets.json`，设置 SDK 路径、必要的动态库／字体配置、Ninja 和测试环境，直接运行：

```sh
cmake --preset local
cmake --build --preset local
ctest --preset local
```

构建产物位于 `build/local`。离开 CMake 直接运行时，也需要提供本机补充依赖路径：

```sh
env LD_LIBRARY_PATH="$HOME/.local/share/JustConnect/sysroot/usr/lib:$HOME/.local/share/JustConnect/Qt/6.12.0/gcc_64/lib" \
    FONTCONFIG_PATH="$HOME/.local/share/JustConnect/sysroot/etc/fonts" \
    ./build/local/JustConnect
```

无显示服务器时额外设置 `QT_QPA_PLATFORM=offscreen`；WSLg 图形运行需要有效的 `DISPLAY` 或 `WAYLAND_DISPLAY`。本机自动验证使用 offscreen，未把它记作桌面视觉或校园网络验收。

CTest 现为 16 项，其中 `webengine_test` 使用 offscreen 和软件渲染实际加载 HTML 并检查 JavaScript 结果，验证内嵌网页运行所需的浏览器进程与 SDK 兼容性。测试不访问校园网或修改系统代理。

SDK 安装阶段另运行三项 Python 安装器测试，覆盖路径校验、未审核构建拒绝和重复合并／清理；Unix 框架符号链接用例仅在 Unix 上执行。安装器测试需要 aqt，日常应用的 CTest 不需要。

## 任务与验证记录

开始开发时先查看[实施计划](../plan.md)中的当前任务与阶段依赖。实现后更新任务勾选、提交／测试证据及受影响的平台验收结果；代码完成但缺实机条件时保留待验收。

CI 编译、CTest、预览打包与真实校园网络验收分别记录。当前代码结构及封装限制见[架构说明](ARCHITECTURE.md)，后续目标和状态以计划为准；本文维护可执行的构建与发布操作。

当前打包仍下载第三方核心的上游版本，校园透明访问与自动共存尚未实现。上游高级用法的来源与已采用约束保留在计划参考索引中，原手工配置示例不再作为当前产品的操作说明；新的使用文档随 [S8](../plan.md#s8) 的实测结果补充，README 暂时留空。
