# 构建与发布

JustConnect 的主仓库是 [wtalioy/JustConnect](https://github.com/wtalioy/JustConnect)。
`origin` 用于自己的开发和发布；`upstream` 等 remote 仅用于查看上游变更，保留原有历史和致谢。

应用已通过 `CoreEngine → EmbeddedCoreEngine → C ABI → corelib.Session` 在宿主内运行 aTrust。正式源码直接维护于 `corelib/` 单一模块，来源与许可见 [UPSTREAM.md](../corelib/UPSTREAM.md)。根 CMake 与原生宿主共用 [CoreLibrary.cmake](../cmake/CoreLibrary.cmake)，Unix 静态链接，Windows 固定随包 DLL。旧下载／独立核心打包校验脚本仍被构建工作流调用，S1-09／10 接续验收并删除；下文独立核心章节作为尚在迁移的构建链路保留，不代表应用仍调用外部核心。

`Core ABI` 工作流验证六组原生库、Qt 适配器／认证 UI、受控协议网关及 Go 回归；三平台 `Tests` 同时构建实际应用并运行 CTest。Go 版本来自 `corelib/go.mod`，cgo 编译器由共用 [setup-core-toolchain](../.github/actions/setup-core-toolchain/action.yml) 准备。Windows 使用固定校验和的 LLVM-MinGW UCRT 编译 Go DLL，C++ 保持 Qt 对应 MSVC。安装包自检、完整依赖及签名验收仍属 S1-09，Linux 权限检查独立保留在 `tests/platform/`。

## 集成 Go 源码的离线基线

使用 [corelib/go.mod](../corelib/go.mod) 固定的 Go 1.27.2，在仓库根目录执行：

```sh
python scripts/test-corelib.py
```

本机可将已有工具链临时加入本条命令的 PATH：

```sh
env PATH="/home/lioy/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.2.linux-amd64/bin:$PATH" \
    python scripts/test-corelib.py
```

入口显式关闭 workspace 和自动工具链切换，要求 Go 版本与模块声明一致；外部依赖使用 Go 缓存和 `go.sum`，不带 vendor。当前使用 `CGO_ENABLED=0` 验证协议源码与离线逻辑，六组 cgo 链接由正式 ABI 宿主验证，正式库与 Qt 适配器构建已接入共享 CMake，S1-09 接续安装包验收。`Tests` 三平台工作流增加同一入口，并将 `corelib/go.sum` 纳入 Go 缓存键。

该入口构建全部源码，并按 `go list` 的实际包集合运行完整套件（含无测试包），数量由验证输出记录。S1-07 已恢复认证包，删除原 `session.do` 已知失败例外；回环 TLS／隧道网关覆盖实际认证、代理收发、查询、阶段取消与失败回滚。Windows 继续运行真实调试文件 ACL 回归，覆盖新建、已有宽权限收紧及拒绝访问后不截断；Unix 验证 `0600`。这些测试不访问校园、创建设备或修改系统网络。

## 正式 C ABI 契约验证

S1-03 的独立入口见 [CORE-ABI.md](CORE-ABI.md)。`corelib/abi/contract.json` 是 C／Go 共用常量的单一来源；普通 Go 验证入口运行 `scripts/generate-core-abi.py --check`，避免两个语言的状态码、版本或边界漂移。构建来源从 Git 注入，运行地址、端口与凭据由宿主传入。

`tests/coreabi` 同时编译 C11／C++17 宿主，实际调用正式库及明确标记的认证测试驱动；新增 `coreabi_protocol_test` 用受控网关驱动正式 C 宿主完成认证、代理数据传输、停止与查询重启；Unix 使用静态库，Windows 使用固定随包 DLL。`Core ABI` 复用已有六组工具链执行该宿主、QThread／WebEngine 共存及 Go 回归，支持的平台执行 race；日志统一在 `build/coreabi/*.log` 并上传。Windows ARM64 的 Go race 不支持，普通 Go 和真实 FFI 检查仍必需通过。根应用已使用相同的库构建入口，安装包自检和完整迁移仍由 S1-09／10 实施。

## 分支与 Actions

- 日常开发使用 `develop`。每次推送到该分支，`Tests` 工作流在 Windows、macOS、Linux 上构建并验证固定核心、编译应用并运行 CTest，不打包、不发布。
- 向 `main` 或 `develop` 提交 PR 同样运行 `Tests`。本地提交需推送到 GitHub 才会触发 Actions。
- 合并并推送到 `main` 后，`Build packages` 工作流为 Windows、macOS、Linux 的 x64/ARM64 构建、测试并打包，产物在该次 Actions 的 Artifacts 中保留 14 天。
- Windows 产物为 ZIP，内含 `JustConnect.exe` 和依赖；macOS 为 DMG；Linux 为 AppImage。
- 在本仓库发布 `vX.Y.Z`（可带 `-beta.1` 等后缀）的 GitHub Release 后，工作流重建该版本，全部成功后将安装包附加到该 Release。推送 `main` 仅生成 Actions 产物，不自动发布正式版本。
- 可从 `main` 手动运行打包工作流；关闭 `nightly` 时必须提供有效的版本号。手动运行只生成产物，不创建 Release。
- 开发预览：进入 Actions → `Build packages` → `Run workflow`，分支选择 `develop`。此时手动构建六组预览包并运行测试，产物名为 `JustConnect-preview-提交SHA-平台-架构`，在该次运行的 Artifacts 下载，保留 14 天。预览始终使用 nightly 应用版本（忽略 `nightly/version` 输入），macOS 使用临时签名，不执行开发者签名、公证或 Release 上传；普通推送到 `develop` 仍只触发测试。
- 旧独立核心打包构建暂用 [core/manifest.json](../core/manifest.json) 固定源码和补丁；实际内嵌库使用本仓库 `corelib/` 源码；已移除 `core_nightly` 输入。应用的 nightly／正式版本均使用该清单，不下载上游浮动 release 或 nightly 核心。

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

需要模块固定版本的 Go、原生 cgo C 编译器、C++17 编译器、CMake 3.19 或更新版本、Qt 6.5 或更新版本，以及 Qt Core、Concurrent、Gui、Widgets、Network、Svg、Core5Compat、WebEngineWidgets。

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

### 当前独立核心构建（迁移前基线）

[构建清单](../core/manifest.json)固定上游提交、源码归档 SHA-256、AGPL-3.0 许可证、Go 版本、模块锁校验和，以及按数组顺序应用的补丁。当前补丁数组为空，直接构建上游源码；会话恢复等功能补丁另按计划审查。

使用清单指定的 Go 1.27.2、Python 3.12 或更新版本及 Git，在本机执行：

```sh
python -m unittest discover -s tests -p build_core_test.py
python scripts/build-core.py
```

脚本先校验源码与补丁，再校验 Go 模块，以 `CGO_ENABLED=0`、`-trimpath` 和固定版本信息编译本机核心，并实际执行 `-version` 检查输出。它不修改 shell 配置，也不接受浮动分支或预编译核心；Go 版本不符会在下载前失败。输出在 `build/core`：可执行文件与 `core-provenance/`，后者包含原始源码、补丁、许可证、清单和构建记录。构建记录保存签名前二进制校验和；macOS 后续签名会改变 Mach-O 文件。

测试与打包共用 [build-core](../.github/actions/build-core/action.yml)，本机也可独立运行脚本。构建脚本现有 10 项测试，覆盖损坏的源码／模块锁／许可证／补丁、补丁顺序、越界路径、错误的 Go 版本及打包后二进制／清单／版本不匹配。上游完整测试并非当前通过项：`session_context_test.go` 调用了不存在的旧方法 `Session.do`；临时纠正该调用后，还发现 `TestRefreshCancellation` 失败，`Session.request` 覆盖了调用者的取消上下文。已撤销临时纠正，不删除上游测试、不携带测试修补；这些问题记入计划，相关行为修复时再恢复完整验证。

六组安装包在各自平台和架构上编译核心。部署脚本只复制 `build/core` 产物，验证源码、许可证、清单与签名前二进制校验和，并实际执行核心检查版本；可单独运行 `python scripts/build-core.py --verify build/core`。Linux 先完成 Qt 部署，再加入核心，避免打包工具再次 strip 导致校验和改变。工作流最终重新解压 Windows ZIP、提取 AppImage 中的核心、挂载 macOS DMG 后验证实际内容。macOS 因签名改变二进制，最终检查完整应用签名、核心版本与全部来源文件；构建记录中的二进制校验和对应签名前文件。

核心构建基线为 `81b85f8`：[三平台 CI](https://github.com/wtalioy/JustConnect/actions/runs/39263157320)与[六组开发预览](https://github.com/wtalioy/JustConnect/actions/runs/39263164818)全部通过，六份预览产物可在后者的 Artifacts 下载。该记录验证固定源码构建、应用回归和实际打包内容，不代表校园登录通过。

本机通过已有 Go 的工具链机制缓存了 Go 1.27.2（约 253 MiB），未替换系统 Go 或修改全局 PATH。本机运行核心构建可使用：

```sh
env PATH="/home/lioy/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.2.linux-amd64/bin:$PATH" \
    python scripts/build-core.py
```

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

本次 SDK 基线提交为 `794f2be`：[三平台测试](https://github.com/wtalioy/JustConnect/actions/runs/39256137284)与[六组开发预览](https://github.com/wtalioy/JustConnect/actions/runs/39256137984)均已通过；预览包可在后者的 Artifacts 下载。它们验证构建、浏览器运行测试与打包，不代替校园网络或真实桌面验收。

## 任务与验证记录

开始开发时先查看[实施计划](../plan.md)中的当前任务与阶段依赖。实现后更新任务勾选、提交／测试证据及受影响的平台验收结果；代码完成但缺实机条件时保留待验收。

CI 编译、CTest、预览打包与真实校园网络验收分别记录。当前代码结构及封装限制见[架构说明](ARCHITECTURE.md)，后续目标和状态以计划为准；本文维护可执行的构建与发布操作。

当前打包使用固定源码构建的第三方核心；校园透明访问与自动共存尚未实现。上游高级用法的来源与已采用约束保留在计划参考索引中，原手工配置示例不再作为当前产品的操作说明；新的使用文档随 [S8](../plan.md#s8) 的实测结果补充，README 暂时留空。
