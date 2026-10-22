# 构建与发布

主仓库为 [wtalioy/JustConnect](https://github.com/wtalioy/JustConnect)，`origin` 用于开发与发布，`upstream` 仅供参考。开发节奏与清理规则见 [AGENTS.md](../AGENTS.md)，进度及实测结论见 [plan.md](../plan.md)；代码职责见[架构说明](ARCHITECTURE.md)，Go 来源与许可见 [UPSTREAM.md](../corelib/UPSTREAM.md)。

## 本地构建

需要 CMake ≥ 3.20、C++17、Python ≥ 3.11、[go.mod](../corelib/go.mod) 固定的 Go 及原生 cgo C 编译器。Qt ≥ 6.10，组件为 Core、Concurrent、Gui、Widgets、Network、Svg、WebEngineWidgets；先配置 Qt 的 CMake 搜索路径。

当前固定 Qt 6.12.0／WebEngine 6.140.0-rc，WebEngine 构建编号 `6.12.0-0-202609281005`，尚非正式版，不与 WebEngine 6.11.2 混用。SDK、aqt 和校验规则统一由 [setup-qt](../.github/actions/setup-qt/action.yml)／[安装脚本](../scripts/install-webengine.py) 维护；Go／cgo 工具链由 [setup-core-toolchain](../.github/actions/setup-core-toolchain/action.yml) 维护，升级须验证三平台测试及六组包。

```sh
cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 3
ctest --test-dir build -C Release --output-on-failure
```

Unix 使用 Go 静态归档；Windows 的 cgo 使用固定校验和的 LLVM-MinGW UCRT，Qt 宿主使用 MSVC，并从应用目录加载随包 DLL。共享 [CoreLibrary.cmake](../cmake/CoreLibrary.cmake) 构建同一份核心，记录来源及工具链到 `build/source-revision.txt`／`build/core-toolchain.txt`。

正式应用可离线自检，不需要账号、网络、TUN 或显示服务器，也不创建应用配置／日志；检查启动必需的 VPN、原网络快照接口及初始保护能力，但不读取实际网络：

```sh
./build/JustConnect --core-self-test
```

Windows 路径为 `build/Release/JustConnect.exe`，macOS 为 `build/JustConnect.app/Contents/MacOS/JustConnect`。无显示服务器的 Linux 界面测试设置 `QT_QPA_PLATFORM=offscreen`；offscreen 通过不代替真实桌面验收。

Qt 协议 UI 测试在 offscreen 且未指定 `QT_QUICK_BACKEND` 时使用 Qt 软件场景图；现有 `--disable-gpu` 仅约束 Chromium。真实页面、脚本、Cookie 及 TLS 断言继续执行，桌面应用的渲染选择不变；两层配置依据 [Qt 软件渲染说明](https://doc.qt.io/qt-6.10/qtwebengine-features.html#force-use-of-software-rendering)。

Linux 设备后端及隔离验证需要系统 `iproute2`。分配后端只使用固定系统目录中由 root 拥有、不可由组或其他用户写入的 `ip` 回读原生链路信息；缺失时返回不支持，不创建设备。

Linux 路由后端与设备分配共用这一受信程序检查。批量命令通过标准输入交付并关闭写端，命令端口保留原有无输入调用；超过管道缓冲区的完整交付／EOF 及内核权限拒绝有针对性回归。路由隔离验证只允许私有网络命名空间，命令与边界见[设备记录](CORELINK-PROBE.md#linux-owned-routes)。

Unix 原生分配测试通过同一后端在交付 fd 前配置 IPv4 点对点地址及非默认 MTU，脚本只保留数据交换和尚未由后端接管的目的路由／源规则。Linux 配置后回读故障验证真实接口及路由无残留；macOS 使用一次性 runner。宿主命名空间拒绝和原普通用户／收发／强杀清理断言保留，测试中的 SIGKILL 只针对持有测试设备 fd 的隔离接收进程。

### 当前 Linux／WSL2 开发环境

本机 Qt 位于 `$HOME/.local/share/JustConnect/Qt/6.12.0/gcc_64`，补充运行依赖位于同级 `sysroot`，包清单／摘要保存在其 `packages.json`。当前 GCC 16.2.1、CMake 4.4.4、Ninja 1.13.2；未修改系统软件包或全局 shell 配置。已忽略的 `CMakeUserPresets.json` 保存 SDK、库／字体及测试依赖路径：

```sh
export PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.2.linux-amd64/bin:$PATH"
cmake --preset local
cmake --build --preset local
ctest --preset local
```

产物在 `build/local`。直接运行时补充依赖环境；WSLg 还需有效的 `DISPLAY` 或 `WAYLAND_DISPLAY`：

```sh
env LD_LIBRARY_PATH="$HOME/.local/share/JustConnect/sysroot/usr/lib:$HOME/.local/share/JustConnect/Qt/6.12.0/gcc_64/lib" \
    FONTCONFIG_PATH="$HOME/.local/share/JustConnect/sysroot/etc/fonts" \
    ./build/local/JustConnect
```

## 集成 Go 源码的离线基线

```sh
python scripts/test-corelib.py
python -m unittest discover -s tests -p '*_test.py'
```

Go 入口校验固定工具链、模块锁、ABI 生成文件、gofmt、vet、构建及全部包测试；显式使用 `CGO_ENABLED=1`／`cgocheck2`，关闭 workspace 和自动工具链切换，依赖来自 Go 缓存与 `go.sum`。Python 安装器测试需要 aqt；普通应用 CTest 不需要。当前本机可使用 `build/s110-python/bin/python` 的现有测试环境。

全量 Go 每包预算与正式 ABI CI 一致为 90 秒。S3 维护／失效回归扩展后，本机 bridge 包约 59 秒；单个网络、取消及退出场景仍保留原有短时限，包总预算留出累计用时和机器调度余量，不扩大场景的失败等待。

## 正式 C ABI 契约验证

固定 Go 与 Qt SDK 就绪后执行：

```sh
cmake -S tests/coreabi -B build/coreabi -DCMAKE_BUILD_TYPE=Release
cmake --build build/coreabi --config Release --parallel 3
ctest --test-dir build/coreabi -C Release --output-on-failure
```

该项目验证正式 C11／C++17 宿主、Qt／WebEngine 共存、受控认证／隧道与代理收发及性能；配置、事件、常量生成和边界见 [CORE-ABI.md](CORE-ABI.md)。六组 CI 在支持的平台执行 Go race；Windows ARM64 不支持 race，普通 Go／FFI／Qt 检查仍执行。回环网关不访问学校账户，也不代替校园／透明接管验收。

同一 Core ABI 工作流在一次性 runner 验证设备权限与正常／强杀清理，范围见[设备记录](CORELINK-PROBE.md#设备与权限边界)。Windows 设备检查先于完整 ABI 构建执行，尽早暴露驱动／权限问题；全部必需检查仍须通过。设备日志同时保留标准输出和错误输出，Windows 直接写入证据文件，超时也保留部分输出；失败不得靠扩大数据期限或放宽清理断言通过。

## 平台结果契约与隔离验证

测试通过 [Platform.cmake](../cmake/Platform.cmake) 按平台注册；`ctest --test-dir build -N` 可查看清单。失败／取消／权限／超时及可能已修改的结果由应用层契约表达，代理快照与所有权恢复规则见[架构说明](ARCHITECTURE.md)。隔离环境要求：

| 平台 | 测试依赖与写入边界 |
| --- | --- |
| Windows | 系统凭据测试使用唯一测试条目，自启动使用唯一 Run 值并清理；代理真实写入仅在临时 Actions runner 的 LAN 执行并恢复，本地仅只读探针与失败夹具 |
| macOS | 凭据使用临时 Keychain；代理使用临时 preferences 文件，仍需预先具备 `sudo -n` 测试权限；登录项脚本用真实 osacompile 编译，不把替身结果算作桌面授权通过 |
| Linux | 需要 gsettings、dbus-run-session、gdbus、gnome-keyring、kreadconfig6／kwriteconfig6（libkf6config-bin）；使用临时 XDG、keyfile／KConfig 和私有 D-Bus，不写当前桌面的代理或凭据库 |

Linux 可用 `JC_TEST_SECRET_PROVIDER` 指定隔离安装的 gnome-keyring-daemon，`JC_TEST_SECRET_PROVIDER_LIBS` 指定其库路径；私有 KDE 工具还需对应 PATH／库路径。用户 preset 可能覆盖环境，必要时直接用 `ctest --test-dir build/local`。工具缺失或授权不足应报告失败，不扩大跳过范围。KConfig 后端在修改前拒绝含凭据的代理 URL，避免密码进入进程参数。

原生凭据验证与使用替身的 UI／账户隔离／晚到结果测试各自保留；桌面解锁、真实授权、Clash 共存和宿主强杀恢复仍按计划单独验收。测试筛选可用 `ctest --test-dir build -R 'credential|profile|setting|coreengine|platform|autostart|systemproxy' --output-on-failure`。

Windows DNS 使用 `JustConnectDnsReader.exe` 的原生 MI 读取，十秒总预算包含进程启动与完整快照，不预热或重试。`JCDNS` 仅保留白名单阶段／计时；可选类缺失、必需提供者失败、空 NRPT、同目录伪造 mi.dll、超时进程清理及 JSON 边界分别验证。生产读取器不含故障参数，测试目标单独启用；本地可用 `JC_TEST_WINDOWS_DNS_READER` 为测试程序指定已构建的 Windows 夹具读取器，经互操作读取真实系统。Windows 原生 CI 验证 MSVC 两架构，应用 CI 另从 CoreRuntime 安装目录运行统一 DNS 入口；包检查使用清理后的环境执行实际读取器，并审计其 PE、哈希及签名。旧脚本入口前超时未作底层归因，完整对照及唯一故障证据归并到 `build/reports/windows-dns-native.json`。

## aTrust 性能基线

```sh
ctest --test-dir build/coreabi -C Release -R coreabi_performance_test --output-on-failure
```

输出 `build/coreabi/performance.json`，与日志一起保存在六组 Core ABI artifact。正式宿主在正常／每次节点回应额外等待 5 ms 两种场景下，测启动、进程 CPU、200 ms 空闲 CPU、峰值 RSS、20 次认证／连接／停止重绑及一次认证取消；每 5 次重连记录 RSS。TCP 64 KiB × 32、UDP 1200 B × 128，另各 16 次 32 B 往返，逐字节及网关计数校验。

吞吐为单个未完成回声的应用 goodput，非最大带宽；5 ms 不是统一网络 RTT，RSS 为进程历史高水位，20 次重连不能证明长期无泄漏。包报告的离线自检耗时也不等于首屏时间。跨硬件／平台结果仅作各自基线，不据此推断性能优劣。

### S1-11 历史测量基线

代码 `6db2c06` 的[六组 Core ABI](https://github.com/wtalioy/JustConnect/actions/runs/39412404160)已通过。正常节点摘要如下；完整 CPU／时延、慢节点、重连和历史包体积见[固定版本原始测量](https://github.com/wtalioy/JustConnect/blob/9a3b729/docs/DEVELOPMENT.md#s1-11-历史测量基线)，当前包体积见 [S2-09](../plan.md#s2-09-closeout)。

| 平台 | 峰值 RSS MiB | TCP／UDP MiB/s |
| --- | ---: | ---: |
| Windows x64 | 39.09 | 114.832／4.271 |
| Windows ARM64 | 40.70 | 27.117／3.612 |
| macOS x64 | 29.11 | 61.476／0.667 |
| macOS ARM64 | 47.73 | 73.831／4.877 |
| Linux x64 | 68.43 | 107.678／4.949 |
| Linux ARM64 | 86.04 | 225.030／5.295 |

## aTrust 配置与升级

设置页与引导共用 Fudan／Custom 入口。Fudan 只预填 `vpn.fudan.edu.cn:443`，认证方式从服务器查询，优先 UIS OAuth2；不写死登录 URL／认证编号。保存前使用实际 C ABI 的纯校验接口，不联网、不占用会话。公开字段映射、账户绑定及迁移由既有模块统一维护，详见[架构说明](ARCHITECTURE.md)。

默认验证服务器证书，可附加学校 PEM CA。“跳过隧道证书校验”默认关闭，为所有 aTrust 配置共用；显式开启后只影响探测及 IP／TCP／L3，登录／资源 HTTPS 和认证页面维持原校验策略。隧道仍加密，但失去对端身份验证；不按学校分支或因连接失败自动降级。

“使用系统凭据库记住认证”默认关闭。启用后可恢复有效认证；文件菜单“清除当前账户认证缓存”不删除密码／TOTP 或其他账户，关闭记住认证也不代替清除。旧版缓存只按原账户隔离迁移，不自动投入登录。系统库锁定／不可用时不写明文替代；Windows 单条凭据上限 2560 字节，超限会提示无法保存，本次连接仍可继续。

导入／重置先改窗口草稿，取消不写原配置；导出只含公开字段并拒绝覆盖源配置，不复制密码、TOTP、票据或登录 URL。原地升级保留有效值、未知键和其他账户；失败保留旧版本，未来版本不降级。配置／缓存保留与删除条件见计划的[收尾记录](../plan.md#implementation-history)。

Fudan Windows 实机验收步骤：启用记住认证并连接；分别测试普通断开、菜单退出后的重启恢复；明确清除当前账户认证缓存后再连接并认证。用户已确认这些场景及手工系统代理后的网页正常，显式代理 SSH 已完成密钥交换；真实过期／MFA 未触发，按确认的 S2 范围不作硬性门槛，处理逻辑与自动回归保留。完整结果统一见 [S2](../plan.md#s2)。

当前 `authentication_started` 不能单独证明重新登录，`transport_connected` 只表示通道／本地代理就绪。TLS 阶段及原因等固定诊断码见 [ABI 事件契约](CORE-ABI.md#事件与认证回应)；这些诊断不记录账号材料、原始证书或请求 URL。

当前开发版仍需手动设置系统代理，或明确启用连接后自动设置，才能让遵循该设置的浏览器使用通道；Windows OpenSSH 需显式代理。下面仅为临时诊断，使用现有 Git for Windows `connect.exe`，替换 SSH 主机／别名、安装路径或已修改的 HTTP 端口，保留 SSH 自身信任检查：

```powershell
ssh -o 'ProxyCommand="C:/Program Files/Git/mingw64/bin/connect.exe" -H 127.0.0.1:11081 %h %p' school-host
```

最终交付遵守 R11：一次连接完成分流、DNS 与应用接管，已有浏览器和终端直接可用，不再设代理、改 SSH 或重开应用。此能力尚未实现，自动设置系统代理不能代替终端接管。

## 分支与 Actions

| 触发 | 结果 |
| --- | --- |
| 推送 develop／向 develop 或 main 提 PR | 三平台 Tests，构建及 CTest，不打包发布；Core ABI 按自身路径规则验证六组宿主 |
| 推送 main | 六组测试与安装包，不创建 Release |
| 手动 Build packages，选择 develop | 六组 nightly 预览，名称 `JustConnect-preview-提交SHA-平台-架构`；忽略 nightly/version 输入，不使用发布签名／公证凭据 |
| 手动 Build packages，选择 main | 可选 nightly；关闭时须提供有效 version，不自动创建 Release |
| 发布 vX.Y.Z（可带后缀）的 GitHub Release | 重建六组并上传附件，失败不发布成功结果 |

Windows 为 ZIP（完整解压并保留核心 DLL），macOS 为 DMG，Linux 为 AppImage；Actions artifact 保留 14 天。普通 job 仅 `contents: read`，上传 Release 的 job 才用 `contents: write`，无需额外 PAT。

[打包工作流](../.github/workflows/build.yml) 统一安装 CoreRuntime、工具链／来源及许可证，解包后清除 SDK 环境并运行 [verify-package.py](../scripts/verify-package.py)。报告检查正式 ABI、版本／干净来源、架构／依赖／系统下限、哈希和签名；Windows 另测移走 DLL 后失败，以及包内 WebEngine en-US／zh-CN 页面和 JavaScript。Release 省略 Go DWARF，不裁掉运行资源；新增语言须同步部署及包验证。

每次打包由 [archive-source.py](../scripts/archive-source.py) 导出同一干净提交的完整维护源码及摘要，附 `source-revision.txt`，支持无 `.git` 的 CMake 重建并标记 `source_state:archive`。包检查拒绝旧独立核心、旧来源目录与 Wintun。macOS 当前最低 14.4；Linux glibc／GLIBCXX 下限以实际包报告为准。静态字段检查不代替旧系统实机兼容验证。

## macOS 签名与公证

普通构建无需 Secrets；缺少 Apple 凭据时使用 ad-hoc 临时签名，预览不声称已开发者签名或公证。需要正式发布时配置：

| 用途 | Actions Secrets |
| --- | --- |
| 开发者签名 | `MACOS_CERT_P12`：证书及私钥 P12 的 Base64；`MACOS_CERT_PASSWORD`：导出密码；`MACOS_CERT_IDENTITY`：Developer ID Application 身份 |
| 公证（另需签名凭据完整） | `APPLE_ID`：开发者账户；`APPLE_APP_SPECIFIC_PASSWORD`：应用专用密码；`APPLE_TEAM_ID`：团队 ID |

PR 不使用签名 Secrets；已配置的签名／公证失败时构建失败，不降级为成功发布。Windows 当前未配置代码签名。

## 任务与验证记录

每个工作单元先验证、独立提交，再更新任务状态；未完成要求不得提前勾选。CI、安装包自检、受控网关和真实校园／桌面结果分开记录。最新证据只维护在计划，历史过程由 Git 追溯，不在本文追加流水或另存重复历史文档。README 待 [S8](../plan.md#s8) 流程稳定后补写。
