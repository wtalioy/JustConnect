# 构建与发布

JustConnect 的主仓库是 [wtalioy/JustConnect](https://github.com/wtalioy/JustConnect)。
`origin` 用于自己的开发和发布；`upstream` 等 remote 仅用于查看上游变更，保留原有历史和致谢。

应用已通过 `CoreEngine → EmbeddedCoreEngine → C ABI → corelib.Session` 在宿主内运行 aTrust。正式源码直接维护于 `corelib/` 单一模块，来源与许可见 [UPSTREAM.md](../corelib/UPSTREAM.md)。根 CMake 与原生宿主共用 [CoreLibrary.cmake](../cmake/CoreLibrary.cmake)，Unix 静态链接，Windows 固定随包 DLL。测试与打包均通过同一 CMake 核心 target；旧核心下载／补丁／独立 EXE 校验脚本、清单、action、专属测试及无调用的 Wintun 分发文件已删除。

`Core ABI` 工作流验证六组原生库、Qt 适配器／认证 UI、受控协议网关及 Go 回归；三平台 `Tests` 同时构建实际应用并运行 CTest。Go 版本来自 `corelib/go.mod`，cgo 编译器由共用 [setup-core-toolchain](../.github/actions/setup-core-toolchain/action.yml) 准备。Windows 使用固定校验和的 LLVM-MinGW UCRT 编译 Go DLL，C++ 保持 Qt 对应 MSVC。六组安装包运行正式应用的离线 ABI 自检，并审计架构、依赖、最低系统版本和签名；具体证据见计划的 S1-09。Linux 权限检查独立保留在 `tests/platform/`。

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

入口显式关闭 workspace 和自动工具链切换，要求 Go 版本与模块声明一致；外部依赖使用 Go 缓存和 `go.sum`，不带 vendor。当前显式使用 `CGO_ENABLED=1` 和 `cgocheck2`，包括 ABI 包、生成文件校验、gofmt、vet 和完整离线测试。`Tests` 与打包运行同一入口；Go 缓存按平台、架构、工具链版本与 `corelib/go.sum` 区分。实际应用和六组 C／Qt 宿主通过共享 CMake 构建正式库。

该入口构建全部源码，并按 `go list` 的实际包集合运行完整套件（含无测试包），数量由验证输出记录。S1-07 已恢复认证包，删除原 `session.do` 已知失败例外；回环 TLS／隧道网关覆盖实际认证、代理收发、查询、阶段取消与失败回滚。Windows 继续运行真实调试文件 ACL 回归，覆盖新建、已有宽权限收紧及拒绝访问后不截断；Unix 验证 `0600`。这些测试不访问校园、创建设备或修改系统网络。

## 正式 C ABI 契约验证

S1-03 的独立入口见 [CORE-ABI.md](CORE-ABI.md)。`corelib/abi/contract.json` 是 C／Go 共用常量的单一来源；普通 Go 验证入口运行 `scripts/generate-core-abi.py --check`，避免两个语言的状态码、版本或边界漂移。构建来源从 Git 注入，运行地址、端口与凭据由宿主传入。

`tests/coreabi` 同时编译 C11／C++17 宿主，实际调用正式库及明确标记的认证测试驱动；新增 `coreabi_protocol_test` 用受控网关驱动正式 C 宿主完成认证、代理数据传输、停止与查询重启；Unix 使用静态库，Windows 使用固定随包 DLL。`Core ABI` 复用已有六组工具链执行该宿主、QThread／WebEngine 共存及 Go 回归，支持的平台执行 race；日志统一在 `build/coreabi/*.log` 并上传。Windows ARM64 的 Go race 不支持，普通 Go 和真实 FFI 检查仍必需通过。根应用及安装包使用相同的库构建入口和离线自检；旧下载文件删除由 S1-10 收尾。

## aTrust 性能基线

`tests/coreabi` 的 `coreabi_performance_test` 复用同一正式 C ABI／QApplication 宿主及受控 TLS 网关。按上述 SDK／Go 环境配置后执行：

```sh
cmake -S tests/coreabi -B build/coreabi -DCMAKE_BUILD_TYPE=Release
cmake --build build/coreabi --config Release --parallel 3
ctest --test-dir build/coreabi -C Release -R coreabi_performance_test --output-on-failure
```

输出 `build/coreabi/performance.json`，六组 Core ABI artifact 同时保存它和测试日志。普通 Go 套件没有原生宿主时明确跳过该集成用例，CTest 必须实际运行并验证网关计数、数据内容和生产库身份；缺少数据、超时或释放失败均导致失败。

每个平台各运行正常节点和每次节点回应额外等待 5 ms 的慢节点。记录进程启动到 ABI 就绪的耗时、完整进程 CPU 时间／工作负载墙钟时间、连接后 200 ms 空闲段 CPU、操作系统报告的峰值 RSS，以及每 5 次重连的峰值 RSS。每组完成 20 次实际短信认证、连接就绪、停止并重绑两个监听端口，最后取消一次等待用户输入的认证。节点探测的原有等待计入连接时间；峰值 RSS 是进程历史高水位，不能当成当前驻留量或证明没有泄漏。

首轮通过 SOCKS 分别收发 TCP 64 KiB × 32、UDP 1200 B × 128，并各记录 16 次 32 B 往返；UDP 真实经过 gVisor 与 aTrust L3 的连接认证、数据分帧和校验和。吞吐按单个未完成回声请求的有效载荷计算，两向均逐字节验证。它是受控应用 goodput，受回声／TLS 分片／调度影响，不表示最大带宽。5 ms 是每次节点回应的等待，不是统一的网络 RTT；延迟场景验证传输和取消仍能完成，不引入跨硬件的性能通过阈值。

六组安装包自检 JSON 另外记录 `size_bytes`（归档、去除符号链接的安装文件、宿主、Windows DLL）及 `offline_self_test_wall_ms`。后者是实际已安装应用的离线 ABI 自检耗时，包含进程启动和自检，不等同于主窗口／WebEngine 首屏时间。运行报告保留源码、工具链、Qt、平台／架构和逻辑 CPU 数；不同 CI 机器的数据只作为各自基线，不能直接归因于操作系统或库化。真实校园／生产 TLS、设备透明访问和长时间负载仍按计划单独验收。没有定位到可复现热点时，保留现有协议栈和依赖，不做推测性优化。

### S1-11 历史测量基线

基线代码 `6db2c0680d7800db7f1bad0cc75dbdc353d240b3`：[三平台 Tests](https://github.com/wtalioy/JustConnect/actions/runs/39412404116)、[六组 Core ABI](https://github.com/wtalioy/JustConnect/actions/runs/39412404160)、[六组包及源码](https://github.com/wtalioy/JustConnect/actions/runs/39412419380)。以下保留原始测量值供后续比较，不作为当前版本包大小或真实校园性能。最新包体积见 [S2-09](../plan.md#s2-09-closeout)。

归档与安装大小使用 MiB（1024² B），安装文件排除符号链接；Unix 宿主含静态核心。离线自检耗时包含启动和 ABI 检查，不是首屏时间。

| 平台 | 归档 MiB | 安装文件 MiB | 宿主／核心 DLL MiB | 应用离线自检 ms |
| --- | ---: | ---: | ---: | ---: |
| Windows x64 | 143.52 | 340.07 | 0.49／21.30 | 446.21 |
| Windows ARM64 | 126.01 | 318.31 | 0.58／20.36 | 2366.16 |
| macOS x64 | 170.72 | 413.47 | 11.27／0.00 | 872.92 |
| macOS ARM64 | 145.56 | 348.33 | 10.36／0.00 | 787.35 |
| Linux x64 | 152.59 | 405.03 | 23.31／0.00 | 29.37 |
| Linux ARM64 | 152.10 | 409.91 | 22.44／0.00 | 40.33 |

进程指标来自正常／慢节点各一个 QApplication 加正式 C ABI 的宿主，非完整主窗口；慢节点每次回应额外等待 5 ms，不等同于统一网络 RTT。每场景完成 20 次认证、连接、停止／重绑监听和一次认证取消，收发及服务器计数验证通过。CPU 为完整子进程 CPU 时间；负载墙钟从就绪到清理结束，空闲段约 200 ms，RSS 是操作系统高水位。

| 平台／节点 | 逻辑 CPU | 启动 ms | 进程 CPU ms／负载 s | 峰值 RSS MiB | 空闲 CPU ms | 连接中位／最大 ms | 停止最大／认证取消 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows x64／正常 | 4 | 45.94 | 406.25／30.54 | 39.09 | 0.00 | 1511.99／1516.08 | 1.22／0.27 |
| Windows x64／慢 | 4 | 58.65 | 437.50／34.31 | 39.14 | 0.00 | 1517.31／1521.71 | 1.16／0.28 |
| Windows ARM64／正常 | 4 | 54.47 | 390.62／30.62 | 40.70 | 0.00 | 1512.26／1516.47 | 0.80／0.29 |
| Windows ARM64／慢 | 4 | 52.70 | 515.62／34.44 | 40.73 | 0.00 | 1517.57／1555.27 | 19.23／0.34 |
| macOS x64／正常 | 4 | 107.43 | 623.09／30.81 | 29.11 | 2.01 | 1514.01／1524.45 | 0.74／0.36 |
| macOS x64／慢 | 4 | 185.83 | 887.19／34.64 | 28.57 | 1.96 | 1519.43／1522.90 | 1.68／0.20 |
| macOS ARM64／正常 | 3 | 43.44 | 268.47／30.70 | 47.73 | 0.41 | 1512.75／1525.00 | 3.82／0.09 |
| macOS ARM64／慢 | 3 | 135.63 | 517.00／35.42 | 47.61 | 0.33 | 1521.81／1537.81 | 2.07／0.80 |
| Linux x64／正常 | 4 | 25.66 | 302.67／30.48 | 68.43 | 0.58 | 1510.31／1513.00 | 0.40／0.14 |
| Linux x64／慢 | 4 | 25.29 | 357.16／34.10 | 69.04 | 0.61 | 1515.60／1516.97 | 0.57／0.20 |
| Linux ARM64／正常 | 4 | 31.73 | 253.12／30.47 | 86.04 | 0.18 | 1510.42／1512.93 | 0.34／0.14 |
| Linux ARM64／慢 | 4 | 30.88 | 290.19／34.07 | 84.18 | 0.19 | 1515.44／1519.00 | 0.46／0.13 |

TCP 64 KiB × 32、UDP 1200 B × 128，另各 16 次 32 B 往返。下表每格为正常／慢节点；吞吐是单个未完成回声的有效载荷 goodput，非最大链路带宽；RTT 为中位数。

| 平台 | TCP MiB/s | UDP MiB/s | TCP RTT ms | UDP RTT ms |
| --- | ---: | ---: | ---: | ---: |
| Windows x64 | 114.832／0.715 | 4.271／0.203 | 0.131／5.671 | 0.255／5.639 |
| Windows ARM64 | 27.117／0.705 | 3.612／0.205 | 0.143／5.563 | 0.265／5.555 |
| macOS x64 | 61.476／0.677 | 0.667／0.178 | 0.525／6.079 | 0.656／6.302 |
| macOS ARM64 | 73.831／0.573 | 4.877／0.154 | 0.155／6.610 | 0.157／6.788 |
| Linux x64 | 107.678／0.744 | 4.949／0.210 | 0.126／5.350 | 0.200／5.423 |
| Linux ARM64 | 225.030／0.753 | 5.295／0.211 | 0.091／5.266 | 0.170／5.388 |

重连每 5 次记录峰值 RSS；20 次完成不能证明长期无泄漏。约 1.51 s 的连接中位数包含既有节点探测等待；不同硬件／工具链的差异不能归因于操作系统或库化。未定位到需改写协议栈的瓶颈，真实校园、生产 TLS、设备权限和长期负载仍待单独验收。

## 平台结果契约与隔离验证

`application/platformoperationresult.h` 定义成功、失败、用户取消、权限拒绝、不支持和超时；`mayHaveChanged` 单独记录可能已有修改，不能用一个失败布尔值推断系统保持原样。`SystemProxyCheck` 将查询结果、冲突及启用状态分开；查询失败不进入覆盖确认或设置。会话只确认验证成功的启用状态，部分清除失败保留清理标记，退出清理失败不会清零。

[Platform.cmake](../cmake/Platform.cmake) 按 `windows/`、`macos/`、`linux/`、`unsupported/` 子目录为代理和自启动选择源文件，基础设施不依赖 Widgets，Linux 凭据后端使用 Qt DBus；弹窗及结果文案在界面层。WinINet／RAS 每次检查原生返回值，模式、各协议端点、绕过项及通知均检查；手动模式不改写原有 PAC 地址。查询返回的字符串按 [Microsoft WinINet 文档](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options) 用 GlobalFree 释放。Unix 工具每条命令共享 5 秒启动／完成期限，检查正常退出和退出码，超时杀死并等待回收；这不是整个多步骤操作或退出流程的 5 秒保证。GNOME 与 KDE 分开处理；端点、认证模式及绕过项必须回读匹配，空输出不是有效空列表。

系统代理端口取活动连接的监听快照，修改待用配置须重连后才影响监听；禁用 HTTP／SOCKS5 时不设置系统代理。冲突查询和确认结果按连接代次隔离，新会话等待前次代理操作结束后发起新查询，旧结果不能替它设置代理；恢复失败保留清理责任并停止自动重试。连接结束统一向 SystemProxySession 请求恢复；若应用仍在进行，则待原操作结果明确后串行恢复，期间保持忙状态。确认没有修改的失败不清除未知代理，恢复失败保留手动重试责任，退出消费同一请求。

Windows 按连接保存与恢复状态，不在清除时重新枚举并关闭未知连接；模式恢复还要求端点及 PAC 地址仍属原记录。按 [WinINet 选项文档](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw)以 `FLAGS_UI` 查询模式、以 `FLAGS` 设置模式。真实写入回归仅由 `GITHUB_ACTIONS=true` 的临时 runner 注册执行，限定 LAN，保留并恢复 runner 基线；普通本地测试仅使用原生只读查询和失败夹具。

macOS 使用系统 [SCPreferences](https://developer.apple.com/documentation/systemconfiguration/scpreferences-ft8) 和网络服务 API，保存原始代理字典及字段缺失状态，按服务 ID 固定恢复对象；独占锁内一次提交，提交／应用失败保留或撤销改动，并回读恢复结果。临时本地端点不携带旧认证字段，不调用 Keychain 修改接口，也不把旧凭据传给命令行。测试以真实原生接口在临时绝对路径 preferences 文件中创建服务，覆盖空配置、禁用服务、失败重试和外部字段／服务变更。Apple 的 [SCPreferencesLock 实现](https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCPLock.c)对私有文件同样要求 root 或授权；原生写入用例因此由 CTest 通过 `sudo -n` 执行，需预先具备免交互测试权限，权限不足仍失败。测试仅写临时文件，普通只读探针保持当前用户查询系统配置。桌面授权交互及真实用户 Keychain 状态不由私有文件回归代替，保留人工验收缺口。

GNOME 输出按 [GLib 字符串格式](https://docs.gtk.org/glib/gvariant-text-format.html#strings)处理引号、控制字符及 Unicode 转义，避免写入后因无法回读而丢失恢复路径。Linux 的平台代理回归除模拟失败外，还在临时 `GSETTINGS_BACKEND=keyfile` 和私有 D-Bus／KConfig 文件中运行真实工具。需要 `gsettings`、`dbus-run-session`、`kreadconfig6` 和 `kwriteconfig6`（Ubuntu 的 [libkf6config-bin](https://packages.ubuntu.com/resolute/libkf6config-bin)）；这些是测试／对应桌面后端的系统工具，不链接或分发 KConfig 库。若工具来自私有 SDK，需保留其 PATH／库路径；可用 `ctest --test-dir build/local` 避免用户 preset 覆盖启动环境。KConfig 的字符串值通过命令行参数写入，后端因此在修改前拒绝含用户信息的代理 URL，避免旧代理密码进入进程参数，原设置保持不动；接口语义见 [KConfig CLI 实现](https://github.com/KDE/kconfig/tree/master/src/kreadconfig)。

自启动成功后才保存偏好；系统项已改变而偏好保存失败时明确提示部分完成，迁移保存失败保留旧版本供重试。设置保存失败不关闭窗口或提前清除认证材料。Linux .desktop 使用 QSaveFile 原子替换；路径按照 [Desktop Entry 规范](https://specifications.freedesktop.org/desktop-entry/latest-single/) 转义。实际 gio 回归发现含百分号的首个可执行路径在字段展开前被判为不存在，因此用固定脚本 exec "$0" 与独立路径参数启动，不把文件路径拼进脚本；测试实际启动含空格、引号、美元／反引号、百分号和反斜杠的文件。

根应用 CTest 与六组原生项目共用测试源：

```sh
ctest --test-dir build -C Release -R 'platformbackend_test|autostart_test|systemproxysession_test|settingwindow_test' --output-on-failure
```

`platformbackend_test` 用真实子进程验证退出、崩溃、超时、取消和权限错误，并在 OS API／命令边界注入失败、部分修改、缺少数据及回读错配；Qt 界面／会话回归检查失败不写、晚到查询不操作、待清理状态和退出失败。Windows／macOS readonly 用例只读取当前系统代理；Linux readonly 用真实 gsettings 的 memory 后端读默认值，isolated 用临时 XDG_CONFIG_HOME 的 keyfile 后端执行写入／回读／清除，不连接会话 dconf。

Windows 自启动测试只操作预先确认不存在的唯一测试 Run 值，并注册退出清理；Linux 只写临时目录。macOS 测试用真实 osacompile 编译脚本，并注入命令结果检查登录项的取消、失败及回读；没有冒充真实 System Events 授权／登录项成功。Linux 设置窗口回归验证实际失败时配置／缓存保留，偏好测试在三平台验证真实存储失败。

S2-06 当前正式后端已按快照及所有权恢复原有代理／PAC／绕过项，隔离验证范围见本节前文。真实桌面授权、校园／Clash 共存、完整有界退出与强杀恢复仍按对应 S3／S4／S7 任务验收。

## aTrust 配置与升级

设置页与配置向导共用 Fudan／Custom 服务器入口。Fudan 使用计划 R6 的 `vpn.fudan.edu.cn:443`，与[复旦信息办新 VPN 公告](https://icampus.fudan.edu.cn/f1/a8/c33159a782760/page.htm)一致；只预填端点，不写死登录域、认证编号或登录 URL。用户点击查询后，从服务器返回项中优先选择 OAuth2（名称含 UIS 的项优先），仍等待查询清理完成再允许确认；S2-03 已用验证证书的公开 authConfig 样本和 Qt／Go 回归核对 authId/subType 保留；真实 Fudan 登录仍按 S1-04 验收。Custom 保留其他学校的 aTrust 地址和认证选择，在预置间切换会保留 Custom 地址草稿。

`ConnectionProfile` 只表示当前 ABI 可用的字段；没有协议选择器、任意附加参数或未实现的 TUN／旧转发开关。保存前由 `EmbeddedCoreEngine::validateConfiguration` 调用 `jc_config_validate`，不占用会话、不查询 DNS 或联网。向导保存失败停留原窗口；导入与恢复默认值先写窗口草稿，取消保留源文件和当前配置；导出用 QSaveFile 原子提交当前配置的公开字段；字段清单从默认配置派生，不复制密码、TOTP、其他账户／未知私有键或可能带会话参数的登录 URL。导出不允许覆盖正在使用的配置（包括指向它的符号链接）。

ProfileService 的同一字段映射服务公开 INI、设置／引导草稿及连接入口；窗口从来源快照持有自己的读取对象，取消编辑不改源文件，旧窗口关闭或销毁后的凭据结果不覆盖新窗口输入。状态文件写入失败会保留当前选择；静默启动偏好保存失败会提示并保留草稿。INI 原文在私有临时目录重新解析并随检查清理，避免 Qt 缓存吞掉格式错误后重复尝试改写坏文件；该检查也用于迁移及凭据来源验证。副本用显式权限新建后仅写入内容，不复制源文件元数据，且只读来源保持原样；目录创建和自动清理复用 [Qt 实现](https://raw.githubusercontent.com/qt/qtbase/6.12/src/corelib/io/qtemporarydir.cpp)，不另加平台封装。

配置版本 9 只补齐缺失默认值，保留现有端点、认证、监听禁用值、未知键及其他账户／配置文件。`SettingsMigrator` 集中复制旧分组、标记旧协议待人工确认、移除明确废弃字段和提交版本；失败保留旧版本，退出不抢先写入升级完成。版本高于当前值时不降级或清理未知的新格式。仍需支持旧分组的已发布配置，在验证不再支持这些版本后才能删除这条迁移路径。

配置加载不再读取 INI 密码／TOTP，默认字段也不创建私有占位。访问安全凭据时先迁移旧值并回读确认，再删除旧值；未确认身份的材料只隔离归档。旧缓存文件不自动绑定账号，清理废弃字段不代替迁移；登录 URL 只作内存预览。设置中的“使用系统凭据库记住认证”默认关闭，启用后通过现有核心恢复已验证的票据／Cookie／设备身份。文件菜单的“清除当前账户认证缓存”处理当前选定账户，密码／TOTP 及其他账户保留；关闭记住认证只停止恢复与保存，不代替清除。旧缓存缺少可信账户绑定，不自动投入登录；旧版清理入口默认取消，明确确认后在后台清除当前配置的系统凭据库隔离副本及旧文件；删除失败如实报告，不清除账户缓存或密码。旧迁移保留到停止支持这些旧版本，具体范围见计划。


Windows 的 Fudan 人工验收使用最终提交对应的预览 ZIP，完整解压后运行 `JustConnect.exe`，保留同目录核心 DLL；普通 Intel／AMD 电脑选择 x64，Windows on ARM 选择 arm64。记录提交号、Windows 版本、架构及下列结果，无需提供密码、Cookie、票据、验证码或系统凭据导出。

1. 在设置中选 Fudan，查询并确认服务器返回的 OAuth2 认证项，启用“使用系统凭据库记住认证”后保存。首次连接完成学校认证，记录是否成功及是否出现“认证缓存未保存”。
2. 普通断开后再次连接，记录是否重新出现学校认证。随后从菜单退出，确认程序结束，再运行同一解压目录中的程序并连接，记录重启恢复结果；隐藏窗口不等于退出。
3. 从文件菜单“清除当前账户认证缓存”明确确认，再断开重连，确认需要重新认证。该动作保留密码／TOTP；“清理旧版缓存”只处理未绑定旧材料，不能代替当前账户清除。
4. 如能切换另一账户，分别选择对应公开账户后验证不能复用前一账户的材料；无法测试时记录缺口。有效期不做固定承诺，等待学校自然失效后再记录一次必要认证，不能用手改缓存假冒学校过期结果。

Windows 系统凭据的单条容量有限，超限会明确提示保存未完成，本次连接可继续；出现该提示时重启后重新认证属于当前保存限制，不能记录为恢复通过。Fudan 的学校策略及人工 MFA 须保留真实结果，离线网关回归不能代替。按用户确认的验收范围，不再要求另一台 aTrust 服务器实测；Fudan 由用户自行测试后反馈，本轮实现工作可先结束。

连接初始化报证书错误时，保留 `[core] tls_...` 固定诊断码即可定位：`tls_authentication_failed` 为认证 HTTPS／方式查询，`tls_resources_failed` 为资源请求，`tls_node_probe_failed` 为数据节点探测，`tls_ip_tunnel_failed` 为 IP 隧道。原因分别为 `tls_unknown_authority`（未知 CA）、`tls_hostname_mismatch`（地址不匹配）、`tls_certificate_time_invalid`（过期或尚未生效）及 `tls_certificate_invalid`（其他证书校验失败）。这些代码不含请求 URL、Cookie、票据或证书原文。记住认证开启时，已验证材料在资源／隧道就绪前即可安全保存；后续 TLS／网络失败不等于认证失效，明确失效仍须清除。服务端 online 记录不能证明本地仍在转发；当前 Ubuntu x64 是继承的固定客户端标识，不能据此判断宿主系统。

针对性回归可运行 `ctest --test-dir build -R 'profileservice|profilemanager|credentialaccess|serversettingswidget|settingwindow|configurationguidedialog|settingsmigrator|settingsprofileloader|coreengine' --output-on-failure`；根测试与包构建还运行完整套件，原生宿主检查实际纯校验导出及资源边界。Linux 设置窗口用临时目录操作真实 Qt 按钮／文件对话框，覆盖库校验失败、启动偏好失败、取消导入／重置、导出、废弃字段清理、旧窗口晚到结果及缓存保留；配置／后台回归另验证损坏文件的重复拒绝和修复重试；这些检查不访问校园账号。

## 分支与 Actions

- 日常开发使用 `develop`。每次推送到该分支，`Tests` 工作流在 Windows、macOS、Linux 上构建并验证固定核心、编译应用并运行 CTest，不打包、不发布。
- 向 `main` 或 `develop` 提交 PR 同样运行 `Tests`。本地提交需推送到 GitHub 才会触发 Actions。
- 合并并推送到 `main` 后，`Build packages` 工作流为 Windows、macOS、Linux 的 x64/ARM64 构建、测试并打包，产物在该次 Actions 的 Artifacts 中保留 14 天。
- Windows 产物为 ZIP，内含 `JustConnect.exe` 和依赖；macOS 为 DMG；Linux 为 AppImage。
- 在本仓库发布 `vX.Y.Z`（可带 `-beta.1` 等后缀）的 GitHub Release 后，工作流重建该版本，全部成功后将安装包附加到该 Release。推送 `main` 仅生成 Actions 产物，不自动发布正式版本。
- 可从 `main` 手动运行打包工作流；关闭 `nightly` 时必须提供有效的版本号。手动运行只生成产物，不创建 Release。
- 开发预览：进入 Actions → `Build packages` → `Run workflow`，分支选择 `develop`。此时手动构建六组预览包并运行测试，产物名为 `JustConnect-preview-提交SHA-平台-架构`，在该次运行的 Artifacts 下载，保留 14 天。预览始终使用 nightly 应用版本（忽略 `nightly/version` 输入），macOS 使用临时签名，不执行开发者签名、公证或 Release 上传；普通推送到 `develop` 仍只触发测试。
- 内嵌库使用本仓库 `corelib/`、模块锁及固定工具链，nightly 与正式版本共用相同源码；导入时的上游提交与归档摘要保留在 [来源说明](../corelib/UPSTREAM.md)，不参与下载或补丁应用。

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

需要模块固定版本的 Go、原生 cgo C 编译器、C++17 编译器、CMake 3.20 或更新版本、Qt 6.10 或更新版本（SSO 内存 Profile 的独立 CA 数据库需要此版本），以及 Qt Core、Concurrent、Gui、Widgets、Network、Svg、WebEngineWidgets。

当前本地与 CI 使用 [Qt 6.12.0](https://www.qt.io/blog/qt-6.12-released)，搭配官方为它构建的 [WebEngine 6.140.0 候选版](https://download.qt.io/development_releases/qtwebengine/6.140.0-rc/)，固定二进制构建编号 `6.12.0-0-202609281005`。已确认允许使用这一候选组件以保持三平台统一 Qt 6.12；它尚不能标作 WebEngine 正式版。[WebEngine 从 Qt 6.12 起独立发布](https://www.qt.io/blog/qt-webengine-will-release-separate)，已排除在 Windows 上出现 DLL 接口不兼容的 Qt 6.12／WebEngine 6.11.2 组合。

SDK 操作集中在 [setup-qt](../.github/actions/setup-qt/action.yml)，测试与打包共用。aqt 固定到支持扩展仓库与原生 ARM64 的提交；[组件安装脚本](../scripts/install-webengine.py) 处理新的 `6120/61400` 仓库路径，只下载 WebEngine，保留校验并拒绝未经审核的构建变更，合并后重新定位 SDK。它不下载源码或从源码构建浏览器。

CI 使用当前可用的 Ubuntu 26.04、Windows Server 2025／Windows 11 ARM64 与 macOS 26 镜像；Actions 使用已核对的最新稳定版本。升级时同时验证 SDK、测试和六组预览包，不仅替换版本号。

```sh
cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 3
ctest --test-dir build --build-config Release --output-on-failure
```

无显示服务器的 Linux 环境可设置 `QT_QPA_PLATFORM=offscreen` 运行界面测试。
核心源码维护在 `corelib/`，应用与测试通过 `cmake/CoreLibrary.cmake` 构建同一份库。使用 `corelib/go.mod` 指定的 Go、Python 3.11 或更新版本、原生 C／C++ 工具链；Windows 的 cgo 使用 setup-core-toolchain 中固定校验和的 LLVM-MinGW UCRT，Qt 宿主仍用 MSVC。Unix 链接 Go 静态归档，Windows 从应用目录加载固定 DLL，不搜索外部核心。

CMake 从 ABI 契约生成 C／Go 常量，显式启用 `CGO_ENABLED=1` 和 `cgocheck2`；Go 源码、模块锁、契约、头文件缺失和构建选项变化都会重建。版本取当前 Git 提交及工作树状态，工具链写入 `build/core-toolchain.txt`。连续无变化构建不重新编译核心。CI 缓存使用平台、架构、Go 版本和 `corelib/go.sum`。

```sh
python scripts/test-corelib.py
./build/JustConnect --core-self-test
```

前者校验固定 Go、单模块／依赖锁、生成文件、gofmt、vet 和全部 cgo 包测试。后者直接运行正式应用，通过与界面相同的库入口验证版本／ABI、生产能力、无效输入拒绝和句柄释放，输出 JSON 并以退出码表示结果；无需显示服务器、账号、TUN 或网络，不创建应用日志／配置。Windows 路径为 `build/Release/JustConnect.exe`，macOS 为 `build/JustConnect.app/Contents/MacOS/JustConnect`。

六平台原生 C／Qt 契约及协议测试使用同一 CMake 核心 target，支持的平台执行完整 race；Windows ARM64 的 Go race 不受工具链支持，普通 Go、FFI 和 Qt 回归仍必须通过。部署脚本统一通过 CMake 的 `CoreRuntime` 组件安装运行库、来源提交、Go／C／C++ 工具链记录、许可证和维护说明。包内不再附带旧 CLI、原始源码归档或 Wintun。Linux 的 linuxdeploy 工具以 `scripts/linuxdeploy.json` 固定内容校验和，使用免 FUSE 的提取运行方式。

`Build packages` 保留 main 推送／Release、develop 手动六组预览的触发方式；预览不使用发布签名凭据。工作流解压 ZIP／AppImage、挂载 DMG 后，用 `scripts/verify-package.py` 从临时工作目录、清除 Qt SDK 和库搜索环境后运行正式程序。它检查 ABI／来源／版本、无网络生命周期、全部原生文件架构与依赖来源，拒绝缺失依赖和外部 Qt；Windows 还验证移走包内 DLL 后启动自检失败。报告拒绝 macOS 的绝对 SDK RPATH 并记录实际搜索路径；同时记录程序和 DLL 的 SHA-256、PE 系统版本字段／ELF 所需 GLIBC 和 GLIBCXX／Mach-O 最低版本，以及真实签名状态。macOS 的部署目标由共享 CMake 统一设置，当前跟随 [Qt 6.12 的 14.4 下限](https://doc.qt.io/qt-6.12/supported-platforms.html)，要求所有包内二进制不高于 Info.plist 声明，并严格验签；预览为 ad-hoc，Developer ID 与公证仅在发布凭据齐全时执行。Windows 部署与签名查询使用 PowerShell 7；预览允许明确记录的 NotSigned，损坏签名失败。

Release 核心通过 Go 链接器 `-w` 省略 DWARF 调试信息，保留静态链接所需符号及来源元数据；Debug／RelWithDebInfo 不使用该选项。Windows 部署仅保留产品所需的 English／简体中文 Qt 翻译、WebEngine `en-US`／`zh-CN` 语言包，跳过 QML 调试插件；继续使用完整 WebEngine 运行库、ICU、快照及资源。Windows ZIP 解压后，把已有 WebEngine 测试宿主临时放到包内，在清除 SDK 环境后强制使用包内进程／资源／插件，分别以两种语言加载页面并执行 JavaScript；结束后删除临时宿主，报告记录 `webengine_locales`，发行包不包含测试程序。新增语言时须同步部署范围和包验证；此处不代表 S7-11 的应用翻译已完成。

Linux 最低 glibc 来自实际包内 ELF 的版本需求，不能由 Qt 的理论平台下限推断本项目在旧发行版可运行；GLIBCXX 需求也写入报告。Windows PE 字段同样不能替代 Qt 的 Windows 10 1809／ARM64 Windows 支持要求。旧系统的实际桌面兼容性按后续平台验收执行，不将这些静态检查写成旧系统实机通过。

每次打包另导出同一干净 Git 提交的完整维护源码和校验和（`archive-source.py`），包含实际修改的 `corelib/`、模块锁、构建脚本与许可证。归档附 `source-revision.txt`，可在无 `.git` 的源码树直接用同一 CMake 构建，重建明确报告 `source_state:archive`。六组自检 JSON 与源码归档作为预览／Release 附件。包检查递归拒绝独立 `zju-connect`／`.exe`、`core-provenance` 和 `wintun.dll`（含大小写变体）；对应回归覆盖嵌套文件与旧来源目录。

### 当前 Linux／WSL2 开发环境

本机 SDK 位于 `/home/lioy/.local/share/JustConnect/Qt/6.12.0/gcc_64`，编译器为 `/usr/bin/c++`（GCC 16.2.1），CMake 4.4.4，Ninja 1.13.2。所需的字体、XCB 和 xkbfile 依赖单独放在 `/home/lioy/.local/share/JustConnect/sysroot`，包清单与 SHA-256 保存在其中的 `packages.json`；未修改系统软件包或全局 shell 配置。

本地只安装 `qtbase`、`qtsvg`、`qtdeclarative`、`qttranslations`、`qtwayland`、配套 ICU，以及 `qtshadertools`、`qtpositioning`、`qtserialport`、`qtwebchannel`、`qtwebengine`。QML／Quick 等是 WebEngine 的依赖。未安装 Qt Creator、Qt Tools、源码、示例、离线文档、独立调试符号或可选的 Vulkan／CUPS 开发包；SDK 静态库中附带的调试信息已移除，保留可链接的库和符号。本地 SDK 约 875 MiB，补充运行依赖约 6 MiB，构建目录另计。CI 额外安装 Qt Tools 以提供部署工具。S1-10 收尾已删除无调用的 Qt Core5Compat 构建／链接及 CI 安装依赖，并更新 SDK 缓存键；本机既有 SDK 中残留的 qt5compat 不参与构建，本地以禁用该包查找的干净构建验证。上述 SDK 大小为原安装记录，不作为本次精简的体积测量。

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

CTest 按平台由 CMake 注册，可用 `ctest --test-dir build/local -N` 查看当前清单；`webengine_test` 使用 offscreen 和软件渲染实际加载 HTML 并检查 JavaScript 结果。原生写入的隔离／恢复边界见上方平台验证说明，不能将自动回归写成用户桌面或校园账号实测。

SDK 安装阶段另运行三项 Python 安装器测试，覆盖路径校验、未审核构建拒绝和重复合并／清理；Unix 框架符号链接用例仅在 Unix 上执行。安装器测试需要 aqt，日常应用的 CTest 不需要。

本次 SDK 基线提交为 `794f2be`：[三平台测试](https://github.com/wtalioy/JustConnect/actions/runs/39256137284)与[六组开发预览](https://github.com/wtalioy/JustConnect/actions/runs/39256137984)均已通过；预览包可在后者的 Artifacts 下载。它们验证构建、浏览器运行测试与打包，不代替校园网络或真实桌面验收。

## 任务与验证记录

开始开发时先查看[实施计划](../plan.md)中的当前任务与阶段依赖。实现后更新任务勾选、提交／测试证据及受影响的平台验收结果；代码完成但缺实机条件时保留待验收。

CI 编译、CTest、预览打包与真实校园网络验收分别记录。当前代码结构及封装限制见[架构说明](ARCHITECTURE.md)，后续目标和状态以计划为准；本文维护可执行的构建与发布操作。

当前打包使用本仓库维护的内嵌核心；校园透明访问与自动共存尚未实现。上游高级用法的来源与已采用约束保留在计划参考索引中，原手工配置示例不再作为当前产品的操作说明；新的使用文档随 [S8](../plan.md#s8) 的实测结果补充，README 暂时留空。

S2-03 默认启用服务器证书验证，私有 CA 可在服务器编辑区以 PEM 格式附加。关闭验证需在当前配置显式选择，界面持续提示其影响；没有错误后自动降级。离线网关夹具将测试 CA 送入正式 ABI，实际验证认证、选线和隧道的信任链；独立回归拒绝未知 CA／错误主机名，并检查取消、超时、协议与网络失败。公开 Fudan 查询使用系统信任成功，只取得公开方法元数据，不等于账号登录或校园业务就绪。

系统凭据后端通过 `credentialstore_test`／`coreabi_credentialstore_test` 检查实际系统 API：Windows 用随机的 JustConnect 专属目标读写／更新／删除，匿名登录边界不能读取原账户材料；macOS 用专用临时 Keychain，显式锁定／解锁并在结束时删除。Linux 测试需要 `gnome-keyring`、`dbus-run-session` 和 `gdbus`，运行在没有服务激活目录的私有总线上，使用临时 XDG 目录及加密测试 keyring；另一个私有总线用真实策略拒绝 CreateItem。检查持久化、二进制不变、另一作用域保留和拒绝／锁定后的原值，未连接当前桌面的凭据库。CI 安装这些测试依赖；生产程序使用标准 Secret Service，可用性由当前用户的默认集合及锁定状态决定。

本地测试可通过 `JC_TEST_SECRET_PROVIDER` 指定隔离安装的 gnome-keyring-daemon，必要的提供方库路径通过 `JC_TEST_SECRET_PROVIDER_LIBS` 传给测试子进程；不修改全局环境。仓库不分发 GNOME 提供方。Windows 使用当前用户 Credential Manager，其原生 blob 上限为 2560 字节，超限明确返回 Limit；各后端共同输入上限为 65536 字节。系统库锁定、不可用或拒绝时不创建应用明文副本。界面经串行后台入口访问系统存储；桌面解锁／授权提示仍需真实用户环境验证，核心票据生命周期继续按 S2-08 验收。

系统 API 依据：[Secret Service](https://specifications.freedesktop.org/secret-service/latest-single/)、[Windows Credential Manager](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)、[Apple SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:))。Linux 提供方可以规范化 MIME 提示，因此后端按不透明字节读取，并验证会话、长度及实际回读数据。

`ctest --test-dir build -R '^profilecredentials_test$' --output-on-failure` 验证凭据作用域、密码更新、指定身份删除、版本／损坏数据拒绝、旧 INI 编码迁移、读写失败／回读锁定、来源被替换及真实文件提交失败后的重启重试。测试使用注入的存储端口和真实临时 INI／缓存文件；原生安全存储的证据由独立 `credentialstore_test` 提供，不能把替身当作 Keychain／Credential Manager／Secret Service 实测。未绑定账户的旧缓存使用独立隔离键，测试确认它不会成为任意账户的密码记录。

`credentialaccess_test` 在受控存储调用被阻塞时运行 GUI 事件，检查原生边界调用来自工作线程、串行迁移／保存、首次空配置、旧缓存迁移失败及重试，以及读／写期间切换账户或服务器后的旧结果拒绝。该测试使用真实线程、QSettings 和临时文件，存储端口仍为替身，不覆盖用户桌面的解锁／授权交互。

创建配置副本使用公开草稿，复制后由凭据访问入口生成独立命名空间；保留有效学校／认证／监听和偏好，不继承已保存的密码或其他账户材料。公开草稿在临时目录完成旧分组迁移再发布，源文件不修改。`profilemanager_test` 覆盖实际文件复制、同名目标、缺失／损坏输入及私有字段排除，`settingsmigrator_test` 覆盖旧／未来版本、当前字段优先、原文件不变及非空目标保护。原配置自身升级仍保留未知键及其他账户数据；公开转移与原地升级采用各自的边界。

`coreengineui_test` 的 SSO Cookie 回归使用随机回环端口和仅含公开测试值的 HTTP 服务，验证当前窗口 Cookie 生效、另一窗口不携带它。修复前实际发送了前一窗口的 Cookie；修复后各自的内存 Profile 隔离。Qt 的[无存储名称 Profile](https://doc.qt.io/qt-6.8/qwebengineprofile.html#QWebEngineProfile) 不持久化浏览器数据；旧默认 Profile 本身也是内存模式，本次修复针对窗口间共享状态，不声称旧实现写了浏览器 Cookie 文件。

界面凭据回归使用注入存储端口与实际 Qt 控件，不访问用户的系统条目。`coreengineui_test` 覆盖不记住的内存登录、记住后的安全写入、原生读写失败仍手动启动、取消／切换后的晚到读拒绝和读取完成后的当前 TLS 策略；`settingwindow_test` 覆盖凭据清除、空密码保留、单独更新 TOTP、导入／重置取消与公开导出；`configurationguidedialog_test` 检查安全读写、手机号、SSO 页面和实际配置写入失败。`credentialaccess_test` 另外验证窗口销毁后已授权保存仍完成、公开草稿过期拒绝及锁定时禁止重新绑定遗留密码。各测试保留独有的失败和边界回归。

S2-05 的回调回归使用两个受控 TLS 服务，先复现私有会话头被送往另一来源，再验证 CAS／OAuth2 均在发出请求前拒绝；同时验证正确网关的回调交换及门户票据、默认／自定义端口、IPv6、用户信息、片段、重复／坏编码和控制字符。可运行 `go -C corelib test ./client/atrust/auth`。实际浏览器回归使用已配置的私有回环 HTTP 网关，验证同源错误路径、iframe 和非法导航拒绝，正常内部 iframe、OAuth2 重定向及 CAS 地址栏回调仍可交付；使用页面 console.error 先复现脚本文本进入应用日志，再验证专用 Page 抑制输出且脚本仍执行；不访问校园账号或使用明文远程 IdP。

浏览器 TLS 使用 [Qt 6.10 的 Profile CA 接口](https://doc.qt.io/qt-6.10/qwebengineprofilebuilder.html#setAdditionalTrustedCertificates)，通过无存储名称创建窗口私有 Profile；[Qt 实现](https://raw.githubusercontent.com/qt/qtwebengine/6.10/src/core/profile_adapter.cpp) 将该形式保持为 off-the-record，不因配置 CA 改用磁盘 Profile。真实协议宿主在受控 HTTPS 网关中验证默认拒绝、学校 CA 成功、后续默认窗口仍拒绝及当前会话快照；另一同主机端口使用相同测试证书，检查页面、样式及同源地址重定向都不能继承网关的证书例外，同时验证同源样式生效，另一主机也仍校验。测试服务统计外部请求必须为零，不仅检查界面布尔值；原有正常协议、SMS、SOCKS／HTTP 与停止检查仍保留。
