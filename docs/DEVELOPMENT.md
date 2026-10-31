# 构建与发布

主仓库为 [wtalioy/JustConnect](https://github.com/wtalioy/JustConnect)，`origin` 用于开发与发布，`upstream` 仅供参考。开发节奏与清理规则见 [AGENTS.md](../AGENTS.md)，进度及实测结论见 [plan.md](../plan.md)；代码职责见[架构说明](ARCHITECTURE.md)，Go 来源与许可见 [UPSTREAM.md](../corelib/UPSTREAM.md)。

## 本地构建

需要 CMake ≥ 3.20、C++17、Python ≥ 3.11、[go.mod](../corelib/go.mod) 固定的 Go 及原生 cgo C 编译器。Windows 原生权限助手使用 C++20，以配合当前 Windows SDK 的 C++/WinRT 头文件；其余目标保留 C++17。Qt ≥ 6.10，组件为 Core、Concurrent、Gui、Widgets、Network、Svg、WebEngineWidgets；先配置 Qt 的 CMake 搜索路径。 SSH 验收另需 PATH 中的 OpenSSH `ssh` 客户端；夹具在临时私有文件中生成一次性身份和已知主机配置，严格核对服务端密钥，不读取用户 SSH 配置。

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

Linux 路由后端与设备分配共用这一受信程序检查。批量命令通过标准输入交付并关闭写端，命令端口保留原有无输入调用；超过管道缓冲区的完整交付／EOF 及内核权限拒绝有针对性回归。路由隔离验证只允许私有网络命名空间，命令与边界见[设备记录](CORELINK-PROBE.md#linux-捕获路由后端)。

Unix 原生分配测试通过同一后端在交付 fd 前配置 IPv4 点对点地址及非默认 MTU，Linux 捕获路由在分配方交付前由正式后端配置，接收方独立核对所属快照与实际全表；脚本保留数据交换，Linux 与 macOS 目的捕获路由均由正式后端管理。Linux 配置后回读故障验证真实接口及路由无残留；macOS 使用一次性 runner。宿主命名空间拒绝和原普通用户／收发／强杀清理断言保留，测试中的 SIGKILL 只针对持有测试设备 fd 的隔离接收进程。原出口探针新增 `--routes build/coreabi/linux_sourceroutes_test`，使用正式专用表／源规则后端；控制管道 EOF 后由持有进程恢复并独立回读原始状态。 受保护快照文件检查使用 `sudo unshare --net -- build/coreabi/linux_sourcejournal_test --isolated`；源路由检查覆盖写前准备、部分写入、应用确认和规则／路由删除前后强杀边界，由新进程从 root 私有记录恢复；删除结果不明且匹配对象仍存在时保留并报告，范围及尚缺的助手／自动恢复服务见[原出口边界](CORELINK-PROBE.md#linux-原出口表规则后端)。

macOS 权限／完整会话回归由 `bash tests/platform/run_macos_networkhelper.sh` 在一次性 runner 运行：同一临时证书签名的普通 Qt／Go 宿主覆盖正常、助手 SIGKILL、服务 `bootout`、授权等待、应用与助手双杀及运行中策略。双杀先停住助手再强杀整个 Qt／Go 与助手，独立守护进程恢复后保留回执，由新应用确认旧回执并取得新 UUID。策略场景复用正式分配器移交另一 utun，先按原检查点恢复其探针捕获，再通过普通进程中的既有 gVisor 处理原网络包；在该接口加入／移除重叠前缀，验证保护、校园选边、切回原网络、缓存地址重捕获及两侧 TCP／UDP。原网络响应带独立标记，并核对两次 TCP／四次 UDP（含空包）和独立校园计数；原始认证／流量计数仍按场景严格核对。root 观察真实回执与设备清单，服务不可用时核对核心结束、utun 释放、责任保留和新连接阻断；重新 `bootstrap` 后确认恢复与清理，再核对新 UUID 并重做系统 DNS／TCP／UDP。新故障等待复用助手操作预算，保留每组原有认证／校园流量计数；详细输出在 `macos-helper/core-*.out`，临时证书／服务不能代替真实桌面批准。 提权等待另测取消后重连与有序退出：提供者持有真实 `AuthorizationRef` 后暂停返回；父进程先交出旧授权的原始引用，并用外部形式回读确认提供者仍持有它；迟到结果释放后应无法重新导入，依据 [AuthorizationFree](https://developer.apple.com/documentation/security/authorizationfree%28_%3A_%3A%29) 的销毁语义确认引用释放，新请求获批前不得产生网络所有权。有序退出走实际 `ApplicationShutdown` 并要求单次认证、零校园数据，公共 TUN 驱动与收发回归共用启动；真实系统授权窗口的显示／关闭仍需桌面验收。

系统代理恢复进程与应用同包，`CoreRuntime` 安装组件在 Windows／Linux 放在宿主旁，macOS 放入 `Contents/MacOS` 并由 macdeployqt 一起重定位。包验证实际运行 `JustConnectProxyRecovery --version` 检查依赖可加载与协议版本，该命令不读写代理；恢复行为由 `proxyrecovery_test` 验证，不以版本输出代替。测试只强杀自己创建的宿主：公共进程／协议夹具覆盖部分失败、外部改写、恢复拒绝、单所有者、坏回复／真实超时及非法／超限输入；Linux 使用私有 GSettings keyfile，macOS 使用私有 SystemConfiguration 文件，Windows 真实 WinINet 强杀仅在一次性 GitHub runner 运行。日常主机不得运行 Windows 原生写入模式。持久快照、受保护记录、新进程恢复及同一客户端有界续接已自动验证；真实注销／桌面授权仍按[计划 S2-06](../plan.md#s2-atrust-配置认证与基础结果)待验，系统代理结果不替代完整网络助手验收。

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

受控网关的流量计数须先于对应回包可见，避免调用方已经收到正确数据却读取旧计数；验证仍同时检查实际载荷、TLS 策略与所属连接，不用放宽计数或等待时间处理该时序。

```sh
python scripts/test-corelib.py
python -m unittest discover -s tests -p '*_test.py'
```

Go 入口校验固定工具链、模块锁、ABI 生成文件、gofmt、vet、构建及全部包测试；显式使用 `CGO_ENABLED=1`／`cgocheck2`，关闭 workspace 和自动工具链切换，依赖来自 Go 缓存与 `go.sum`。Python 安装器测试需要 aqt；普通应用 CTest 不需要。当前本机可使用 `build/s110-python/bin/python` 的现有测试环境。

Tests／Core ABI 的 Linux 显式依赖安装传入 `sudo env NEEDRESTART_MODE=l apt-get install ...`，让 needrestart 按[官方说明](https://manpages.debian.org/testing/needrestart/needrestart.1.en.html#ENVIRONMENT)仅报告待重启服务；ARM64 原生日志已确认该步骤使用报告模式。仍执行依赖安装、库／内核扫描及原有构建、原生和设备检查；此设置只属于该 apt 子进程，不修改发布应用或宿主配置。Qt action 后续自行安装依赖不继承它，仍可能触发服务重启。

### Linux CI 依赖源

三组工作流的 Linux 依赖安装统一先运行 `setup-linux-apt`：从 hosted runner 已配置的镜像列表移除慢的 Azure 项，继续使用其中的 Ubuntu 官方 archive／security 来源；没有该列表的镜像保持原配置。`99a6b87` 的 x64 原生日志记录 Azure 下载 42.2 MB 耗时 15 分 11 秒（46.3 kB/s），原日志归 `build/reports/native-policy-99a6b87/linux-x64.log`。来源格式见 [runner-images 配置](https://github.com/actions/runner-images/blob/main/images/ubuntu/scripts/build/configure-apt-sources.sh)；依赖、签名校验和验收门槛不变，实际提速仍须当前 CI 日志确认。

全量 Go 每包预算与正式 ABI CI 一致为 90 秒。S3 维护／失效回归扩展后，本机 bridge 包约 59 秒；单个网络、取消及退出场景仍保留原有短时限，包总预算留出累计用时和机器调度余量，不扩大场景的失败等待。

## 正式 C ABI 契约验证

固定 Go 与 Qt SDK 就绪后执行：

```sh
cmake -S tests/coreabi -B build/coreabi -DCMAKE_BUILD_TYPE=Release
cmake --build build/coreabi --config Release --parallel 3
ctest --test-dir build/coreabi -C Release --output-on-failure
```

该项目验证正式 C11／C++17 宿主、Qt／WebEngine 共存、受控认证／隧道与代理收发及性能；配置、事件、常量生成和边界见 [CORE-ABI.md](CORE-ABI.md)。六组 CI 在支持的平台执行 Go race；Windows ARM64 不支持 race，普通 Go／FFI／Qt 检查仍执行。回环网关不访问学校账户，也不代替校园／透明接管验收。

支持 race 的矩阵串行测试包，保留平台默认的进程内并行度及原场景时限；矩阵在全量检查后额外执行五次 `TestTUNBoundsFlowsAndJoinsFullCapacityOnShutdown` 与 `TestTUNDNSUsesOwnedPeerAndCampusACL`，保留原 256 流容量、每次关闭一秒及 DNS 查询五秒断言，日志归 `go-race-tun-regressions.log`。DNS 场景复用已建立的同一 owned-peer TCP 连接执行顺序查询，跨帧回复、路由确认、拒绝和关闭仍逐项检查；新握手／重传／转发由实际 TCP 回归覆盖，不为同一 DNS 断言重复建立连接。异步查询将错误送回主测试线程，查询失败必须结束测试，避免工作协程 `t.Fatal` 留下主线程永久等待结果。满容量场景仍创建 256 条真实 UDP 流；其对端仅创建用到的 UDP 协议，TCP／UDP 混合收发继续使用完整真实对端；拒绝及未完成握手场景直接注入有效 SYN，检查实际 RST 元组、确认号与校验和，保留原一秒准备／关闭时限，避免用多余的客户端 TCP 栈竞争被测入口。race 全量与回归集重复失败后仍收集独立 ABI 构建／宿主证据，步骤最终返回原失败；普通测试、配置、构建或宿主失败直接结束。`coreabi_workflow_test` 在临时目录用八种结果验证失败传播及 Windows ARM64 原有能力分支。关闭回归同时记录调度等待、实际清理及总用时；失败输出登记表状态与协程堆栈，不能把竞态检测下的偶发超时直接当作死锁，也不能以重跑代替重复失败的诊断。

同一 Core ABI 工作流在一次性 runner 验证设备权限与正常／强杀清理，范围见[设备记录](CORELINK-PROBE.md#设备与权限边界)。Windows 设备检查先于完整 ABI 构建执行，失败步骤直接保留失败状态；完整矩阵和 Windows 专用模式通过显式状态条件继续收集独立 ABI／应用证据，取消则停止。不能依据 `continue-on-error` 改写后的步骤 conclusion 宣称设备通过；最终强制门槛仍读取原始 outcome，全部必需检查仍须通过。工作流回归另外覆盖八种设备失败／前置失败／取消条件。设备日志同时保留标准输出和错误输出，Windows 直接写入证据文件，超时也保留部分输出；失败不得靠扩大数据期限或放宽清理断言通过。

Windows 设备与普通 Qt／Go 数据面可用 `gh workflow run coreabi.yml --ref <源码引用> -f windows_packet_only=true` 单独验证双架构；该模式复用完整矩阵的同一驱动检查、正式数据面及应用会话目标，不代替最终六组 ABI／三平台 Tests。Wintun 版本、归档校验和、架构、签名者与包内名称由 `resource/network-helper-windows.json` 单一维护，`scripts/windows_helper_sdk.py` 只暂存已校验归档中的对应原生 DLL、许可证和官方头文件，不解压其他条目。实际文件路径由生产者传给测试，不依赖测试构建目录。原生构建、三处强杀／外部冲突检查和受保护安装／真实 SCM 重启在 Qt／Go 下载前执行，保留原时限与数据断言。独立助手项目为 `infrastructure/networkhelper/windows/helper`，依赖 Windows SDK／C++20 及 `WINTUN_INCLUDE_DIR` 指向的已校验官方头文件；构建输入 `JC_HELPER_DRIVER_SHA256`、`JC_HELPER_LICENSE_SHA256` 固定 SDK 载荷，缺失时拒绝安装。`--install` 在管理员授权后安装当前实际映像及固定载荷并注册恢复服务，`--service` 进入 SCM；`--authorize` 是普通权限启动器，`--control` 仅服务绑定实际进程的固定协议。Qt 后置检查使用 `python tests/platform/run_windows_helper.py --qt-control`，与原生检查共用无证书的安装夹具，但不重复无关恢复用例。当前主应用接管及真实桌面 UAC 状态见计划，不以原生部件检查代替产品可用。


## 平台结果契约与隔离验证

测试通过 [SystemIntegration.cmake](../cmake/SystemIntegration.cmake) 按平台注册；`ctest --test-dir build -N` 可查看清单。失败／取消／权限／超时及可能已修改的结果由应用层契约表达，代理快照与所有权恢复规则见[架构说明](ARCHITECTURE.md)。隔离环境要求：

| 平台 | 测试依赖与写入边界 |
| --- | --- |
| Windows | 系统凭据测试使用唯一测试条目，自启动使用唯一 Run 值并清理；代理真实写入仅在临时 Actions runner 的 LAN 执行并恢复，本地仅只读探针与失败夹具 |
| macOS | 凭据使用临时 Keychain；代理使用临时 preferences 文件，仍需预先具备 `sudo -n` 测试权限；登录项脚本用真实 osacompile 编译，不把替身结果算作桌面授权通过 |
| Linux | 需要 gsettings、dbus-run-session、gdbus、gnome-keyring、kreadconfig6／kwriteconfig6（libkf6config-bin）；使用临时 XDG、keyfile／KConfig 和私有 D-Bus，不写当前桌面的代理或凭据库 |

Linux 可用 `JC_TEST_SECRET_PROVIDER` 指定隔离安装的 gnome-keyring-daemon，`JC_TEST_SECRET_PROVIDER_LIBS` 指定其库路径；私有 KDE 工具还需对应 PATH／库路径。用户 preset 可能覆盖环境，必要时直接用 `ctest --test-dir build/local`。工具缺失或授权不足应报告失败，不扩大跳过范围。KConfig 后端在修改前拒绝含凭据的代理 URL，避免密码进入进程参数。

原生凭据验证与使用替身的 UI／账户隔离／晚到结果测试各自保留；桌面解锁、真实授权、Clash 共存和宿主强杀恢复仍按计划单独验收。测试筛选可用 `ctest --test-dir build -R 'credential|profile|setting|coreengine|platform|autostart|systemproxy' --output-on-failure`。

Windows DNS 使用 `JustConnectDnsReader.exe` 的原生 MI 读取，十秒总预算包含进程启动与完整快照，不预热或重试。`JCDNS` 仅保留白名单阶段／计时；可选类缺失、必需提供者失败、空 NRPT、同目录伪造 mi.dll、超时进程清理及 JSON 边界分别验证。生产读取器不含故障参数，测试目标单独启用；本地可用 `JC_TEST_WINDOWS_DNS_READER` 为测试程序指定已构建的 Windows 夹具读取器，经互操作读取真实系统。Windows 原生 CI 验证 MSVC 两架构：现有 `--build-only` 在 Qt／Go 安装前构建同一生产读取器及自检目标，调用既有包校验执行真实读取，失败立即停止，不替代后续 Qt 完整校验；来源摘要归 `build/coreabi/windows-native-dns.json`。三处目标共用 CMake 构建定义及系统库清单，不额外下载 SDK 或增加开关。应用 CI 另从 CoreRuntime 安装目录运行统一 DNS 入口；包检查使用清理后的环境执行实际读取器，并审计其 PE、哈希及签名。旧脚本入口前超时未作底层归因，完整对照及唯一故障证据归并到 `build/reports/windows-dns-native.json`。 设备探针的 Authenticode 与配置共用 CI 选择的绝对 pwsh 路径，包校验同样使用 pwsh 宿主，保留 60 秒、完整 Valid 状态及固定发布者指纹检查，不以归档哈希代替签名。

## aTrust 性能基线

```sh
ctest --test-dir build/coreabi -C Release -R coreabi_performance_test --output-on-failure
```

输出 `build/coreabi/performance.json`，与日志一起保存在六组 Core ABI artifact。正式宿主在正常／每次节点回应额外等待 5 ms 两种场景下，测启动、进程 CPU、200 ms 空闲 CPU、峰值 RSS、20 次认证／连接／停止重绑及一次认证取消；每 5 次重连记录 RSS。TCP 64 KiB × 32、UDP 1200 B × 128，另各 16 次 32 B 往返，逐字节及网关计数校验。

吞吐为单个未完成回声的应用 goodput，非最大带宽；5 ms 不是统一网络 RTT，RSS 为进程历史高水位，20 次重连不能证明长期无泄漏。包报告的离线自检耗时也不等于首屏时间。跨硬件／平台结果仅作各自基线，不据此推断性能优劣。

### S1-11 历史测量基线

代码 `6db2c06` 的[六组 Core ABI](https://github.com/wtalioy/JustConnect/actions/runs/39412404160)已通过。正常节点摘要如下；完整 CPU／时延、慢节点、重连和历史包体积见[固定版本原始测量](https://github.com/wtalioy/JustConnect/blob/9a3b729/docs/DEVELOPMENT.md#s1-11-历史测量基线)，S2-09 瘦身体积见[固定版本测量](https://github.com/wtalioy/JustConnect/blob/adc3c1f/plan.md#s2-09-closeout)，当前实际包报告见[计划基线](../plan.md#当前验收基线)。

| 平台 | 峰值 RSS MiB | TCP／UDP MiB/s |
| --- | ---: | ---: |
| Windows x64 | 39.09 | 114.832／4.271 |
| Windows ARM64 | 40.70 | 27.117／3.612 |
| macOS x64 | 29.11 | 61.476／0.667 |
| macOS ARM64 | 47.73 | 73.831／4.877 |
| Linux x64 | 68.43 | 107.678／4.949 |
| Linux ARM64 | 86.04 | 225.030／5.295 |

## Windows 网卡查询与 CPU 采样

A6 的 `da23405` 实机记录中，DNS Client 峰值 86.3%，新增／删除路由各一批后仍有高占用尾部；WPR CPU 栈约 92.7% 的累计样本经过 NDIS，未取得该系统版本的公开函数符号，不据此确认 DNR 内部缺陷。记录归 `build/reports/windows-dns-cpu-da23405/summary.json`，原始 ETL 保留在用户临时目录。

原网卡快照由 `net.Interfaces` 加逐接口 `Addrs` 组成，Windows 上每次都会整机枚举并查询未使用的 DNS 元数据。当前改为一次原生查询，跳过 DNS 服务器与后缀信息；出口校验和原 DNS 监听准备复用这份读取，绑定 socket 则直接以别名查询 LUID／索引。[DNS 信息跳过标志](https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/types.go)采用 WireGuard 同一平台固定值，不添加旧系统回退。正式 DNS 来源仍由 DNS 读取器完整收集，保持保护、恢复及观察频率。

可用 `go -C corelib test -run '^TestReadInterfacesMatchesSystemInterfaces$' -bench BenchmarkInterfaces -benchtime=3x ./internal/networkstate/windows` 在 Windows 只读比较。 地址夹具按完整通用 sockaddr 分配，另用 `go -C corelib test -gcflags=all=-d=checkptr=2 ./internal/networkstate/windows` 验证指针边界，保留双栈与失败断言。i9-13900HX／32 逻辑处理器单次配对基线：旧查询平均 8489.8 ms，新查询 12.7 ms，各 3 次；实际全接口／双栈地址／状态与原查询一致，描述另与系统接口表核对。它只衡量接口查询耗时，不代表整体 CPU 峰值或连接耗时降幅。

2026-10-30 用户在 Windows 11 26H2 实测 `70f90a5`：接管、断开正常，无恢复错误／重试；DNS Client 各约 15% CPU 持续 1—2 秒，原数十秒高占用尾部消失。日志记录接管 1722 ms（网卡／路由 1609 ms、DNS 94 ms；220 捕获前缀／6 校园 DNS／0 原 DNS 来源），解除接管 211 ms、恢复 134 ms、确认 15 ms、检查 0 ms、关闭 5 ms。峰值／持续时间来自用户任务管理器观察，非新一轮 WPR；前后前缀数和系统状态不同，不据此推定固定加速比例或其他机器结果。校园浏览器／SSH 与 MagicDNS A 不变仍引用此前 `929e24d` 实测，未新增完整发布矩阵结论。

## 数据包转发分配基线

gVisor 出站端点复用依赖自带的 `PacketBuffer.ToView`／`View.Release`，与 TUN 回包链路一致，删除自维护的分片列表／拼包实现；正常、写失败及 panic 都归还临时缓冲。报文头／有效载荷、未读容量隔离、资源拒绝与取消／失败回归保留。

`go -C corelib test -run '^$' -bench '^BenchmarkEndpointWritePackets$' -benchtime=1s -count=3 ./stack/gvisor` 比较 1200 字节分片包的同步空写端点；Go 1.27.2、i9-13900HX，Linux 旧版 400—434 ns／1330 B／2 次分配，改后 107—108 ns／0 B／0 次分配；Windows x64 旧版 328—390 ns，改后 109—122 ns，同样消除每包两次分配。该微基线不含 TLS／网络／路由，不能当作校园吞吐或整体 CPU 降幅；缓冲池冷启动／GC 后可重新分配。日志归 `build/reports/performance-2d0bbd3/packet-write-*.log`。

逐包连接跟踪键使用内部定长二进制元组，保留地址族、协议、源／目标 IP 和端口，不作为日志／IPC／持久化字段；取消对地址与端口的逐包字符串格式化。`go -C corelib test -run '^$' -bench '^BenchmarkConnTrackKey$' -benchtime=1s -count=3 ./client/atrust`：Windows x64 旧版 223—224 ns／112 B／6 次分配，改后 26—29 ns／48 B／1 次分配；Linux 241—245→22—25 ns，分配变化相同。字段隔离、IPv4 等价表示、认证回退及收发状态回归保留；基线不代表整体吞吐。日志归同报告目录的 `conntrack-key-*.log`。

空闲认证扫描按首个实际任务分配批次，并以当前连接数限制容量；扫描频率、重试、超时及批次上限保持原契约。`go -C corelib test -run '^$' -bench '^BenchmarkIdleAuthBatch$' -benchtime=1s -count=3 ./client/atrust` 在 256 条无待办连接下：Windows x64 1218—1465→461—482 ns／次，Linux 1783—1954→449—485 ns；每次 6528 B／1 次分配→0。它消除每条 L3 隧道每秒四次的空批次分配，不改变扫描复杂度，也不外推整体 CPU。日志归同目录的 `idle-auth-*.log`。

域名规则索引在单条命中时复用不可变资源，多条重叠时按总量一次分配并保留更具体规则优先及同组顺序。`go -C corelib test -run '^$' -bench '^BenchmarkDomainResourceMatch$' -benchtime=1s -count=3 ./resolve` 在 1001 条域名规则下，Windows x64 单条命中 375—377→355—357 ns、80 B／1 次分配→0；重叠命中 482—494→477—480 ns、224 B／2 次分配→144 B／1 次分配。Linux 单条命中 384—387→364—368 ns，分配变化相同；未命中均约 12—14 ns／0 分配。此为纯索引查询，不代表整机 CPU／网络吞吐；旧线性扫描替身基准已由实际命中／未命中／重叠基准替换，原始样本归 `build/reports/review-0684a4b/domain-match-*.log`。

完整元组的认证回退复用现有连接索引，只在网关省略请求身份时使用，并校验地址族、协议和初始化元数据；未知显式身份不降级回退。1024 条待认证连接下，`BenchmarkAuthResponseTupleLookup` 在 Windows／Linux 均约 4.4 µs→77—84 ns／0 分配；存储键仍约 22 ns／48 B／1 次分配。L3 接收直接使用响应帧独占缓冲区，仅跨帧残包再拼接；保留交付包的独立所有权。`BenchmarkReadLoopPacket` 经 `io.Pipe` 驱动实际读取／分包／跟踪／交付 1200 字节包，Linux 三次样本每包 3948 B／9 次分配→2668 B／8 次分配，约 2.27—2.35→1.83—1.92 µs；此为本机微基线，未测整体 CPU／网络吞吐。跨帧多包／2000 字节残包回归合并到实际读取循环检查；认证 wire、排队及失败回归保留。样本归 `build/reports/review-0684a4b/{auth-tuple,readloop}-*.log`。

TCP 隧道的带帧写入在同一连接的发送锁内复用缓冲区，容量由现有 65535 字节帧长约束，每个使用该模式的活动连接最多保留 65539 字节逻辑缓冲，raw 模式不分配它。`BenchmarkTCPTunnelWrite` 使用同步空写端点，Linux／Go 1.27.2 三次样本：1200 字节 337—344→23 ns、1280 B／1 次分配→0；32 KiB 7.83—7.91→0.599—0.601 µs、40960 B／1 次分配→0；64 KiB 跨帧写入 15.4—16.3→1.16 µs、73734 B／2 次分配→0。保留超长拆帧、连续／并发写、短写失败与关闭打断回归；基线不含 TLS／系统网络，稳定态零分配不代表首次缓冲分配为零，也不外推 Windows 整体 CPU。24 个原始样本及汇总归 `build/reports/review-0684a4b/tcp-write-*`。

Qt 的核心事件读取在活动会话内复用 ABI 上限为 256 KiB 的缓冲区，终态／解析失败后释放，取消、长度及代次校验保持。L3 空闲探测的写入和等待发送锁共用已有 `interval × missLimit` 预算，超时关闭原传输以触发原重连链路；逐包发送不新增计时器。删除被成功心跳写入持续清零、无法自然累计的旧遗漏计数器，并把直接注入计数器的测试替换为真实写阻塞及发送锁阻塞的超时／重连检查；首轮等待、活动流量抑制、帧格式及控制响应回归保留。

复查按单个桌面用户、现有流量／DNS／事件上限进行，覆盖 Go 数据面／认证／分流、C ABI 调用方、C++ 助手／DNS／路由／恢复，以及 Qt 日志／状态／配置调用链。除上述已测改进外，原网络观察、所有权确认、必要的跨线程／IPC 拷贝及上游协议身份保持；未用减慢观察、扩大路由或冻结控制器发现来换性能。未测的全链路吞吐、RSS 与 macOS／Linux 实机仍按 S8 复核；不把有限检查称作全仓绝对最优。

## 全仓审查与测试保留范围

A8 从 `0684a4b` 起，按单个桌面用户及现有容量上限审查维护源码、实际调用方、构建／CI 和测试注册。产品代码按认证、分流／数据面、ABI、系统助手与 Qt 调用链复查；测试按独有行为、失败／取消、安全、恢复和平台契约核对，必要处深入夹具实现，不以文件数量或逐行形式验证代替运行证据。完整清单和本地原始证据归 `build/reports/review-0684a4b/`，交付版本及必需原生／实际包结果由 [plan.md](../plan.md#当前验收基线)维护。

删除无产品入口的旧 PCAP／TLS 文件采集器、专属测试和选项、重复根模块烟测、无调用报文 API 及不支持平台的空后端；保留真实 TLS、SSH 私钥权限、数据包边界、账户隔离、策略原子性、取消、故障及独立恢复回归。测试工具只在测试链路使用。旧配置与已交付恢复记录仍有实际升级／恢复调用，待结束对应升级支持且确认无恢复责任后删除。权限验证、观察频率及必要所有权拷贝继续保留，未为形式对称增加兼容层或框架。

Qt 配置菜单复用两个既有职责的动作组，连续切换不累积旧组；单实例 IPC 在计算校验和前检查解码状态，畸形短帧不再触发越界读取，正常及分段握手回归保留。macOS 原生 CI 的 TUN DNS 跟踪显示回包已发出，测试客户端却按库默认 2 秒提前于显式 5 秒查询预算结束。夹具现按 context 剩余预算设置 I/O，5 秒总上限及路由确认前不许回复等断言保留；虚拟时间验证 3 秒回包成功和 5 秒到期失败，旧实现两项均在 2 秒失败。生产 DNS 超时不改，不宣称修复运行中调度延迟；有界合成报文轨迹及 goroutine 诊断仅在失败时输出，正常产品无该开销，确认实际根因并不再需要时删除。证据 `build/reports/s6/dns-deadline-*.log` 及 `macos-arm64-tun-dns-failure.txt`。

## aTrust 配置与升级

设置页与引导共用 Fudan／Custom 入口。Fudan 只预填 `vpn.fudan.edu.cn:443`，认证方式从服务器查询，优先 UIS OAuth2；不写死登录 URL／认证编号。保存前使用实际 C ABI 的纯校验接口，不联网、不占用会话。公开字段映射、账户绑定及迁移由既有模块统一维护，详见[架构说明](ARCHITECTURE.md)。

默认验证服务器证书，可附加学校 PEM CA。“跳过隧道证书校验”默认关闭，为所有 aTrust 配置共用；显式开启后只影响探测及 IP／TCP／L3，登录／资源 HTTPS 和认证页面维持原校验策略。隧道仍加密，但失去对端身份验证；不按学校分支或因连接失败自动降级。

“使用系统凭据库记住认证”默认关闭。启用后可恢复有效认证；文件菜单“清除当前账户认证缓存”不删除密码／TOTP 或其他账户，关闭记住认证也不代替清除。旧版缓存只按原账户隔离迁移，不自动投入登录。系统库锁定／不可用时不写明文替代；Windows 单条凭据上限 2560 字节，超限会提示无法保存，本次连接仍可继续。

导入／重置先改窗口草稿，取消不写原配置；导出只含公开字段并拒绝覆盖源配置，不复制密码、TOTP、票据或登录 URL。原地升级保留有效值、未知键和其他账户；失败保留旧版本，未来版本不降级。配置／缓存保留与删除条件见计划的[收尾记录](../plan.md#验证与收尾)。

Fudan Windows 实机验收步骤：启用记住认证并连接；分别测试普通断开、菜单退出后的重启恢复；明确清除当前账户认证缓存后再连接并认证。用户已确认这些场景及手工系统代理后的网页正常，显式代理 SSH 已完成密钥交换；真实过期／MFA 未触发，按确认的 S2 范围不作硬性门槛，处理逻辑与自动回归保留。完整结果统一见 [S2](../plan.md#s2-atrust-配置认证与基础结果)。

当前 `authentication_started` 不能单独证明重新登录，`transport_connected` 只表示通道／本地代理就绪。TLS 阶段及原因等固定诊断码见 [ABI 事件契约](CORE-ABI.md#事件与认证回应)；这些诊断不记录账号材料、原始证书或请求 URL。

已交付的 `8fefd1c` 代理预览仍需手动设置系统代理，或明确启用连接后自动设置；该预览中的 Windows OpenSSH 需显式代理。开发分支的透明入口及未验收项按 plan 单独记录。下面仅为临时诊断，使用现有 Git for Windows `connect.exe`，替换 SSH 主机／别名、安装路径或已修改的 HTTP 端口，保留 SSH 自身信任检查：

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

## 不需申请签名的开发与发行

功能实现、权限助手、开发、预览、main 和 Release 均不依赖需要申请的公开签名或公证；当前工作流不配置签名 Secrets、不注册签名服务，也不向系统导入根证书。未来取得公开签名时，可作为独立发行步骤附加发布者身份，不改变功能、授权、网络或恢复逻辑，也不预建签名服务框架。Windows 使用管理员授权的受保护助手部署；macOS 构建在私有临时目录自动生成本地签名身份，为应用、助手与 WebEngine 签名后销毁私钥和临时钥匙串。本地叶证书有效期十年，仅绑定同一构建的组件，不提供公开发行者信任；成功、失败及取消均清理本次密钥材料。使用 macOS 自带 OpenSSL 导出系统钥匙串可接受的 PKCS#12；Tests 与打包流程在下载 Qt 前用真实 Mach-O 小包验证签名、hardened runtime、应用／助手角色和同一叶证书、深度校验、系统服务注册／撤销及密钥清理，完整 Qt 包另按实际产物验收。系统可能先报告服务未找到，首次连接仍应尝试注册并按真实结果提示用户批准；已有注册不重复安装。

macOS 仍校验相同叶证书、角色标识与 hardened runtime；系统管理员授权、受保护部署、对端身份和网络恢复校验保持。新包的实际身份与系统服务注册已通过原生检查，首次桌面批准仍须实测，不能仅凭脚本通过宣称透明访问可用。系统首次打开／未知发布者提示按平台实际行为记录，不通过关闭系统安全或导入自建根信任消除。

### 无外部证书的 Windows 助手部署

Windows 包单独构建静态 CRT 的 C++ 助手，`WindowsNetworkHelper` 安装组件将助手、官方签名 Wintun DLL 与许可证放在应用旁；普通应用使用动态 Qt CRT。固定 SDK 归档及驱动／许可证 SHA-256 由构建传入，`--version` 的 `identity_ready` 只表示载荷配置完整，不表示已获得管理员授权或发行签名。管理员通过系统 UAC 批准本次助手，安装器固定当前运行映像与源文件身份，核对载荷哈希后复制到管理员／SYSTEM 控制的 Program Files 目录，再注册独立恢复服务。源文件、已安装文件及父目录的句柄、重解析点、所有者与写权限校验保持；同哈希但普通用户所有的文件仍拒绝接管。GUI／Go 不整体提权，控制端点继续绑定 PID／创建时间／SID／连接 UUID。

本地无需生成证书、导入根证书或配置 Secrets。CI 使用实际未签名助手验收受保护安装／复用、驱动与许可证被篡改时写入前拒绝、普通用户不可修改、授权拒绝／取消、独立 SCM 恢复和普通 Qt／Go 数据路径。包验证仍检查官方驱动签名、来源、哈希和依赖；Windows 自有程序允许未签名，已有签名损坏仍拒绝。无证书不消除系统首次打开／未知发布者提示，真实 UAC 交互与实际安装包仍须验收。浏览器、已有终端与 Codex 的普通 SSH 通过同一透明接管访问校园，不要求额外代理或 SSH 配置。


### 只读原 DNS 原生联验

`corelib/service` 的 `TestNativeProtectedOriginalDNS` 可验证实际 Tailscale／MagicDNS 等原 DNS 来源通过核心监听后的 A／AAAA、UDP／TCP 与保护方向；不创建系统 TUN、不安装助手或改系统网络。用当前原生系统的有效规则取得来源／有序服务器，节点的实际名称与地址由已有服务提供，不用夹具地址代替发现。

通过环境变量 `JC_NATIVE_ORIGINAL_DNS_CONFIG` 提供 JSON：`route` 使用 [OriginalDNSRoute](CORE-ABI.md) 的名称规则、服务器端点、实际查询接口／来源标识及 `listen:"127.0.0.1:0"`；`name` 为该范围内的实际节点绝对名称，`addresses` 为节点实际 IP 数组。Windows NRPT 保留系统查询路由，`interface` 为空。可从 `tailscale status --json`、`Get-DnsClientNrptPolicy -Effective` 和对应本地来源取得这些事实，不保存凭据或把此配置加入产品设置。

在原生平台运行 `go -C corelib test -mod=readonly -count=1 -run '^TestNativeProtectedOriginalDNS$' -v ./service`；跨编译时使用 `go test -c` 并将同一环境变量交给目标机器上的测试程序。未提供快照时仅此项显式跳过；提供后必须真正执行。测试把同名校园映射设为不同地址，要求原源答案和原方向发布不被覆盖；各传输的记录数与直接上游比较，包括真实 NODATA，不由节点的 IPv6 地址推断它必有 AAAA。桌面实际接管／恢复仍另验。

### Windows 连接耗时

Windows 日志中的 `network apply stages` 给出所有权记录、设备／路由、DNS 三段耗时及捕获前缀数量；`network apply` 是完整助手操作耗时，认证和交互授权另计。比较同一机器的普通连接／断开，保留这些行即可定位耗时，不能用 CI 延迟代替校园实测。新增路由由系统创建 API 原子拒绝重复项，创建后的身份／属性回读和删除前核对继续保留。

### Windows MagicDNS 实测

[MagicDNS](https://tailscale.com/docs/features/magicdns) 为 Tailscale 设备提供名称。保持 Tailscale 开启，先在 PowerShell 列出已有设备：

```powershell
$ts = tailscale status --json | ConvertFrom-Json
$ts.Peer.PSObject.Properties.Value | Select-Object HostName,DNSName
```

选一条实际 `DNSName`，在 JustConnect 连接前、校园接管就绪后、断开恢复确认后分别运行：

```powershell
Resolve-DnsName '替换为那条DNSName' -Type A -DnsOnly
```

三次应返回相同设备的 Tailscale 地址；若该设备提供 SSH，再用相同名称连接，验证实际访问。记录所用包版本和三个阶段的结果。若 `tailscale` 不在 PATH，可将首条命令中的它改为 `& "$env:ProgramFiles\Tailscale\tailscale.exe"`。此检查不替代校园／普通出口、桌面授权和注销验收。

## 任务与验证记录

每个工作单元先验证、独立提交，再更新任务状态；未完成要求不得提前勾选。CI、安装包自检、受控网关和真实校园／桌面结果分开记录。最新证据只维护在计划，历史过程由 Git 追溯，不在本文追加流水或另存重复历史文档。README 待 [S8](../plan.md#s8-实测与交付) 流程稳定后补写。


### Mihomo 控制连接真实解析

Core ABI 六组原生检查使用 [测试运行时锁](../tests/platform/mihomo-runtime.json) 固定官方 Mihomo v1.19.32 发布资产及 SHA-256；[准备脚本](../tests/platform/setup_mihomo.py) 只写 `build/tools/test-mihomo`，不是产品依赖或安装入口。生产配置不固定 Mihomo 端口或 Fake-IP 网段。

本地复现：`JC_TEST_MIHOMO_BINARY=/absolute/path/to/mihomo go -C corelib test -count=1 -run TestOfficialMihomoRealDNSControlTLS ./underlay`。未提供二进制的普通单元检查跳过该真实运行测试；Core ABI 先准备运行时，准备失败即失败。测试只启动自己的临时实例，关闭 TUN 与所有代理入口，使用自有回环 DNS 和随机控制端口；核对自定义 `198.19.0.0/16` Fake-IP 与 API 返回的真实地址、原域名 TLS 交换及系统解析未被调用，分别执行 TCP 与原生 Unix socket／Windows named pipe。结束只停止自有进程并清理临时文件，不改系统接口、路由或 DNS。

相邻原生进程夹具覆盖端点／创建时间不匹配、密钥保护、重定向、响应上限、CNAME／AAAA、取消与并发初始化；underlay 的完整性测试覆盖认证方式、登录、网关、重连共用拨号路径以及错误 TLS 名称被拒绝。上述均不代表正在运行的 Clash TUN 已完成流量与原出口验证，也不替代桌面或校园验收。


Linux Core ABI 另在全新网络命名空间执行 `mihomo_tun_linux.py`：官方 Mihomo 实际创建 TUN 和捕获规则，独立对端提供真实 DNS／TLS，普通 UID 且零 capabilities 的探针先验证未绑定 TLS 被 TUN 捕获并拒绝，再使用正式 underlay 完成四阶段请求，核对原源地址、域名证书、接口和系统 DNS 未调用。保留 `rp_filter=1`，结束验证捕获解除。脚本拒绝宿主命名空间；只有 CI 隔离验证可运行提权部分，本地只构建探针及核对自有回环对端。结果归 `build/coreabi/linux-mihomo-tun.log`，不替代 macOS／Windows 的运行中 TUN 或真实校园验收。


控制链的 Go 实现或自有 Mihomo 夹具可用六架构专项快速复验：`gh workflow run coreabi.yml -R wtalioy/JustConnect --ref develop -f controller_only=true`。专项复用正式平台矩阵、固定 Go／cgo 和 Mihomo 运行时，执行 underlay／Mihomo／接口绑定的完整普通及受支持 race 测试并上传实际日志；默认 push 仍执行完整 Core ABI。专项只提供控制链证据，ABI、设备、授权和路由等改动仍须对应正式检查，跳过不记为通过。DNS 测试运行时复用正式 UDP／TCP 配对分配器选择共同可用端口，避免 Windows 两种传输的保留区间不同导致监听失败。


macOS 控制专项另验证普通用户从 PID 对应的系统套接字表发现监听，以及自有 root Mihomo 的实际查询。root 夹具仅在 `GITHUB_ACTIONS=true` 的 macOS runner、已准备固定运行时时启动，关闭 TUN、仅开启自有回环 mixed 数据入口，私有配置置于 root 专属目录；Go 调用方保持普通 UID，必须不能读取配置，并通过核验的入口完成实际 TCP／UDP 回包。固定 CI Python 设置进程在 stdin EOF 后停止自己的 Mihomo 并删除临时目录，正常／race 两轮均执行；本地不运行提权部分。

Windows 使用现有进程句柄查询；权限拒绝时，通过 Windows 的公开 `SystemProcessInformation` 获取创建时间，不读取目标内存或提权。高权限 Clash Verge 的端点来自实际 NPFS 目录中的控制命名空间，依据 [Verge IPC 契约](https://github.com/clash-verge-rev/clash-verge-service-ipc/blob/v2.7.6/src/core/paths.rs)；不构造完整路径、枚举连接其他服务或猜测控制端口。打开候选只查询内核服务端 PID，发送 HTTP 前再次核验 PID／创建时间。其他高权限前端的私有 IPC 需要其公开发现契约，不能据此宣称通用支持。

`TestProtectedWindowsControllerRealDNS` 仅限制自有官方实例的进程／配置 DACL，再启动普通权限调用方，必须确认进程查询与配置读取均拒绝、实际发现对应管道并查询原 DNS；结束恢复对象权限并停止自有实例。CI 管理员使用现有普通 token 夹具降低子进程权限；本地普通用户无需提权，不改系统接口、路由或 DNS。原生回归另验证公开创建时间与实际句柄一致、畸形／取消不发布部分身份、旧身份拒绝及无关单连接管道保持未连接。

macOS／Windows 的控制专项另运行 `mihomo_tun_native.py` 与普通权限 `corelib/tests/mihomotun`。在一次性 runner 先直接验证显式测试 URL 的真实 IPv4／TLS、源地址及原路由，再启动关闭代理入口、开启 Fake-IP 与实际 TUN／`MATCH,REJECT` 的官方实例。普通探针核对同域 Fake-IP 和内核路由已进入实际 TUN、未绑定 TLS 被拒绝，然后以应用默认的 `AutoDetect=false` 创建正式 underlay，关闭系统 DNS 来源，验证四阶段各自的新 TLS 连接均保留真实地址、原域名证书、原接口及源地址。最后关闭自有 TUN，核对原路由及未绑定 TLS 恢复。四阶段使用公开测试资源演示同一控制拨号契约，不冒充真实校园认证。

该步骤需要 CI 的系统权限及公开 HTTPS 资源，不能在日常主机运行；本地只编译、执行只读路由／URL 回归与无系统副作用的清理测试。提权设置进程只启动自己的官方实例，父进程 EOF 或看门狗到期均先通过自有控制器关闭 TUN，再停止自己创建的进程；关闭失败必须使步骤失败。控制命令与临时密钥仅属于自有实例，产品控制链继续只读。运行证据为控制专项的 `live-tun.log`，未影响原 SDK 4096 次／30 秒门槛；六组完整设备／ABI 工作流保持原有要求。

网关与校园捕获重叠回归补充默认配置：Linux 原 C++ 源规则／捕获夹具现在同时验证显式接口与 `AutoDetect=false` 加 VPN 地址排除，目标网关处于实际 `/32` 捕获内，仍需普通 UID／零 capabilities、TCP／UDP、严格 rp_filter、缺失接口拒绝和完整恢复。macOS／Windows 的实际 TUN 探针先通过正式 underlay 建立接管前 TLS，随后分别验证控制器真实解析和显式本地 DNS＋VPN 地址排除；两种模式各执行四阶段新 TLS 请求，原源地址／接口／证书与关闭恢复断言保留。它们与常规 Core ABI 共用同一执行体，Windows 始终先完成原签名 SDK 门槛及正式应用检查，再启动可能带有嵌入驱动的上游测试运行时；设备失败继续保留并使任务失败。

### 共存监听所有权基准

Linux / WSL、i9-13900HX，同一真实监听前保留 128 个无关 fd，三次 100 ms 样本的中位值：完整 fd 表复验 0.321 ms／34,559 字节／517 次分配，缓存 PID／监听 inode 的原生复验 0.242 ms／9,792 字节／31 次分配。单次耗时约降 25%，分配字节约降 72%；只度量所有权检查，不代表整体 CPU 或吞吐改善。权限证明只在监听身份变化时请求，真实收发和同端口外部重占拒绝另由隔离 root Mihomo 夹具验证。

复现：`go -C corelib test -run '^$' -bench '^BenchmarkListenerOwnership$' -benchtime=100ms -count=3 ./internal/mihomo/linux`。本次原始输出：`build/reports/s6/listener-owner-benchmark.log`。

macOS 的跨 UID 数据回归核对普通调用方 → root 官方实例 → 自有 TCP／UDP 对端，`d5ddf06` 六架构原生及三平台应用 CI 已通过。TCP 所有权观察改用系统内核 PID 清单；Apple M1 Virtual／darwin arm64 三次 100 ms 样本的中位耗时由旧 `lsof` 清单 13.33 ms 降至 4.72 ms（约 65%），Go 分配字节由约 21.0—21.3 KB 增至 43.2—43.7 KB，因为读取的是全局 TCP 清单。此为组件壁钟耗时和分配比较，不代表整体 CPU／吞吐；保留连接前后的实时 PID／启动身份／监听复验。复现基准：`go -C corelib test -run '^$' -bench '^BenchmarkNativeTCPOwnership$' -benchtime=100ms -count=3 ./internal/mihomo/macos`，CI 原始输出为 `macos-listener-ownership.log`。

Linux 安装助手验收的 `--coexistence-mihomo /absolute/path/to/mihomo` 在同一私有网络中启动 root 官方运行时、普通应用、真实 Secret Service 和私有桌面设置，验证 `CoexistenceNetworkAccess` 的完整调用链。分别启动 blacklist／whitelist／rule 三种 Fake-IP 过滤模式的独立实例：每组通过实际原 DNS 预热 QHostInfo 的 Fake-IP 缓存，再以预先创建的同一 Qt HTTP 客户端执行三种代理模式乘四种系统代理／TUN 组合，共 36 组，连同校园系统 DNS／HTTP／TCP／UDP／OpenSSH、普通 HTTP／SOCKS UDP、受保护网络和有序恢复。组间只在预热前清理隔离解析器的上一组缓存；另测运行中追加／撤回 TUN 排除：校园保持原生接管，普通原生 HTTP 只在排除生效时绕开 GLOBAL REJECT，撤回后恢复原选择；显式 SOCKS UDP 继续遵守代理模式。已有 TUN 的第二次启动显式绑定夹具提供的原接口，因为回环认证服务器没有物理传输套接字，不能冒充自动出口探测证据。私有 mount namespace 为自身网络挂载只读 sysfs，并隔离 `/tmp` 的正式代理锁；结束等待或精确清理自己的恢复进程，不改用户桌面。此为预热过 QHostInfo 缓存的真实 Qt 客户端与隔离系统验收；浏览器自身缓存、剩余平台 V2—V5 与用户实机继续依最终矩阵补验。

Linux 捕获删除检查点的 ptrace 夹具在 fork／vfork 前后暂停所属助手与命令子进程，核对写前记录及内核路由存在／消失后才中断。清理先杀并回收暂停的子进程，再杀助手，沿用总计五秒的原清理预算；这些尚未 exec 的子进程仍继承日志锁，不能让夹具延长持锁时间并与应用恢复竞争。所属进程、两种路由状态、原恢复期限及所有权／无外部写入断言保留。


Windows 的 `TestNativeWindowsSessionCoexistence` 复用普通权限应用／正式 C++ 助手夹具，在一次性提权 runner 启动自己的官方 Mihomo，并读取、切换实际 WinINet 设置。两次完整会话各测三模式乘四开关；每格核对实际内核普通出口接口、校园 DNS／TCP／UDP／OpenSSH 与 Qt HTTP 前置，以及公共 HTTP 基线、GLOBAL REJECT 和受保护回环 HTTP。公共探针沿用 `github.com/robots.txt`，拒绝结果必须先有同一目标的可达基线。回环认证夹具显式绑定事先由内核选出的原接口，不计自动网卡检测；控制写入只发送给核对过 PID 的自有命名管道。结束恢复应用所有权、夹具原 WinINet 标志／地址、DNS／网卡，并核对源配置未改。该新增矩阵当前只通过 Go 双架构交叉编译与工作流检查；Windows C++ 构建／实际运行待原生 CI。

macOS 的 `TestNativeMacCoexistence` 随原正式签名／XPC 助手夹具运行，两次会话各验证 12 组合和实际内核出口、校园 DNS／HTTP／TCP／UDP／OpenSSH、公共出口与受保护回环 HTTP。父夹具只启动自己的 root Mihomo；普通应用复用真实预授权的网络权利和正式 `PlatformSystemProxyBackend`，不改授权数据库。矩阵使用进程内系统代理后端，独立代理恢复进程继续引用既有专项证据，不能把此格说成恢复进程的完整组合验收。父夹具仅在内存备份／恢复本 runner 的 Proxies 字段，不改 DNS／接口字段；失败时先终止可核对父子身份的测试进程、恢复网络责任，再清理自己实例和代理设置。回环认证显式绑定实际原接口，不计自动探测。Go 双架构交叉编译、Python／shell／工作流检查通过；macOS SDK 不在本机，C++ 构建、真实授权和流量组合仍待原生 CI。