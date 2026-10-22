# S1-06：Go／Qt 链接与权限原型

本文件保留 S1-06 的工具链结论与设备权限证据。S1-03 已交付正式 ABI，旧模拟 ABI 原型已被替代并删除；后续链接回归统一测试真实库。S1-08 将应用接入正式内嵌库；校园会话和新安装包仍按各自阶段验收。

## 链接与回归

唯一宿主入口为 [tests/coreabi](../tests/coreabi/CMakeLists.txt)，构建命令和契约检查见 [CORE-ABI.md](CORE-ABI.md)。Go 版本从 `corelib/go.mod` 读取，Qt 复用应用 SDK。正式库检查头文件、版本、来源、缓冲区所有权、257 轮生命周期及四个 QThread 并发调用，同时执行 GUI 定时器和 WebEngine HTML／JavaScript。认证驱动复用相同导出与传输，验证输入覆盖／Go GC、回应、取消与重启。Release 中检查仍生效，构建启用 `GOEXPERIMENT=cgocheck2`。

[Core ABI](../.github/workflows/coreabi.yml) 在六组原生 runner 上执行宿主和 Go 回归；支持 race 的五组平台运行 race，Windows ARM64 的限制单独记录。Unix 固定 `c-archive`，Windows 固定随包 `c-shared` DLL，不再每次重试已经确认会超时的 Windows archive。Windows cgo 沿用 SHA-256 固定的 LLVM-MinGW UCRT，C++ 仍用 Qt 对应的 MSVC／Visual Studio 链接器；DLL 从可执行目录加载并保持到进程退出，不跨 CRT 分配／释放。工具链、构建、宿主与 Linux 设备日志统一上传为 `coreabi-平台-架构` artifact。

### 历史链接选型证据

以下是旧原型在删除前的原始验证记录，保留用于解释 D5 的选择；源码可从对应提交读取。

| 目标 | 链接结论 | 证据 |
| --- | --- | --- |
| Linux x64 | `c-archive` 本地及 CI 通过 | WSL2 本地 GCC 16.2.1；原生 ubuntu-26.04 GCC 15.2.0 |
| Linux ARM64 | `c-archive` CI 通过 | 原生 ubuntu-26.04-arm，GCC 15.2.0 |
| macOS x64 | `c-archive` CI 通过 | 原生 macos-26-intel，AppleClang 21.0.0.21000101 |
| macOS ARM64 | `c-archive` CI 通过 | 原生 macos-26，AppleClang 21.0.0.21000101 |
| Windows x64 | `c-shared` CI 通过；静态链接成功，但首次 Go 调用 60 秒超时 | LLVM-MinGW Clang 23.1.3 UCRT → MSVC 19.51.36260／VS 18；[定位及 DLL CI](https://github.com/wtalioy/JustConnect/actions/runs/39272524508)，257 轮检查与 WebEngine JavaScript 通过 |
| Windows ARM64 | `c-shared` CI 通过；静态链接成功，但首次 Go 调用 60 秒超时 | 原生 windows-11-vs2026-arm，LLVM-MinGW Clang 23.1.3 UCRT → MSVC 19.51.36260／VS 18 |

以上六组均对应代码提交 `481c61b` 的[链接原型 CI](https://github.com/wtalioy/JustConnect/actions/runs/39272524508)，均使用 Go 1.27.2，并实际通过前述 257 轮、4 QThread、GC、缓冲区与 WebEngine 检查。同提交的[三平台应用 CI](https://github.com/wtalioy/JustConnect/actions/runs/39272524710) 也全部通过，每平台 16 项 CTest。本地 `go vet`、actionlint 1.7.12（仅忽略其目录尚未收录的 runner 标签）与差异空白检查通过。

Windows 静态路径的已知线索：固定 Go 的 [PE 链接器 `addInitArray`](https://go.dev/src/cmd/link/internal/ld/pe.go) 生成 `.ctors`，而 [MSVC CRT 初始化](https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-initialization?view=msvc-170) 使用 `.CRT$XCU`。两组定位日志均已确认静态宿主完成 Qt 初始化后，卡在首次 Go ABI 调用且不返回；构造段约定的归因仍属源码推断。不调用 Go 的私有启动符号或改写 archive 的节区来作为正式方案。DLL 初始化及同一份回归在两组均通过，故 D5 的原型选择为 Unix 静态、Windows 固定随包 DLL；正式核心及打包仍由 S1-05—09 复验。

上述历史原型没有执行 race detector。当前契约与 FFI 的覆盖、race 支持范围统一记录在 [CORE-ABI.md](CORE-ABI.md)；它们仍不能代替正式协议、网络吞吐、权限或安装包验收。

## 设备与权限边界

D2 的设备入口子方案已收敛：Linux／macOS 使用最小授权助手创建 TUN／utun，再将 fd 交给普通宿主；Windows 使用 Wintun 设备助手持有 ring，仅传递受限 IP 包。认证、aTrust、资源分流与核心仍留在 Qt 进程。Clash 的 TUN／系统代理开关不作为此入口的前提。路由优先级、系统 DNS、回环排除及正式助手尚需 S4／S5／S6 验证；原型回包不代表浏览器／终端已自动接管。

| 平台 | 选定的设备与权限边界 | 已验证与剩余缺口 |
| --- | --- | --- |
| Linux | 非持久 TUN，助手创建／配置，通过 `SCM_RIGHTS` 交付 fd；普通宿主拥有数据 I/O，最后关闭 fd 结束设备。 | x64／ARM64 隔离内核原型及本机 WSL 通过普通 uid、零 capabilities、UDP 双向和正常／强杀后的设备及显式路由清理。直接创建仍需权限；正式 Go／Qt、授权与 AppImage 路径、完整路由／DNS 恢复待验收。 |
| macOS | utun kernel control，助手创建／配置，`SCM_RIGHTS` 交付已连接 fd；数据含四字节地址族头。 | x64／ARM64 一次性 runner 通过普通 uid／gid、原生组核对、无法恢复 root、实际 UDP 及正常／强杀清理。正式宿主、签名／桌面授权与系统 DNS 仍待验收。 |
| Windows | 官方固定哈希／签名 Wintun 0.14.1；助手拥有适配器和 ring，同账户普通权限宿主通过私有 IPC 处理 IP 包，不跨进程强转会话指针。 | x64／ARM64 设备步骤通过真实普通权限回包、超大帧拒绝和按原始 PnP 实例／路由确认清理；源码 `1105671` 的完整六组 ABI 检查通过。正式 Qt IPC 身份验证、性能、助手授权与驱动分发待验收，应用尚未带入此运行库。 |

权限分析起于[导入基线](../corelib/UPSTREAM.md#导入基线)及其锁定依赖；S1-07 已删除无产品调用、直接修改宿主网络的旧系统 TUN 栈，不再恢复该实现或由核心直接改路由／DNS。新助手只承载实际需要的设备／网络操作，不能成为任意命令提权入口；具体操作必须回读并按所有权恢复。

2026-10-22 只读复查确认：当前 [Wintun 驱动](https://git.zx2c4.com/wintun/tree/driver/wintun.c) 在注册 ring 的 IOCTL 内再次按调用者执行 `SeAccessCheck`，使用只授予 SYSTEM／Administrators 的固定描述符；[StartSession](https://git.zx2c4.com/wintun/tree/api/session.c) 还在本进程分配 ring 内存。因而只传递设备 HANDLE 不能证明普通宿主能注册 ring。隔离实验验证最小设备助手拥有 ring、仅交付受限 IP 包 I/O 的路径；认证、aTrust 与分流继续留在 Qt 宿主。已选择该设备 I/O 路径，正式 Qt 数据面／性能／授权未验收，不恢复已删除的旧 TUN 栈。当前 Windows 只读发现 Sangfor 虚拟接口处于 Up，另有 Meta、Tailscale、WSL 和其他覆盖接口；未修改日常网络，接口存在不作为认证有效的证据。

数据接入须复用现有分流语义：[gVisor 拨号](../corelib/stack/gvisor/dial.go)分别保留 aTrust TCP 与 L3 路径，授权规则由[共用拨号层](../corelib/dial/dialer.go)按域名、IP、协议和端口匹配。现有 gVisor 已独占读取 [L3Conn](../corelib/client/atrust/l3conn.go) 的共享入站队列，不能另开一个连接给 TUN 竞争同一队列。系统 IP 路由本身不能区分端口；透明前端还须处理捕获范围内不走校园的流量，并保持其实际原出口及保护范围，不能全部绑定物理网卡或直接将每个包写入校园 L3。设备探测通过只解决入口权限／生命周期，这些接入与策略仍须另验。原型保留直连与显式主机路由两种数据路径，显式路由只绑定新设备，回读后才发送测试数据，并沿用关闭／强杀后的全路由清理断言；清理同时要求实际设备消失和原接口零路由，不能以“接口 down”代替清理。

本机只读快照 `build/reports/windows-original-network.json` 保留实际接口／地址、路由与 DNS，含 26 条接口／地址族记录、608 条路由和两条既有 NRPT 规则。Tailscale、WSL 和 Meta 均有 IPv4／IPv6 路径；Meta 包含两条分割默认路由，不能把它们当成目标保护范围。Sangfor 接口处于 Up，关联 518 条活动路由，接口别名并不包含厂商名，须结合接口索引与硬件描述核对。此快照只作调查证据，正式应用前仍需重新读取并校验；既有规则／接口不得被猜测归属或自动清空，接口存在不证明认证有效。

<a id="windows-device-probe"></a>
### Windows 设备助手隔离实验（S4-01／D2）

[设备原型](../tests/platform/windows_device_probe.go) 仅在一次性 CI 中创建随机名称的专用适配器，使用官方 Wintun 0.14.1 的公开 API。下载包固定 SHA-256 为 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`，运行前核对 WireGuard 签名并保留随包许可证；不修改 DLL 或提取内嵌驱动，应用交付尚未引入该运行库。

助手只持有 ring 和新设备；同账户的普通权限／medium integrity 子进程通过继承的匿名管道处理一组限定测试 IP／UDP 端口的数据包，不加载 Qt 或 aTrust。根据 [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken) 的句柄权限继承语义，显式取得创建进程和降低完整性所需权限；使用 `LUA_TOKEN` 降为普通用户令牌，取消管理员 SID 的允许权限并移除可删除特权；仅手动降低完整性和移除特权不足以证明 UAC 降权。验证原始 UDP socket 经设备、普通进程及助手回注收到回包，拒绝超大 IPC 帧，检查正常关闭和助手被终止后的设备／路由消失。

独立控制进程先安装只约束设备助手的 Job 生命周期，再恢复其主线程；异常时仅清理本次随机名称及创建时捕获的 Wintun PnP 实例。此 Job 不管理 VPN 核心，原型不修改既有接口、DNS 或默认路由。本机只运行五项原生只读／令牌／帧边界检查及拒绝本机设备操作的入口检查。[源码 `1105671`](https://github.com/wtalioy/JustConnect/actions/runs/39681929870)的 Windows x64／ARM64 设备步骤已通过普通权限真实回包、超大帧拒绝，以及正常／强杀后的原始 PnP 实例和显式路由清理；六组完整 ABI 与三平台 Tests 同样通过，日志／SDK 来源元数据随各组 artifact 保存。

适配器／路由读取使用 x/sys 的 IP Helper API；创建时按 LUID／GUID 捕获原始 PnP 实例，删除后用 Configuration Manager 查询同一实例。接口表可保留 Down 元数据，不能按名称或一般 Down 状态猜测实体设备已删除。固定 PowerShell 配置操作及安全恢复均有操作／管道等待期限；证据直接写入文件，真实超时子进程已验证部分输出仍保留。设备结果不代替校园 TCP、性能、授权界面、Qt IPC 身份校验或生产路由／DNS 恢复；正式实现接入后保留独有内核故障回归，删除被替代脚手架。

<a id="mihomo-api-probe"></a>
### Mihomo 控制接口隔离核对（D3 前置）

2026-10-22 使用本机 Clash Verge 所带的 Mihomo `v1.19.32 windows amd64`（Go 1.26.8，`with_gvisor`），二进制 SHA-256 为 `3c107d54ef1b895e4980b53f517d52f3c1137101fa2637347c9ce343fc50d7b2`。[探测脚本](../tests/platform/mihomo_api_probe.py) 只启动并管理自己的临时实例：随机回环控制端口及密钥、关闭 TUN 和代理入口、两个自有回环 DNS 替身，不读取用户配置、订阅或控制密钥，不修改系统路由／DNS。控制端口即使碰撞，也须先通过随机规则标记核对所属实例后才允许写入。

| 操作 | 实际回读 |
| --- | --- |
| 无密钥访问 | HTTP 401 |
| Fake-IP DNS 监听与 `/dns/query` | 同一实例的实际 DNS 包返回测试 Fake-IP 范围，API 返回自有上游的真实 A 地址；可作为控制连接解析的候选，尚未接入产品 |
| `PATCH /configs` 修改 mode | 生效 |
| 同一 PATCH 传入 rules／dns | 返回成功但均未生效；分别用规则列表和不同 DNS 替身的真实回答核对 |
| TUN 关闭时 PATCH 排除测试网段 | 回读包含指定范围，TUN 仍关闭；不代表开启时的实际绕行已验证 |
| `PUT /configs?force=true` 提交完整 payload | 规则、mode 和 DNS 回答均切换；无效规则返回 400，保留上次有效版本；恢复初始完整配置后回读一致 |

复现：在目标平台使用 Python 运行 `python tests/platform/mihomo_api_probe.py <mihomo可执行文件>`；当前本机结果保存在 `build/reports/mihomo-api-windows-v1.19.32.json`，进程、监听、临时配置和日志随测试结束清理。请求使用[官方 API](https://wiki.metacubex.one/api/)公开路径，不依据 HTTP 成功码推断所有字段可增量修改。`GET /configs` 没有完整规则／DNS／代理定义，因此不能用该响应拼出用户全量配置后盲目 PUT；正式联动仍须验证配置来源、外部改写与所有权恢复、运行中 TUN 实际流量，以及其余平台／目标版本。D3 保持待验收，不据此修改运行中的 Clash。

### Linux 设备／fd 原型复现

[unix_device_probe.py](../tests/platform/unix_device_probe.py) 使用 Python 标准库与现有 `ip` 命令，测试内核权限与 fd 所有权，不把结果写成 Go／Qt 数据面已经接入。脚本拒绝在宿主网络命名空间运行；隔离命名空间内只创建测试 TUN 及其直连测试网段，不配置 DNS 或外部出口。

```sh
sudo unshare --net -- "$(command -v python)" tests/platform/unix_device_probe.py --uid "$(id -u)"
```

当前 WSL 本机不依赖 sudo，可从普通用户 shell 使用 WSL 自带的 root 启动入口执行同一测试：

```sh
wsl.exe --distribution archlinux --user root --exec unshare --net -- \
    python /home/lioy/JustConnect/tests/platform/unix_device_probe.py --uid 1000
```

父进程创建 TUN 并配置隔离地址后，接收进程先清空补充组并降为普通 uid／gid，再接收 fd；父进程关闭原 fd。接收进程读取内核发出的 UDP 包，再经 TUN 注入合法 IPv4／UDP 回包，由普通 UDP socket 验证收到预期数据。分别验证主动关闭与持有 fd 时被 SIGKILL 后的设备／自动路由清理。本地另验证了宿主命名空间／非 root 调用及测试设备名已存在时会被拒绝，以及测试前后宿主接口、全表路由和 `/etc/resolv.conf` 一致。代码 `7a910de` 的 [Linux x64／ARM64 CI](https://github.com/wtalioy/JustConnect/actions/runs/39275742177) 两组均通过同一隔离测试，日志保存在各组 artifact 的 `linux-device.log`。

同提交的[六组库链接／宿主检查](https://github.com/wtalioy/JustConnect/actions/runs/39275742177)和[三平台应用回归](https://github.com/wtalioy/JustConnect/actions/runs/39275741690)均通过；Windows／macOS 在本次仅重跑链接与宿主回归，没有执行设备权限测试。

该测试只覆盖内核设备与 fd 生命周期；直连路由随设备删除不等于已经实现任意路由／DNS 的所有权恢复。它没有验证提权界面、助手身份认证、Go fd 接收、TCP 转发、校园隧道或 Clash 共存。Windows 本机为 x64 普通用户，WSL root 不代表 Windows 管理员权限；没有据此进行 Windows 驱动安装或 UAC 提权。

### Linux 原出口与更具体的捕获路由

[隔离检查](../tests/platform/original_route_linux.py)只在新的网络命名空间中创建 veth 原网络、独立 TCP／UDP 回显端点及非持久 TUN。目标的 `/32` 捕获路由优先于原网络 `/24`；接口绑定单独使用在严格反向路径检查下已复现超时，因此测试保留 `rp_filter=1`，仅为所选原地址增加源规则与专用目标路由表。先回读两类选路并实际读取 TUN 包及捕获源地址，再由零 capabilities 的普通用户运行[生产 underlay 探针](../tests/platform/original_route_probe.go)，验证指定原接口的 TCP／UDP 往返及原地址，接口缺失必须报错。两端命名空间退出即释放设备和规则；宿主接口、全表路由、规则、DNS 及反向路径设置保持不变。

本地 WSL 隔离内核及 [Linux 双架构 CI](https://github.com/wtalioy/JustConnect/actions/runs/39732640460) 已通过，日志为 `linux-original-route.log`，关键结果归并至计划引用的当前报告。该结果验证出口绑定与定向源规则的组合，正式后端尚未应用这组操作；未覆盖其他策略路由选择器、自动选择、IPv6、Windows／macOS 的竞争路由或正式助手恢复，不能据此接管日常网络。

### macOS utun／fd 隔离实验

同一 [Unix 原型](../tests/platform/unix_device_probe.py) 在 macOS 使用 kernel control 分配全新 utun，按 [Apple 公开定义](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.h)取得接口名并处理四字节地址族头。仅允许一次性 GitHub macOS runner，以 root 创建／配置测试点对点地址，再经 `SCM_RIGHTS` 将 fd 交给已设置普通 uid／gid 和明确附加组后 exec 的全新 Python 进程；复用 Linux 的实际 UDP 双向、主动关闭及持有 fd 时 SIGKILL 检查。测试目的已有非默认路由时拒绝运行，结束后检查接口和其全部路由消失，不改系统 DNS／默认路由。接收方逐阶段确认权限、两条路由通信及最终 fd 所有权，共用原八秒预算；避免 [macOS 上不安全的 fork 后原生调用](https://docs.python.org/3/library/os.html#os.fork)，不延长等待或跳过数据与清理检查。

[源码 `1105671` 的两组 macOS 及 Linux](https://github.com/wtalioy/JustConnect/actions/runs/39681929870)均通过直连／显式路由的真实设备／fd 读写、正常关闭及强杀后的设备／路由清理，日志分别为 `macos-device.log`／`linux-device.log`；本机 Linux 另验宿主接口、路由、DNS 不变。降权验证使用原生 `getgroups` 读取进程组，仅保留目标主组，并检查真实／有效 uid、gid 和无法恢复 root；[Python 的 macOS 组查询](https://docs.python.org/3/library/os.html#os.getgroups)可能返回目录成员列表，不能据此判断 `setgroups` 的结果。签名助手与真实桌面授权仍待验收，不依据源码或 Linux 结果宣称可用。原 `linux_device_probe.py` 已由共享脚本替代并删除，原 Linux 能力及独有权限断言保留。

Qt／WebEngine 宿主保持普通用户权限。CI 的网页加载验证只覆盖同进程 Go 运行时和浏览器子进程共存，不能替代真实桌面沙箱／UAC／授权取消验证；不通过禁用 WebEngine sandbox 解决权限问题。真实设备验收至少记录：设备创建、非提权宿主收发、重复关闭、宿主崩溃后的设备／路由／DNS 残留、拒绝／取消授权，以及 Windows ARM64 原生驱动行为。任一平台未证明数据路径交付前，不继续依赖该路径的网络接管。

依据：[Go build modes](https://pkg.go.dev/cmd/go#hdr-Build_modes)、[cgo 指针规则](https://pkg.go.dev/cmd/cgo#hdr-Passing_pointers)、[Qt 对象线程规则](https://doc.qt.io/qt-6/threads-qobject.html)、[Linux TUN 设备权限与生命周期](https://docs.kernel.org/networking/tuntap.html)、[Apple utun control 注册](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.c)、[Wintun ring 分配／注册与释放](https://git.zx2c4.com/wintun/tree/api/session.c)、[Wintun API](https://www.wintun.net/)、[Qt WebEngine 平台与沙箱说明](https://doc.qt.io/qt-6/qtwebengine-platform-notes.html)。上游文档仅支持可行性分析，不替代对应设备验证。
