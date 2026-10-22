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

独立控制进程先安装只约束设备助手的 Job 生命周期，再恢复其主线程；异常时仅清理本次随机名称及创建时捕获的 Wintun PnP 实例。此 Job 不管理 VPN 核心，原型不修改既有接口、DNS 或默认路由。本机只运行七项原生只读／令牌／帧／协议边界检查及拒绝本机设备操作的入口检查。[源码 `1105671`](https://github.com/wtalioy/JustConnect/actions/runs/39681929870)的 Windows x64／ARM64 设备步骤已通过普通权限真实回包、超大帧拒绝，以及正常／强杀后的原始 PnP 实例和显式路由清理；六组完整 ABI 与三平台 Tests 同样通过，日志／SDK 来源元数据随各组 artifact 保存。

Windows 设备探针由 CI 选择一个绝对 pwsh 路径，签名检查与设备配置共用该宿主，原 60／30 秒预算不变；配置脚本通过完整 `-Command` 参数执行，不使用交互式标准输入。新设备创建后先通过原生 IP Helper／SetupAPI 核对 LUID／PnP 身份，发送 `allocated`；配置后再次核对同一身份并发送 `configured`，父进程收到第二阶段前不将其视为就绪。配置失败仍保留第一阶段的清理身份，未知／变化／重复阶段不发布就绪；身份补查使用已有原生入口，删除 PowerShell 的设备查找副本。新增受控配置后失败场景，在真实 IPv4 路由出现后退出，仍须验证原 PnP 节点与路由消失；原普通权限收发、超大帧、正常／强杀清理断言及预算保留。本机七项只读／协议回归和 ARM64 交叉编译通过，真实设备场景只在一次性原生 CI 执行，当前增量待两架构验收。


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

[unix_device_probe.py](../tests/platform/unix_device_probe.py) 复用正式 [Linux TUN 分配后端](../infrastructure/platform/linux/tundevice.cpp) 的原生测试程序，再使用 Python 标准库与现有 `ip` 命令验证权限和 fd 所有权；主应用、Go 数据入口及正式授权助手尚未接入。脚本拒绝在宿主网络命名空间运行；隔离命名空间内只创建测试 TUN 及其直连测试网段，不配置 DNS 或外部出口。

```sh
sudo unshare --net -- "$(command -v python)" tests/platform/unix_device_probe.py --uid "$(id -u)" --allocator build/coreabi/linux_tundevice_test
```

当前 WSL 本机不依赖 sudo，可从普通用户 shell 使用 WSL 自带的 root 启动入口执行同一测试：

```sh
wsl.exe --distribution archlinux --user root --exec unshare --net -- \
    python /home/lioy/JustConnect/tests/platform/unix_device_probe.py --uid 1000 \
    --allocator /home/lioy/JustConnect/build/local/linux_tundevice_test
```

父进程创建 TUN 并配置隔离地址后，接收进程先清空补充组并降为普通 uid／gid，再接收 fd；父进程关闭原 fd。接收进程读取内核发出的 UDP 包，再经 TUN 注入合法 IPv4／UDP 回包，由普通 UDP socket 验证收到预期数据。分别验证主动关闭与持有 fd 时被 SIGKILL 后的设备／自动路由清理。本地另验证了宿主命名空间／非 root 调用及测试设备名已存在时会被拒绝，以及测试前后宿主接口、全表路由和 `/etc/resolv.conf` 一致。代码 `7a910de` 的 [Linux x64／ARM64 CI](https://github.com/wtalioy/JustConnect/actions/runs/39275742177) 两组均通过同一隔离测试，日志保存在各组 artifact 的 `linux-device.log`。

同提交的[六组库链接／宿主检查](https://github.com/wtalioy/JustConnect/actions/runs/39275742177)和[三平台应用回归](https://github.com/wtalioy/JustConnect/actions/runs/39275741690)均通过；Windows／macOS 在本次仅重跑链接与宿主回归，没有执行设备权限测试。

该测试只覆盖内核设备与 fd 生命周期；直连路由随设备删除不等于已经实现任意路由／DNS 的所有权恢复。它没有验证提权界面、助手身份认证、Go fd 接收、TCP 转发、校园隧道或 Clash 共存。Windows 本机为 x64 普通用户，WSL root 不代表 Windows 管理员权限；没有据此进行 Windows 驱动安装或 UAC 提权。

当前 Linux 分配入口由 `UnixTunDevice` 的平台实现单独维护：连接 UUID 派生设备名，排他创建非持久原始 IP TUN，回读名称／索引／帧模式；`TUNGETIFF` 的 NO_PI 与 NOFILTER 位复用，因此通过受信系统 `iproute2` 的链路详情核对真实 PI／virtio 头部状态，复用已有平台命令端口，固定参数且不经 shell；对象仅拥有自己的 fd，不接管已有同名设备。创建后的回读失败关闭 fd 并报告可能已修改；原生回读失败及错误 PI／virtio 帧模式注入验证实际接口回滚，活动及无队列持久设备冲突均保留原设备。`SCM_RIGHTS` 接收端使用原子 CLOEXEC，两种 Linux 隔离检查复用此入口，已删除 Python 分配副本。最后一个 fd 关闭的内核生命周期依据 [TUN/TAP 文档](https://docs.kernel.org/networking/tuntap.html)；本地普通 uid 的双向 UDP、正常／强杀清理与原网络不变及 [`a0aec56` 的 Linux 双架构](https://github.com/wtalioy/JustConnect/actions/runs/39761802978)均已通过，不代替完整路由／DNS 恢复或助手授权。

IPv4 配置增量复用 [`UnixTunDevice::createIpv4`](../infrastructure/platform/tundevice.cpp)，只配置这次新建、尚未交付的设备：源／对端须是不同的规范单播 IPv4，使用 `/32` 点对点掩码，MTU 为 68—65535；配置前记录原 MTU／标志／空 IPv4，配置后独立回读完整预期及设备索引。macOS [utun 创建时即可为 UP](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.c)，不把初始 down 当作共有契约；实际状态由原生 ioctl／getifaddrs 读取。失败关闭私有 fd，不交付部分配置；当前不支持更改已交付设备或恢复已有接口。共享设备／原出口脚本及捕获路由检查已移除重复地址／启用命令；Linux 捕获路由由分配方在交付 fd 前调用正式后端，原出口表／规则由独立原生持有进程负责；macOS 目的路由仍保留至对应正式后端接管。

本地 Linux 应用及正式 ABI 构建均通过配置后普通用户双向 UDP、正常／强杀最终 fd 清理；真实配置后的回读错误／MTU 不符故障注入验证设备及全部 IPv4 路由回滚，宿主接口、全表路由／规则、DNS 与 rp_filter 不变。完整应用 45/45、正式 ABI 23/23 通过，报告 `build/reports/unix-tun-configuration.json`；该增量仍待 Linux／macOS 两架构原生 CI，未验收平台不据此继续透明接管。

### Linux 原出口与更具体的捕获路由

[隔离检查](../tests/platform/original_route_linux.py)只在新的网络命名空间中创建 veth 原网络、独立 TCP／UDP 回显端点，并通过同一原生分配后端取得非持久 TUN。目标的 `/32` 捕获路由优先于原网络 `/24`；接口绑定单独使用在严格反向路径检查下已复现超时，因此测试保留 `rp_filter=1`，仅为所选原地址增加源规则与专用目标路由表。先回读两类选路并实际读取 TUN 包及捕获源地址，再由零 capabilities 的普通用户运行[生产 underlay 探针](../tests/platform/original_route_probe.go)，验证指定原接口的 TCP／UDP 往返及原地址，接口缺失必须报错。两端命名空间退出即释放设备和规则；宿主接口、全表路由、规则、DNS 及反向路径设置保持不变。

本地 WSL 隔离内核及 [Linux 双架构 CI](https://github.com/wtalioy/JustConnect/actions/runs/39732640460) 已通过，日志为 `linux-original-route.log`，关键结果归并至计划引用的当前报告。该结果验证出口绑定与定向源规则的组合，这组操作现由下述正式原出口后端接管，其增量仍待原生验收；未覆盖其他策略路由选择器、自动选择、IPv6、Windows／macOS 的竞争路由或正式助手恢复，不能据此接管日常网络。

Linux 路由恢复另在私有命名空间核对了内核删除匹配：`ip route del <prefix> dev <owned> proto <owned> scope link` 拒绝删除设备或协议已变化的路由，但首选源地址被改写时仍会删除，不能视为完整快照的原子比较。正式后端须记录所属资源身份和实际应用结果，恢复前核对完整回读，遇到外部改写保留并报告；回读与删除间的竞争仍需故障验证，不以命令成功代替所有权证明。实验结果已归并至计划引用的当前基线报告。

<a id="linux-source-routes"></a>
### Linux 原出口表／规则后端

[`LinuxSourceRoutes`](../infrastructure/platform/linux/sourceroutes.cpp) 在新建的连接专用 IPv4 表中配置明确目标，源地址必须属于所选原接口；空网关表示直连，非零网关另有所属 `/32` 链路路由。只接受规范 `/2`—`/32`，不提供默认出口或全局私网规则。保留实际原接口／索引、源地址／网关、连接 UUID、表、metric、原先不存在和完整路由／源规则；不改接口地址、MTU、原有路由或 DNS。priority 1 已占用、非标准更早规则或候选表已有路由／引用时拒绝，未知策略不猜测。接口名限安全 ASCII token；自动拓扑选择和其他命名方式仍待接入。

```sh
sudo unshare --net -- build/coreabi/linux_sourceroutes_test --isolated
sudo unshare --net -- python tests/platform/original_route_linux.py --uid "$(id -u)" \
    --probe build/coreabi/original-route-probe --allocator build/coreabi/linux_tundevice_test \
    --routes build/coreabi/linux_sourceroutes_test
```

后端与捕获路由共用规范前缀／主机路由解释及受信 iproute2 检查。全表／规则各限 4096 行、1 MiB，写入前检查新增容量；所属路由建立索引。接受 iproute2 省略 main 表的原生表示，所属专用路由／规则缺少表身份时拒绝恢复且保留记录；合法 blackhole／goto 规则保留。每次应用／恢复各有十秒命令预算，失败回滚独立计时。恢复先按 priority／源前缀／表／协议删除源规则并回读；删除失败、外部新引用或重复身份均保留表和记录。确认删除后重建的同值规则视为外部项；路由删除带设备、协议、scope、metric、非零源地址及适用的下一跳。只忽略已知派生 linkdown／默认 unicast 表示差异，其他已确认外部改写保留，未确认值不猜测删除。

本地双构建验证直连／网关、地址别名、错误所有者／重命名、已有表／规则／外部引用、真实部分批次失败、读回故障、恢复重试、读后源规则改写／同值重建、linkdown、4096 行完整容量及永久降权拒绝。原出口脚本已删除专用表／源规则命令，由独立原生持有进程调用同一后端，原预算／严格反向路径及普通 Go TCP／UDP 断言保留；关闭控制管道后检查原始表／规则完全恢复。Linux 分配方已用同一正式捕获后端替换手写目标路由，详见下节交付检查。当前不证明安装助手、持久恢复、控制器崩溃／断电恢复、IPv6 或任意属性的跨对象原子比较；S4-06 前不应用于日常网络。证据 `build/reports/linux-source-routes.json`；[`1aedf70` 六组原生](https://github.com/wtalioy/JustConnect/actions/runs/39814716256)及[三平台应用](https://github.com/wtalioy/JustConnect/actions/runs/39814716577)均通过。

新实例可通过 `LinuxSourceRoutes::recover` 载入同一启动／网络命名空间的可信所有权记录，再调用既有恢复；快照含启动 UUID、命名空间设备／inode，身份检查使用 `/proc/thread-self/ns/net`。完整结构、规范所有者、派生表／metric、实际设备身份、原先不存在及已确认路由／规则均严格核对；畸形、重复、跨启动／命名空间或超过 2 MiB 的记录不取得部分所有权，不能替换活动实例。失败恢复保留载入记录供重试，已删除后同值重建的外部规则仍拒绝接管。**调用方须先认证权限所有者的受保护记录；不能把用户提供的 JSON 当作授权。** 受保护检查点存储见下文；写前日志、内核操作期间的崩溃协调及服务重启仍未实现，因此不宣称完整持久恢复已交付。

隔离检查在实际持有进程应用源表／规则后将其 SIGKILL，由另一个全新进程读取已交付记录并恢复；先在另一真实网络命名空间验证拒绝载入，再恢复原命名空间的实际内核状态。直连、外部表引用拒绝／移除后重试、未确认应用值、同值重建和 4096 路由完整序列化回读均覆盖。测试模式 `--recover` 仅在 root 私有命名空间接受有界标准输入，不安装为助手；本地双构建及宿主不变证据见 `build/reports/linux-source-recovery.json`，[`94fa653` 的六组原生](https://github.com/wtalioy/JustConnect/actions/runs/39819892215)及[三平台应用](https://github.com/wtalioy/JustConnect/actions/runs/39819892236)均通过。

[`LinuxSourceJournal`](../infrastructure/platform/linux/sourcejournal.cpp) 只从已打开的 root 私有目录描述符操作固定 `source.json`，不接受任意输出路径；目录须为 root 0700，文件须为 root 0600 单链接普通文件，读取／替换／删除拒绝符号链接、硬链接、超限、错连接及已知外部改写。目录独占锁按独立打开描述持有；关闭／进程结束释放锁，不自动删除未恢复记录。完整 UTF-8 JSON 检查点最多 2 MiB，临时文件 fsync 后原子重命名并 fsync 目录；首次发布使用不替换语义，更新／删除前比对文件身份及完整旧字节，已确认删除后重建的同值记录不接管。删除目录同步失败保留已删除事实，重试不误认新文件。

```sh
sudo unshare --net -- build/coreabi/linux_sourcejournal_test --isolated
```

真实文件系统检查覆盖不安全目录、隐式当前目录、并发锁／首次发布、其他连接、文件同步／目录同步故障、删除同步重试、原字节／同值 inode 替换、非私有权限、符号／硬链接及超限保留。原源路由检查把实际已交付快照同步到保护目录，持有进程 SIGKILL 后由全新 `--recover-journal` 进程读取、复用同一后端恢复并同步删除记录；临时目录在永久降权前销毁，预算和权限断言不变。证据 `build/reports/linux-source-journal.json`，本地双构建通过，原生增量待验。**当前只覆盖已交付快照的可靠存储／恢复，尚无应用前写前记录、内核操作与删除状态之间的崩溃协调、正式权限助手或自动恢复进程重启。** 系统代理的宿主强杀恢复也仍待 S2-06／S3-05／S4-06／S7-03 实现，不以此替代。

### macOS utun／fd 隔离实验

同一 [Unix 检查脚本](../tests/platform/unix_device_probe.py) 在 macOS 复用 [utun 平台实现](../infrastructure/platform/macos/tundevice.cpp)，由内核自动分配新接口，按 [Apple 公开定义](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.h)回读名称／索引及零外部标志，使用四字节地址族头。Unix 后端共用所有权声明与原生测试，已删除 Python 的 macOS 分配副本；普通权限创建须拒绝，重复创建保留原 fd／身份。仅允许一次性 GitHub macOS runner，以 root 创建／配置测试点对点地址，再经 `SCM_RIGHTS` 将 fd 交给已设置普通 uid／gid 和明确附加组后 exec 的全新 Python 进程；复用 Linux 的实际 UDP 双向、主动关闭及持有 fd 时 SIGKILL 检查。macOS 控制通道使用 Unix 数据报；单线程测试接收后立即设置 CLOEXEC，Linux 仍使用原子接收，不将前者宣称为原子保证。测试目的已有非默认路由时拒绝运行，结束后检查接口和其全部路由消失，不改系统 DNS／默认路由。接收方逐阶段确认权限、两条路由通信及最终 fd 所有权，共用原八秒预算；避免 [macOS 上不安全的 fork 后原生调用](https://docs.python.org/3/library/os.html#os.fork)，不延长等待或跳过数据与清理检查。

```sh
sudo env GITHUB_ACTIONS="$GITHUB_ACTIONS" RUNNER_OS="$RUNNER_OS" "$(command -v python)" tests/platform/unix_device_probe.py --uid "$(id -u)" --allocator build/coreabi/macos_tundevice_test
```

[`a14ecba` 的六组 Core ABI／设备](https://github.com/wtalioy/JustConnect/actions/runs/39769154866)及[三平台应用测试](https://github.com/wtalioy/JustConnect/actions/runs/39769154825)全部通过。Unix 原生创建方等接收方核对 fd／身份并确认后才释放引用，创建方进程退出后才配置和执行流量测试；两平台均通过普通用户双向 UDP、正常／强杀后最终引用清理，原八秒总预算不变。本地拒绝确认的隔离检查无设备泄漏。早期未确认移交时序下的失败未作底层归因，独有失败片段保留在 `build/reports/unix-tun-backends.json` 的引用中；不将后续通过宣称为已证明某个 macOS 内核缺陷。普通权限设备创建拒绝、CLOEXEC、身份／帧模式、降权和来源检查保留；正式授权助手及完整网络恢复仍待。

<a id="linux-owned-routes"></a>
### Linux 捕获路由后端

[`LinuxTunRoutes`](../infrastructure/platform/linux/tunroutes.cpp) 只为已拥有且配置非零点对点地址的 TUN 新增 main 表 IPv4 `/2`—`/32` 路由，不覆盖已有目标。创建及删除都带连接派生的 metric、设备、数字协议／作用域／表、本地源地址和对端下一跳；回读保留内核完整值，裸 IP 的主机路由与 `/32` 规范前缀等价匹配。命令按已验证字段批量输入，无 shell 或任意命令接口；内核快照最多 4096 行／1 MiB，预先核对应用后容量，不能写入后才发现无法完整回读。

```sh
sudo unshare --net -- build/coreabi/linux_tunroutes_test --isolated
```

原生检查验证实际 UDP 进入 TUN 并在严格 `rp_filter=1` 下回到原 socket、原有默认／分割默认／主机路由不变、重复前缀合并、不同连接拒绝、部分批次失败回滚、回读失败与恢复重试、首次无法确认的值保留记录，以及读回前后改写设备／源地址／下一跳和接口重命名。最后永久降权并清空 capabilities，验证真实内核拒绝写入且未留下路由。恢复批次允许单项保护条件失败后继续清理其他所属项，再回读确认结果；不凭命令退出码推断已恢复。

[`5c57603` 的 Linux 双架构原生 CI](https://github.com/wtalioy/JustConnect/actions/runs/39782590189)均通过该检查，同轮其余四组 Core ABI／设备及[三平台应用测试](https://github.com/wtalioy/JustConnect/actions/runs/39782590442)也通过，证据归并至 `build/reports/linux-owned-routes.json`。主应用／正式授权／持久恢复日志、DNS 及任意属性的读写竞争尚未交付，原出口专用表／源规则已通过双架构原生验收，主应用接入仍待；S4-06 之前不用于日常网络。原出口隔离脚本的专用表／源规则已由正式后端接管。Linux 分配方在交付 fd 前配置同一正式捕获后端的目标路由，将连接／设备／完整实际路由值随元数据交付；接收方对照真实全表，不使用会省略设备字段的按设备筛选输出。两份 Python 手写捕获命令已删除；创建方退出后普通用户双向包、正常／强杀后设备与路由消失、严格 rp_filter 原出口均在本地双构建通过，见 `build/reports/linux-capture-handoff.json`，该交付增量原生矩阵待验。测试仍是隔离调用，不安装为权限助手；macOS 的捕获命令保留至对应正式后端通过。

[源码 `1105671` 的两组 macOS 及 Linux](https://github.com/wtalioy/JustConnect/actions/runs/39681929870)均通过直连／显式路由的真实设备／fd 读写、正常关闭及强杀后的设备／路由清理，日志分别为 `macos-device.log`／`linux-device.log`；本机 Linux 另验宿主接口、路由、DNS 不变。降权验证使用原生 `getgroups` 读取进程组，仅保留目标主组，并检查真实／有效 uid、gid 和无法恢复 root；[Python 的 macOS 组查询](https://docs.python.org/3/library/os.html#os.getgroups)可能返回目录成员列表，不能据此判断 `setgroups` 的结果。签名助手与真实桌面授权仍待验收，不依据源码或 Linux 结果宣称可用。原 `linux_device_probe.py` 已由共享脚本替代并删除，原 Linux 能力及独有权限断言保留。

Qt／WebEngine 宿主保持普通用户权限。CI 的网页加载验证只覆盖同进程 Go 运行时和浏览器子进程共存，不能替代真实桌面沙箱／UAC／授权取消验证；不通过禁用 WebEngine sandbox 解决权限问题。真实设备验收至少记录：设备创建、非提权宿主收发、重复关闭、宿主崩溃后的设备／路由／DNS 残留、拒绝／取消授权，以及 Windows ARM64 原生驱动行为。任一平台未证明数据路径交付前，不继续依赖该路径的网络接管。

依据：[Go build modes](https://pkg.go.dev/cmd/go#hdr-Build_modes)、[cgo 指针规则](https://pkg.go.dev/cmd/cgo#hdr-Passing_pointers)、[Qt 对象线程规则](https://doc.qt.io/qt-6/threads-qobject.html)、[Linux TUN 设备权限与生命周期](https://docs.kernel.org/networking/tuntap.html)、[Apple utun control 注册](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.c)、[Wintun ring 分配／注册与释放](https://git.zx2c4.com/wintun/tree/api/session.c)、[Wintun API](https://www.wintun.net/)、[Qt WebEngine 平台与沙箱说明](https://doc.qt.io/qt-6/qtwebengine-platform-notes.html)。上游文档仅支持可行性分析，不替代对应设备验证。
