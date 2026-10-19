# S1-06：Go／Qt 链接与权限原型

本原型仅验证工具链与边界，不连接 VPN，不修改路由、DNS 或系统代理，不替换当前 `QProcess` 后端。正式会话 ABI 留给 S1-03；上游源码导入留给 S1-05。

## 链接与回归

入口为 [tests/corelink](../tests/corelink/CMakeLists.txt)，独立 CMake 工程避免把 Go 编译器提前变成现有应用的必需依赖。Go 版本沿用 [manifest](../core/manifest.json) 的 1.27.2，原型无第三方 Go 模块，因而没有 `go.sum`。Qt 沿用当前 6.12.0／WebEngine 6.140.0 候选 SDK。

原型使用整数句柄、固定宽度整数及带长度的字节缓冲区。输入在返回前复制到 Go 内存；Go goroutine 在调用者覆盖输入后执行 GC；输出复制到 C++ 分配的缓冲区，不跨堆分配／释放。四个 QThread 并发进入 Go，事件循环的定时器和 WebEngine HTML／JavaScript 同时工作。检查空输入、内嵌 NUL、64 KiB 边界、空指针、容量不足及缓冲区护栏、无效／过期句柄、重复销毁、未读取即销毁、257 轮创建／读取／销毁和最终句柄数。所有检查在 Release 中同样生效。构建启用 `GOEXPERIMENT=cgocheck2`，没有关闭指针检查。

原型的全局锁只用于这一小型测试，不作为正式会话的并发／取消设计。没有 Go → Qt 回调，后续采用 S1-03 的事件读取与 Qt 排队交付；不得从 Go 线程直接访问 Widgets。DLL 路径由可执行文件目录确定，设置 `PreventUnloadHint`，随宿主退出释放运行时，不尝试卸载 Go。

```sh
# PATH 中须为 manifest 固定的 Go，CMAKE_PREFIX_PATH 指向当前 Qt SDK。
cmake -S tests/corelink -B build/corelink -DCMAKE_BUILD_TYPE=Release
cmake --build build/corelink --config Release --parallel 3
ctest --test-dir build/corelink -C Release -V --output-on-failure
```

Windows 手工复现使用配置参数 `-DPROBE_MODE=c-shared`，并将 `CC` 设为工作流固定的 LLVM-MinGW 本机目标编译器；C++ 仍由 Visual Studio 生成器构建，ARM64 增加 `-A ARM64`。完整的 SDK／编译器安装与两种模式尝试步骤保留在工作流中。

本机额外使用 DEVELOPMENT 中的 Qt 运行依赖环境；相同环境也须用于链接：

```sh
export PATH="/home/lioy/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.2.linux-amd64/bin:$PATH"
export CMAKE_PREFIX_PATH=/home/lioy/.local/share/JustConnect/Qt/6.12.0/gcc_64
export LD_LIBRARY_PATH=/home/lioy/.local/share/JustConnect/sysroot/usr/lib:$CMAKE_PREFIX_PATH/lib
export FONTCONFIG_PATH=/home/lioy/.local/share/JustConnect/sysroot/etc/fonts
```

[Core library probe](../.github/workflows/corelink.yml) 在六组原生 runner 上分别编译并实际执行同一宿主。优先 `c-archive`；Windows 用 SHA-256 固定的 [llvm-mingw 20261006 UCRT](https://github.com/mstorsjo/llvm-mingw/releases/tag/20261006) 编译 cgo，C++ 宿主仍用 Qt 对应的 MSVC／Visual Studio 链接器及默认动态 CRT。Windows 静态宿主构建失败，或明确超时在首次 Go ABI 初始化调用时，才允许尝试 `c-shared`；Go 编译失败、初始化返回后的功能失败或其他运行失败均使 CI 失败。构建日志包含实际工具链、链接错误和运行定位，`selected-mode.txt`／`fallback-reason.txt` 记录选择和回退原因，作为 14 天 artifact 上传；长期结论在本文件和 plan 中保存。Windows DLL 用 QLibrary 直接解析固定 C 导出，不要求 MSVC 读取 MinGW import library，也没有跨 CRT 释放内存。

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

构建原型通过不代表正式 aTrust 核心、取消／超时、事件积压、网络吞吐或安装包已验收。这里没有执行 race detector；指针检查、并发调用和 GC 压力不等于数据竞争检测。正式 Go／FFI 回归与工具链支持范围在 S1-04／09 落实。

## 设备与权限边界

这里核对的是现有上游的 **TUN 候选路径**，不预先决定 JustConnect 必须创建 TUN。Clash 的 TUN／系统代理开关是独立的兼容场景，不能拿它们作为 JustConnect 流量入口的前提；JustConnect 自身采用何种透明入口仍由 D2／S5 原型决定。以下 `EPERM` 或 Wintun 交付缺口只约束对应候选路径，不代表整个透明访问方案不可行。无 Clash 时仍须证明网页与终端流量如何进入同进程核心，不能用 HTTP 代理测试替代这一验证。

核对对象为 manifest 的上游 `c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63` 及其锁定依赖：Unix 使用 `github.com/mythologyli/sing-tun@c04d9db95dc7`；Windows 实际走 `golang.zx2c4.com/wireguard@ecfc5a8d5446/tun` 与 `golang.zx2c4.com/wintun@0fa3db229ce2`，并非 sing-tun 的 Windows 路径。

| 平台 | 源码核对与候选边界 | 当前证据／缺口 |
| --- | --- | --- |
| Linux | `sing-tun.New` 可通过 `Options.FileDescriptor` 接收已创建 fd，跳过设备创建／配置；Go 关闭 `os.File`，最终 fd 关闭后非持久 TUN 自动消失。候选：小助手创建／配置设备，验证对端后通过 Unix socket `SCM_RIGHTS` 交付，Go 独占接收的 fd；助手另负责路由／DNS 和恢复。 | 本地 uid=1000 可打开 `/dev/net/tun`，`TUNSETIFF(IFF_TUN\|IFF_NO_PI)` 返回 errno=1 `EPERM`，关闭 fd 后无遗留设备；`sudo -n true` 不可用。尚未验证提权助手、fd 交付后的非提权读写／关闭、AppImage 路径及退出／崩溃恢复。 |
| macOS | `sing-tun.New` 同样可接收外部 utun fd；创建 utun 的 kernel control 要求权限。候选：授权助手创建／配置，`SCM_RIGHTS` 交付已连接 socket；最后关闭 fd 结束 utun。utun 数据还带地址族头，不能按 Linux 包格式直接套用。 | 仅源码可行性核对，无 macOS 实机授权／传递／数据面证据。`sing-tun.Close` 还会刷新 DNS 缓存，库化时须将需权限的系统操作移到助手，不能只接收 fd 就认为完全非提权。 |
| Windows | `CreateTUNWithRequestedGUID` 在宿主内创建／打开适配器，并调用 `StartSession` 注册 ring；session 包含进程虚拟内存、锁和事件，`End` 与适配器 `Close` 分别清理。单独 `DuplicateHandle` 不能转移这个指针与内存集合，不能把助手创建的 `WINTUN_SESSION_HANDLE` 强转给宿主。 | **现有 Wintun 候选路径的非提权交付尚未证明**：当前公开封装没有接收预创建会话的接口，尚无非提权宿主启动 ring 的实测方案。若采用此入口，需要 Windows x64／ARM64 设备、正常用户及受 UAC 授权的小助手，验证驱动 ACL／ring 注册权限和支持的安全交付办法。不得据此给整套 GUI 提权或把核心放到助手。 |

Unix 的上游 `stack/tun/NewStack` 目前没有传入 `FileDescriptor`，后续必须显式接入设备所有权，并拆开它直接执行的 `ip`／`route`／`ifconfig`／DNS 修改。Windows 的地址、MTU、路由和 DNS 也直接在核心内执行；移到助手后仍需回读结果与按所有权恢复。这些是 S4 的实现范围，本原型不新增任意命令提权入口。

Qt／WebEngine 宿主保持普通用户权限。CI 的网页加载验证只覆盖同进程 Go 运行时和浏览器子进程共存，不能替代真实桌面沙箱／UAC／授权取消验证；不通过禁用 WebEngine sandbox 解决权限问题。真实设备验收至少记录：设备创建、非提权宿主收发、重复关闭、宿主崩溃后的设备／路由／DNS 残留、拒绝／取消授权，以及 Windows ARM64 原生驱动行为。任一平台未证明数据路径交付前，不继续依赖该路径的网络接管。

依据：[Go build modes](https://pkg.go.dev/cmd/go#hdr-Build_modes)、[cgo 指针规则](https://pkg.go.dev/cmd/cgo#hdr-Passing_pointers)、[Qt 对象线程规则](https://doc.qt.io/qt-6/threads-qobject.html)、[Linux TUN 设备权限与生命周期](https://docs.kernel.org/networking/tuntap.html)、[Apple utun control 注册](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.c)、[Wintun ring 分配／注册与释放](https://git.zx2c4.com/wintun/tree/api/session.c)、[Wintun API](https://www.wintun.net/)、[Qt WebEngine 平台与沙箱说明](https://doc.qt.io/qt-6/qtwebengine-platform-notes.html)。上游文档仅支持可行性分析，不替代对应设备验证。
