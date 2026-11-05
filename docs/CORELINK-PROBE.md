# Go／Qt 链接与权限验证

当前支持 Windows x64／ARM64、macOS x64／ARM64；产品进程保持普通权限。正式 ABI、来源与生命周期契约见 [CORE-ABI.md](CORE-ABI.md)，平台实现与恢复边界见 [ARCHITECTURE.md](ARCHITECTURE.md)。历史选型可从 Git 追溯，不保留失效命令。

## 链接与回归

[Core ABI](../.github/workflows/coreabi.yml) 在四组原生 runner 验证同一源码。macOS 固定 Go `c-archive`，Windows 固定随包 `c-shared` DLL；Windows 首次 archive 调用超时的历史结论仍有效，不重复试探。Windows cgo 使用固定哈希的 LLVM-MinGW UCRT，Qt 宿主使用 MSVC。支持 Go race 的三组目标执行竞态检查，Windows ARM64 继续执行普通 Go、ABI 与 Qt 检查。

Intel CI 使用 macOS 15，Apple Silicon 使用 macOS 26。Intel macOS 26 运行器的系统图标服务故障会阻塞 Qt 首次窗口聚焦，已由线程采样确认，与[上游问题](https://github.com/actions/runner-images/issues/14751)一致；因此选择可用的原生镜像，不修改产品图标、浏览器或系统服务。该镜像恢复正常后可重新评估，Intel macOS 26 桌面验证仍归 S8。Core ABI 对长时间运行的 macOS 原生测试保留一次线程采样，原超时和失败状态不变。

[当前基线](../plan.md#当前验收基线) 区分自动原生检查、实际包和真实校园测试。回环网关与一次性 runner 不能代替桌面批准、校园访问或真实系统注销。

## 设备与权限边界

| 平台 | 正式路径 | 核对范围 |
| --- | --- | --- |
| Windows | C++ 助手创建官方固定哈希／签名 Wintun 设备和 ring；普通 Qt／Go 经所属私有通道处理 IP 包 | 原 SDK 4096 包／30 秒、正常／强杀恢复、安装与来源、实际路由／DNS、普通进程身份 |
| macOS | C++ 助手创建并配置独有 utun，经 XPC／SCM_RIGHTS 交付 fd；Go 校验并持有自己的副本 | 内核地址／MTU／帧、普通用户 TCP／UDP／DNS／SSH、所有权、助手丢失与独立恢复 |

macOS 运行 `bash tests/platform/run_macos_networkhelper.sh`；设备与正式 ABI 探针分别为 [macos_device_probe.py](../tests/platform/macos_device_probe.py) 和 [tun_coreabi_macos.py](../tests/platform/tun_coreabi_macos.py)。这些写网络的检查只允许一次性 macOS Actions runner，不在日常主机运行。分配器在普通接收方确认后释放自身设备 fd，保留捕获恢复控制与受保护日志；最后引用关闭后核对设备与路由消失。

Windows 使用 `python tests/platform/run_windows_packet.py` 与 `python tests/platform/run_windows_helper.py --qt-control`；固定 SDK、签名检查、普通 token 和实际应用会话共用生产后端，失败不得通过重跑或放宽超时掩盖。

## Mihomo 控制接口隔离核对

官方版本及四架构哈希统一在 [mihomo-runtime.json](../tests/platform/mihomo-runtime.json)。`python tests/platform/mihomo_api_probe.py <mihomo可执行文件>` 在自有实例验证真实解析、Fake-IP 过滤、配置更新失败保留与恢复；控制请求不能扩大校园授权，不修改用户配置文件。

正式控制来源必须核对进程、启动身份及当前监听所有权；Windows 使用原生进程／命名管道身份，macOS 使用内核进程与 TCP 清单。不接受控制器自报地址作为所有权证明。连接前后再次核验监听，端口被外部进程重占时拒绝。

`mihomo_tun_native.py` 与 `corelib/tests/mihomotun` 仅在一次性 runner 创建自有的真实 TUN，先证明未绑定连接被 REJECT，再核对正式 underlay 仍保留真实 DNS、TLS、源地址与原接口；结束撤销自有 TUN 并验证恢复。代理端口的 TCP／UDP 配对、真实收发、受保护网络、原 DNS 与共存切换另由正式应用会话回归覆盖。浏览器自身预热缓存与实际 Tailscale 直连仍按发布矩阵实测。
