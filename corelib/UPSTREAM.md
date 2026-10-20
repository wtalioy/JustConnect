# Go 核心来源与维护

`corelib/` 是 JustConnect 自有的单一 Go 模块。协议源码直接在此维护、重构和精简，不是独立程序、插件、嵌套上游模块或 vendor 副本。S1-03 已实现 [C ABI 契约和传输](../docs/CORE-ABI.md)，S1-07 已接入正式会话（平台验收记录见计划）；S1-08／09 已将 Qt 应用、测试及六组打包统一切换到同进程内嵌库。

## 导入基线

| 项目 | 固定值 |
| --- | --- |
| JustConnect 整合日期 | 2026-10-19 |
| 上游 | https://github.com/Mythologyli/zju-connect |
| 提交 | `c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63` |
| 原始归档 | https://codeload.github.com/Mythologyli/zju-connect/tar.gz/c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63 |
| 归档 SHA-256 | `d0f48689be9a63432768f8e228920cfc7371b939281123628a91e583bc847798` |
| 原始模块 | `github.com/mythologyli/zju-connect`，Go 1.25.6 |
| 当前模块 | `github.com/wtalioy/JustConnect/corelib`，固定 Go 1.27.2 |
| 原始 go.sum SHA-256 | `9d3ab7b3f7cf9b04c0d3325b1d18ef1653c7db3c2940fc75415f0bad1945f914` |
| 原始许可证 SHA-256 | `8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef` |

导入范围为原归档中的全部 Go 文件，但不导入独立 CLI 的 `main.go`、`init.go`、`init_test.go`，以及 EasyConnect／Android 的 `mobile/mobile_android.go`。导入时共保留 137 份上游 Go 源文件，含 46 份协议和公共包测试，并暂存当时依赖闭包中的 `configs`、EasyConnect 包和平台文件；这是历史导入基线，不是当前文件数。产品仅提供 aTrust，后续清理见下文。

同时导入 `go.mod`、`go.sum`、根许可证、`internal/ping/LICENSE` 和两份上游 README。根许可证原文保存为 [LICENSE.zju-connect](LICENSE.zju-connect)，上游说明与致谢原文保存为 [UPSTREAM-README.md](UPSTREAM-README.md) 和 [UPSTREAM-README_en.md](UPSTREAM-README_en.md)。未导入上游 Actions、Docker／服务安装配置、示例配置及推广图片；当前源码没有依赖它们的嵌入资源。

S1-05 迁移模块及 Go 导入路径、固定工具链、通过 `go mod tidy`／`go mod download` 重建依赖锁，并添加 JustConnect 的模块集成测试。首次 Windows 回归后，TLS 密钥日志与 PCAP 改用共享的 `internal/privatefile`：写入前收紧已有文件权限，Windows 使用仅当前账户可访问的受保护 DACL，Unix 使用 `0600`；协议实现不变。首次三平台 CI 暴露 Windows 不提供 Unix 权限位：`internal/keylog/keylog_test.go` 和 `underlay/pcap_test.go` 的 `0600` 断言仅在非 Windows 平台执行；文件内容、错误传播和抓包行为测试仍在全部平台执行。不维护指向上游源码的本地 `replace`。历史 `inet.af/netaddr` 替换已随无调用方的系统路由 IPSet 副本删除；当前没有模块替换。

导入时逐文件验证了源码：除上述路径迁移和模块锁外，与校验过的归档一致；许可证和上游说明保持逐字节一致。以后直接提交这里的实际修改，利用本次导入提交和固定归档审查差异，有选择地合入上游修复，不重新下载覆盖源码、不维护外部补丁队列。Go 的外部依赖由 `go.sum` 和 module cache 管理，不提交整个缓存或 vendor。

## 阶段收尾清理

S1-03 后按调用关系删除了 EasyConnect 协议及其三份专属测试，移除通用 gVisor 栈对 EasyConnect 错误类型和进程退出的依赖；aTrust 的数据面与回归保留。删除无调用方的旧 CLI 初始化注册表、`configs` 配置及默认值测试，包括写死校园 resolver 文件的初始化操作。这些是 S1-03 后的历史清理；当时尚有 macOS TUN 调用的 DNS 方法和终止钩子，现已按 S1-07 的实际闭包删除。

`go mod tidy` 删除 etree、utls、gopsutil 及仅由它们引入的依赖，其他协议依赖未升级。gVisor 入站包的较弱前缀断言测试已由完整字节相等、排除未读容量的现有用例覆盖，删除重复用例。aTrust 的 dialer 注入由选项映射及 `SetupContext` 的实际取消回归覆盖，已移除仅断言构造结果非空的旧 API 冒烟测试。S1-07 已将认证交互改由宿主 Handler 接管，删除旧 CLI 及其专属测试。

S1-10 的全仓收尾进一步删除了无调用的旧设备管理 API、L3 元数据编解码辅助函数、resolver getter、报文访问器／标志常量和验证码校验包装。正式回应验证保留在 bridge 契约，认证 Handler／MFA、实际 L3 帧解析、DNS 解析、报文校验与 gVisor 接口不变；资源匹配回归直接调用正式函数，删除只供测试调用的生产包装。删除的代码只使用标准库，无需改变 Go 模块锁。

S1-11 继续删除旧验证码文件路径契约，以及没有运行调用方的握手／anti-MITM 包装、旧 VIP 解码、L3 绕行选项、underlay 查询／超时包装、Android 专属设置及测试报文 setter。正式协议、带 context 的安全／取消路径与错误处理保留；测试改调正式路径，发送帧解码和 conntrack 查询归测试夹具维护。验证码只经 Handler 交付内存图片。Go 依赖闭包仍需要 sing-tun 接口监视、gVisor 数据栈和 MFA，不因没有 CLI 就删减实际依赖；协议的 `mobileId`、进程身份和 User-Agent 是网关字段，保留至真实样本支持变更。六平台性能场景与复现方式见 [构建说明](../docs/DEVELOPMENT.md#atrust-性能基线)。

## 离线验证与已有缺陷

在仓库根目录、使用固定 Go 工具链执行：

```sh
python scripts/test-corelib.py
```

入口检查单一模块、固定工具链、没有远程上游核心依赖、Go 模块校验及构建；验证后要求 `go.mod/go.sum` 不变。按 `go list` 的实际包集合运行完整离线测试（含无测试包），其中 JustConnect 的 `module_test.go` 通过注入 dialer 访问回环 TLS 网关，验证迁移后的真实 aTrust 清单读取与 HTTP 失败传播，不访问校园网或创建 TUN。这项早期清单测试不单独代表会话验收；正式认证、代理、C ABI 和生命周期由新增受控网关／宿主回归验证，真实校园及 TLS 生产策略仍在后续阶段。

S1-07 修复了原始认证测试的错误方法名及 `Session.request` 覆盖调用者 context 的缺陷。请求和认证会话任一取消均中断 HTTP 操作，包括响应体读取；完整认证测试已恢复，验证入口不再存在已知失败例外。可独立运行：

```sh
go -C corelib test -timeout 60s ./...
```

S1-07 已将 aTrust 认证、IP／L3／TCP 隧道的会话失效退出改为错误交付，加入后台工作等待、初始化失败回滚及握手取消，修复 setup 结束误取消维护请求的问题。CLI 的 stdin／浏览器／验证码 HTTP 服务已删除；宿主注入 `authchallenge.Handler`，缺省明确拒绝交互。认证方式查询通过客户端的显式 context 与 underlay 发起，不再另建带隐式文件配置的临时客户端。`corelib.Session` 组合 underlay、客户端、解析器、gVisor 及 SOCKS／HTTP，返回前等待资源清理；正式 ABI 使用同一会话。日志只经注入诊断接口交付固定事件，不改宿主全局日志或输出凭据报文。删除无产品调用的系统 TUN／路由／DNS 操作、Shadowsocks、端口转发、外部站点保活和全局关闭注册表，仅保留当前实际调用的协议及代理路径；SOCKS UDP 绑定、连接和工作也纳入会话，回应失败立即撤销。对应废弃功能的测试随实现删除，安全文件、报文、取消及生命周期回归保留并补充。TLS 的上游兼容默认值和协议身份字段仍按 S2-03／真实校园验证收敛；本单元不新增证书跳过开关。

导入代码 `1611e9c` 已通过来源核对及原 23 包的 Linux 限定基线，并验证新增认证编译错误不会被已知缺陷例外掩盖。[首次推送 CI](https://github.com/wtalioy/JustConnect/actions/runs/39279301877)的 Linux、macOS 限定基线及应用测试通过，Windows 因两处 Unix 权限断言失败；`197ea01` 已修正断言平台范围。2026-10-20 进一步实测发现 Windows 仍保留继承／已有 ACL，现已在共享文件入口修复。本机 Linux 的 24 包限定基线、Windows x64 的 17 个离线测试程序实际运行通过。修复提交 `f9b4111` 的[三平台 CI](https://github.com/wtalioy/JustConnect/actions/runs/39284985278)全部成功：Windows、Linux、macOS 均通过模块及依赖锁校验、全部源码构建、24 包限定离线基线与各 16 项应用测试；Windows ACL 回归也通过 CI。S1-05 源码整合已验收，认证包仍按上述 S1-07 缺陷单独标为受阻，不能把限定基线描述为完整认证套件通过。

Windows 权限验收直接查询真实文件的 DACL，不从 Go `FileMode` 推断 ACL。`underlay/debug_permissions_windows_test.go` 对 TLS 密钥日志与 PCAP 各覆盖新文件、已有 Everyone 完全访问权限、拒绝写入三种情况：新建与重开后均禁止继承，只有当前用户 SID 的单条允许项；拒绝写入返回访问拒绝，原文件不被截断。修复前四个权限收紧用例均失败，修复后六个用例在本机 Windows 通过；同一测试进入 Windows CI。该实现复用现有 `golang.org/x/sys/windows`，无新增依赖；Windows 调试文件在打开期间独占，避免读者与已有文件 ACL 收紧竞争。权限建立失败即返回错误，不输出敏感数据。Unix 同时覆盖已有宽权限文件收紧和清空。

Windows 实现使用微软规定的 [CreateFile 安全描述符](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)和 [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo) 设置当前用户 DACL，并禁止继承；不试图防御拥有接管所有权特权的系统管理员。

## 许可证与分发

导入代码保留上游 AGPL-3.0 许可及 `internal/ping/LICENSE` 中的 MIT 许可；不因目录、模块名或维护方改变而替换版权声明。仓库根部的现有 GPL-3.0 许可证保持不变。

按 [GNU 许可证兼容说明](https://www.gnu.org/licenses/license-compatibility.html)及 [GPL／AGPL 的 FAQ](https://www.gnu.org/licenses/gpl-faq.html)，GPLv3 与 AGPLv3 可按第 13 条组合，AGPL 的网络交互相关要求适用于组合程序。后续分发须保留适用的许可证和声明，提供包含本地实际修改、相关构建／安装脚本和所需依赖的对应源码；不能把未修改的原始归档当作当前实现的源码。S1-09 已将六组包切换为同进程库，并导出含实际修改、模块锁、许可证及构建脚本的完整对应源码。S1-10 删除旧下载／补丁／独立 EXE 校验链路与无调用的 Wintun 分发文件；本表保留导入基线，当前构建使用仓库实际源码和 `go.mod/go.sum`，不重新获取原始核心归档。

S2-03 继续维护认证方法的 authId/subType，并按完整运行时身份选择；查询用例及实际 Fudan 公开元数据证据见计划。认证、节点探测和数据隧道现在共用会话 TLS 策略，默认验证系统信任链与主机名；标准 `*tls.Config` 可由 Go 调用方传入，ABI 提供有界 PEM CA 和显式关闭验证配置。重复握手实现、旧强制不验证断言与无调用配置透传已删除；保留 Sangfor 协议防篡改、取消／失败及真实网络回归。该策略和六组离线宿主／包已验收，不等于完成真实校园账号登录或生产数据节点互通。
