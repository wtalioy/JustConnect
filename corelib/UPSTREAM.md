# Go 核心来源与维护

`corelib/` 是 JustConnect 自有的单一 Go 模块。协议源码直接在此维护、重构和精简，不是独立程序、插件、嵌套上游模块或 vendor 副本。正式会话和 C ABI 分别由 S1-07、S1-03 实现；当前 Qt 应用尚未切换到这个模块。

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

导入范围为原归档中的全部 Go 文件，但不导入独立 CLI 的 `main.go`、`init.go`、`init_test.go`，以及 EasyConnect／Android 的 `mobile/mobile_android.go`。共保留 137 份上游 Go 源文件，含 46 份协议和公共包测试。保留其包职责结构、版权，以及当前依赖闭包所需的 `configs`、EasyConnect 包和平台文件；产品仍只计划提供 aTrust，这些内部残留在 S1-11 按依赖和回归精简。

同时导入 `go.mod`、`go.sum`、根许可证、`internal/ping/LICENSE` 和两份上游 README。根许可证原文保存为 [LICENSE.zju-connect](LICENSE.zju-connect)，上游说明与致谢原文保存为 [UPSTREAM-README.md](UPSTREAM-README.md) 和 [UPSTREAM-README_en.md](UPSTREAM-README_en.md)。未导入上游 Actions、Docker／服务安装配置、示例配置及推广图片；当前源码没有依赖它们的嵌入资源。

S1-05 迁移模块及 Go 导入路径、固定工具链、通过 `go mod tidy`／`go mod download` 重建依赖锁，并添加 JustConnect 的模块集成测试。首次 Windows 回归后，TLS 密钥日志与 PCAP 改用共享的 `internal/privatefile`：写入前收紧已有文件权限，Windows 使用仅当前账户可访问的受保护 DACL，Unix 使用 `0600`；协议实现不变。首次三平台 CI 暴露 Windows 不提供 Unix 权限位：`internal/keylog/keylog_test.go` 和 `underlay/pcap_test.go` 的 `0600` 断言仅在非 Windows 平台执行；文件内容、错误传播和抓包行为测试仍在全部平台执行。不维护指向上游源码的本地 `replace`。`inet.af/netaddr` 的远程替换沿用上游，用于该外部依赖的实际模块来源，并非另一个 VPN 核心模块。

导入时逐文件验证了源码：除上述路径迁移和模块锁外，与校验过的归档一致；许可证和上游说明保持逐字节一致。以后直接提交这里的实际修改，利用本次导入提交和固定归档审查差异，有选择地合入上游修复，不重新下载覆盖源码、不维护外部补丁队列。Go 的外部依赖由 `go.sum` 和 module cache 管理，不提交整个缓存或 vendor。

## 离线验证与已有缺陷

在仓库根目录、使用固定 Go 工具链执行：

```sh
python scripts/test-corelib.py
```

入口检查单一模块、固定工具链、没有远程上游核心依赖、Go 模块校验及构建；验证后要求 `go.mod/go.sum` 不变。运行 24 个包的限定离线基线（含无测试包），其中 JustConnect 的 `module_test.go` 通过注入 dialer 访问回环 TLS 网关，验证迁移后的真实 aTrust 清单读取与 HTTP 失败传播，不访问校园网或创建 TUN。此测试不代表正式 C ABI、认证、生产 TLS 策略或网络转发已经验收。

**认证包测试仍受阻，不能记录为通过。** 上游 `client/atrust/auth/session_context_test.go:28` 调用了不存在的 `Session.do`。验证入口单独编译这个测试包，只有仍为该条已知诊断时才标为 `BLOCKED`；出现新诊断或该缺陷消失都会失败，要求修复新问题或移除例外，不任意忽略测试失败。全部相关测试原样保留。可直接复现完整套件的现状：

```sh
go -C corelib test -timeout 60s ./...
```

计划已记录：修正测试调用后还会暴露 `TestRefreshCancellation` 的真实上下文缺陷，`Session.request` 当前覆盖请求自带的取消上下文。这些在 S1-07 修复并恢复认证包测试，再实施依赖它们的会话接入。源码中现有的致命退出、全局状态和认证 TLS 默认行为也不能直接当作可嵌入的安全会话；它们仍按 S1-07、S2-03 的边界收敛。

导入代码 `1611e9c` 已通过来源核对及原 23 包的 Linux 限定基线，并验证新增认证编译错误不会被已知缺陷例外掩盖。[首次推送 CI](https://github.com/wtalioy/JustConnect/actions/runs/39279301877)的 Linux、macOS 限定基线及应用测试通过，Windows 因两处 Unix 权限断言失败；`197ea01` 已修正断言平台范围。2026-10-20 进一步实测发现 Windows 仍保留继承／已有 ACL，现已在共享文件入口修复。当前 Linux 的 24 包限定基线、Windows x64 的 17 个离线测试程序实际运行通过，完整三平台 CI 待重验。

Windows 权限验收直接查询真实文件的 DACL，不从 Go `FileMode` 推断 ACL。`underlay/debug_permissions_windows_test.go` 对 TLS 密钥日志与 PCAP 各覆盖新文件、已有 Everyone 完全访问权限、拒绝写入三种情况：新建与重开后均禁止继承，只有当前用户 SID 的单条允许项；拒绝写入返回访问拒绝，原文件不被截断。修复前四个权限收紧用例均失败，修复后六个用例在本机 Windows 通过；同一测试进入 Windows CI。该实现复用现有 `golang.org/x/sys/windows`，无新增依赖；Windows 调试文件在打开期间独占，避免读者与已有文件 ACL 收紧竞争。权限建立失败即返回错误，不输出敏感数据。Unix 同时覆盖已有宽权限文件收紧和清空。

Windows 实现使用微软规定的 [CreateFile 安全描述符](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)和 [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo) 设置当前用户 DACL，并禁止继承；不试图防御拥有接管所有权特权的系统管理员。

## 许可证与分发

导入代码保留上游 AGPL-3.0 许可及 `internal/ping/LICENSE` 中的 MIT 许可；不因目录、模块名或维护方改变而替换版权声明。仓库根部的现有 GPL-3.0 许可证保持不变。

按 [GNU 许可证兼容说明](https://www.gnu.org/licenses/license-compatibility.html)及 [GPL／AGPL 的 FAQ](https://www.gnu.org/licenses/gpl-faq.html)，GPLv3 与 AGPLv3 可按第 13 条组合，AGPL 的网络交互相关要求适用于组合程序。后续分发须保留适用的许可证和声明，提供包含本地实际修改、相关构建／安装脚本和所需依赖的对应源码；不能把未修改的原始归档当作当前实现的源码。S1-09／10 的包和源码分发切换仍须落实这些要求及依赖声明，本次没有发布新核心或替换现有安装包。
