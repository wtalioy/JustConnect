# Go 核心来源与维护

`corelib/` 是 JustConnect 维护的单一 Go 模块，直接维护协议、认证、分流及数据面；不是外部程序、插件、嵌套模块或 vendor 副本。宿主契约见 [CORE-ABI.md](../docs/CORE-ABI.md)，维护与验证见 [DEVELOPMENT.md](../docs/DEVELOPMENT.md)。

## 导入基线

| 项目 | 固定值 |
| --- | --- |
| 整合日期 | 2026-10-19 |
| 上游 | https://github.com/Mythologyli/zju-connect |
| 提交 | `c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63` |
| 原始归档 | https://codeload.github.com/Mythologyli/zju-connect/tar.gz/c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63 |
| 归档 SHA-256 | `d0f48689be9a63432768f8e228920cfc7371b939281123628a91e583bc847798` |
| 原始模块／Go | `github.com/mythologyli/zju-connect`／1.25.6 |
| 当前模块／Go | `github.com/wtalioy/JustConnect/corelib`／[go.mod](go.mod) |
| 原始 go.sum SHA-256 | `9d3ab7b3f7cf9b04c0d3325b1d18ef1653c7db3c2940fc75415f0bad1945f914` |
| 原始许可证 SHA-256 | `8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef` |

许可证原文保留在 [LICENSE.zju-connect](LICENSE.zju-connect) 与 [ping/LICENSE](internal/ping/LICENSE)。上游作者、贡献者与致谢可从[固定提交的原说明](https://github.com/Mythologyli/zju-connect/blob/c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63/README.md)追溯，包括 EasierConnect、socks2http。原 README 副本不再作为本项目的用户文档随仓维护。

## 维护范围

只保留产品实际使用的 aTrust 协议与共享数据栈。CLI、EasyConnect／移动端、无调用的设备／路由／DNS 管理、端口转发和文件日志入口及其专属测试已清理；外部依赖由 `go.mod`／`go.sum` 固定，不复制整个缓存或重新覆盖源码。

网关协议的进程身份、User-Agent、`mobileId` 等固定身份字段来自已经验证的协议基线，不代表产品支持相应系统；变更须有真实网关证据。认证由宿主注入 `authchallenge.Handler`，无处理器明确拒绝交互；上下文取消、失败回滚与全部工作退出必须保留。日志仅交付固定诊断事件，不输出凭据、Cookie 或原始票据。

原生实现只维护 Windows／macOS：C++ 助手负责提权、系统修改与独立恢复，Go 负责认证、策略和最短数据链。`internal/privatefile` 仅供原生 OpenSSH 测试创建临时私钥，正式核心不依赖它。

## 验证

在受支持系统使用固定 Go 工具链运行 `python scripts/test-corelib.py`，检查 ABI 生成、格式、模块锁、来源、vet、构建与全部离线回归。受控 TLS 网关覆盖真实协议、取消、身份隔离和安全边界；四架构原生 ABI／设备和实际包检查由 CI 执行。真实校园、桌面与系统注销缺口仅在[计划](../plan.md)记录，不用离线成功代替。
