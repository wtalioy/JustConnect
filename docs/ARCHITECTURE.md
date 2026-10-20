# 当前代码结构

当前代码仍通过 `QProcess` 运行独立核心。[实施计划](../plan.md#s1)已调整为同仓库维护 aTrust 源码、编成库并通过 C ABI 在 Qt 宿主内调用；这一迁移尚未完成。下文描述现有实现，不能将旧构建通过视为库化验证。

JustConnect 使用轻量级分层架构。界面层通过 Coordinator 组合应用服务和平台实现，避免
`MainWindow` 直接承担连接进程、配置存储及认证窗口的生命周期。

## 目录职责

```text
core/             连接领域模型与状态机，不依赖界面和平台实现
application/      用例、会话及基础设施端口
infrastructure/   QProcess、QSettings、系统代理、文件和更新检查等实现
presentation/     Qt Widgets 界面、对话框和界面流程 Coordinator
tests/            按端口或纯逻辑边界测试各层行为
corelib/          JustConnect 单一 Go 模块；C ABI 与正式会话已实现，Qt 应用待接入
```

依赖方向为：

```text
presentation -> application -> core
       |              ^
       v              |
infrastructure -------+
```

`application` 不引用 `presentation` 或具体的 `infrastructure` 类型。具体实现主要由
`MainWindowCoordinator` 创建并注入：

- `CoreProcess` → `ExternalCoreProcess`
- `SystemProxyBackend` → `PlatformSystemProxyBackend`
- `ProfileBackend` → `ProfileManager`

`CoreProcess` 定义连接配置、事件和错误接口，`ExternalCoreProcess` 负责启动核心与转换进程事件。当前使用 [zju-connect](https://github.com/Mythologyli/zju-connect)；命令构建与输出解析位于 `infrastructure/coreprocess/`。接入其他核心需适配其协议、认证查询、版本检查与打包来源。

目标边界为 `application/CoreEngine` → `infrastructure/EmbeddedCoreEngine` → JustConnect 内部 C ABI → `corelib/` 内的 Go 会话与协议实现。Go 源码已直接整合进 `corelib/`，使用 `github.com/wtalioy/JustConnect/corelib` 单一模块；不另设上游源码目录、嵌套模块或本地 `replace`。协议包可直接维护和精简，[来源与许可证](../corelib/UPSTREAM.md)就地保留。S1-03 已实现独立的 [C ABI 契约与传输](CORE-ABI.md)，包含有界事件、句柄、停止／销毁和认证回应；S1-07 的正式 Runner 调用同模块 `Session`，支持认证方式查询、宿主认证回应和会话启停；受控网关验证协议及代理数据路径，真实校园与 Qt 应用接入仍待对应阶段验收。无调用的旧 CLI 初始化／配置与 EasyConnect Go 实现已删除，通用 gVisor 栈不再依赖具体 VPN 协议包；认证交互保留 `authchallenge.Handler`，CLI 处理器及其 stdin／浏览器接管已删除；aTrust 客户端负责认证维护与隧道后台工作，失效通过错误返回。`Session.Run` 拥有 underlay、认证／隧道、gVisor、解析器及必要监听，退出前等待工作与资源清理；桥接层在该返回之后才允许新代次。必要的 SOCKS／HTTP（含 UDP association）由 `service.Listeners` 统一拥有，诊断通过会话注入且不接管全局日志。无产品调用方的系统 TUN／路由／DNS 修改、外部保活、Shadowsocks／端口转发及全局终止钩子已删除；设备权限脚本独立保留，D2 仍未选型。

Qt 主线程接收结构化事件，数据转发留在 Go 内；凭据、认证回应和策略通过显式接口传入。正式切换时删除核心命令行、文本解析及进程兼容层，不保留两套正式后端。必要的权限助手和独立恢复守护不承载 VPN 核心。

`tests/coreabi/` 直接验证正式 C ABI，同时检查 QThread 并发与 WebEngine 共存；已替代并删除 S1-06 模拟 ABI 原型，避免维护两套契约和链接构建。`tests/platform/` 独立验证 Linux 内核设备权限与 fd 生命周期；历史链接证据及各平台设备权限边界见[原型记录](CORELINK-PROBE.md)。

## 主要流程

- `MainWindowCoordinator` 是主界面的组合入口，并维护 VPN 与系统代理之间的生命周期联动。
- `ConnectionUiController` 处理连接、断开、系统代理按钮及错误展示。
- `AuthDialogCoordinator` 管理登录、sudo、验证码、TOTP 和 SSO 对话框。
- `ConnectionSession` 负责核心进程、重连和连接状态，不依赖具体 `QProcess` 实现。
- `ProfileService` 持有当前配置上下文，`SettingsMigrator` 负责配置版本迁移。

新增代码应按“变化原因”归位：界面行为放入 `presentation`，用例状态放入
`application`，平台或文件 I/O 放入 `infrastructure`，可独立验证的连接规则放入
`core`。不要重新引入通用 `utils` 目录；只有跨多个职责且没有明确归属的代码才需要新建
共享模块。

## 目前的边界限制

上述目录结构不代表所有封装已经完成：

- `ProfileService::settings()` 仍向调用方暴露 `QSettings*`，界面中仍有配置键名和存储操作。
- `AuthInfoWindow` 仍直接调用核心查询认证方式；部分平台函数仍决定错误弹窗，代理后端的成功结果尚未完整反映底层失败。
- 主窗口仍承担配置菜单、托盘和部分工作流；平台代理实现集中在含条件编译的大型源文件中。
- CMake 仍以单一应用源码列表组织构建，目录分层尚未由独立目标与依赖检查约束。

领域与应用层允许使用现有 Qt Core 类型、QObject 和事件机制，与 Widgets 的分离不表示已脱离 Qt。`CoreProcess` 是当前外部核心的应用端口，不是动态协议插件系统。

这些改进的顺序、完成条件和验证状态统一维护在[实施计划](../plan.md)：库链接、生命周期、Qt 适配和旧构建清理见 [S1](../plan.md#s1)，基础结果、认证与配置用例收敛见 [S2](../plan.md#s2)，一键流程和 UI 重设计见 [S7](../plan.md#s7)。库化所需的构建 target 和结构化事件已列为 S1 必需交付；配置读写／校验统一纳入 S2-07，原型、视觉和操作验收纳入 S7-08—10。针对性重构结合实际功能删减重复实现，界面可重新组织布局与操作流程；当前代码仍是原有界面，尚未完成这些改造。目标与当前实现分开记录，代码结构变化后再同步目录和调用关系。
