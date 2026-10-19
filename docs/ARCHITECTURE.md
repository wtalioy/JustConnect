# 当前代码结构

当前代码仍通过 `QProcess` 运行独立核心。[实施计划](../plan.md#s1)已调整为同仓库维护 aTrust 源码、编成库并通过 C ABI 在 Qt 宿主内调用；这一迁移尚未实现。下文描述现有实现，不能将旧构建通过视为库化验证。

JustConnect 使用轻量级分层架构。界面层通过 Coordinator 组合应用服务和平台实现，避免
`MainWindow` 直接承担连接进程、配置存储及认证窗口的生命周期。

## 目录职责

```text
core/             连接领域模型与状态机，不依赖界面和平台实现
application/      用例、会话及基础设施端口
infrastructure/   QProcess、QSettings、系统代理、文件和更新检查等实现
presentation/     Qt Widgets 界面、对话框和界面流程 Coordinator
tests/            按端口或纯逻辑边界测试各层行为
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

目标边界为 `application/CoreEngine` → `infrastructure/EmbeddedCoreEngine` → JustConnect 内部 C ABI → `corelib/` Go 会话 → `third_party/zju-connect/` 协议实现。Qt 主线程接收结构化事件，数据转发留在 Go 内；凭据、认证回应和策略通过显式接口传入。正式切换时删除核心命令行、文本解析及进程兼容层，不保留两套正式后端。必要的权限助手和独立恢复守护不承载 VPN 核心。

`tests/corelink/` 是 S1-06 的独立工具链原型，通过最小 C ABI 在 Qt／WebEngine 宿主内调用 Go，不是第二套应用后端。它与正式源码／ABI 的实现分开，链接证据和各平台设备权限边界见[原型记录](CORELINK-PROBE.md)。

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
