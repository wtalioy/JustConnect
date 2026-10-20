# 当前代码结构

JustConnect 将可修改的 aTrust Go 源码直接纳入 `corelib/` 单一模块。Qt 通过版本化 C ABI 在同一宿主内调用正式会话；数据转发留在 Go 内。来源及许可证见 [corelib/UPSTREAM.md](../corelib/UPSTREAM.md)，契约见 [CORE-ABI.md](CORE-ABI.md)。

## 目录与依赖

```text
presentation/     Qt Widgets、认证窗口与流程 Coordinator
application/      连接／配置／系统代理用例及基础设施端口
core/             连接配置、错误与状态规则
infrastructure/   内嵌库适配、QSettings、系统代理、日志与更新实现
corelib/          会话、aTrust、underlay、解析、gVisor、回环代理及 C ABI
cmake/            应用和原生宿主共享的 Go 库／Qt 适配构建入口
tests/            领域、端口、界面、真实 C ABI 与受控网关回归
```

`application` 依赖 `core`，不引用 Widgets 或具体基础设施。`MainWindowCoordinator` 组合 `CoreEngine → EmbeddedCoreEngine`、`SystemProxyBackend → PlatformSystemProxyBackend` 和 `ProfileBackend → ProfileManager`。认证方式窗口通过应用层 `AuthMethodsQuery` 使用 `CoreEngine`，允许注入测试端口；只在查询与清理均成功后交付完整方法身份，取消或失败不暴露部分结果。

## 会话与线程

`ConnectionSession` 持有连接意图、重连计时器及当前配置，使用 `ConnectionSessionState` 管理状态。`EmbeddedCoreEngine` 将配置序列化后提交专属 Qt 工作线程；创建、异步启动、认证回应、读取、停止和销毁都在该线程调用 C ABI。每次最多一个 Qt 事件在途，应用线程确认交付后继续读取，避免另造无界日志队列。诊断字符串只供记录，状态仅由结构化状态／终态事件改变。

Go 的会话代次和请求 ID 全程保留为十进制字符串。`AuthDialogCoordinator` 异步展示短信、TOTP、RADIUS、内存图片验证码和 SSO；回应带原始身份。应用及 Go 都检查当前请求，旧窗口提交／取消不能影响新会话。停止不等待认证 UI；销毁先中断读取，再等待句柄与借用缓冲区结束。Unix 静态链接；Windows 从可执行文件目录固定加载随包 DLL，并保持 Go runtime 到宿主退出。

`Session.Run` 拥有 underlay、认证／隧道、gVisor、解析器及 SOCKS／HTTP（含 UDP association），所有清理结束后才释放活动会话名额。进程只允许一个活动连接或认证方式查询。查询界面等待清理终态后才允许确认选择。系统代理由单独用例拥有，通道就绪后才自动设置；当前库不创建系统 TUN、不改变系统路由／DNS，GUI 无需为连接整体提权。

`UpdateChecker` 从已加载库读取提交、工作树状态、ABI、平台／架构和 Go 版本。应用更新随 JustConnect 发布；没有独立核心版本探测、上游版本比较或运行时后端回退。

## 验证与迁移边界

`tests/coreabi/` 验证实际 C11／C++17 导出、内存与生命周期、QThread／WebEngine 共存、测试驱动认证，以及受控 TLS 网关的真实协议。S1-11 性能基线通过正式宿主测量正常／慢节点的 CPU、峰值 RSS、TCP／UDP 和 20 次认证重连，实际安装包另记录体积及离线启动自检耗时；场景与限制见 [构建说明](DEVELOPMENT.md#atrust-性能基线)。Qt 适配器覆盖旧／重复回应、取消、重启与销毁竞态；`coreengineui_test` 验证实际窗口、会话和正式协议，运行认证方式查询、短信提交、SOCKS／HTTP 数据收发与活动停止。

旧 `CoreProcess`、命令构造、输出解析、CLI 查询／版本／设备授信及 sudo 窗口已删除。测试与打包已统一通过 CMake 构建本仓库的核心库，运行组件安装固定 DLL／工具链／来源与许可证；三平台实际包运行正式应用离线 ABI 自检并审计依赖、架构、最低系统版本与签名。旧下载 action、脚本、清单、专属测试及无调用的 Wintun 分发文件已删除；包检查拒绝独立核心、旧来源目录及 Wintun（含大小写变体）。S2-02 已删除旧高级设置窗口、EasyConnect／未实现选项控件及专属运行字段；设置页和向导共用 Fudan／Custom 服务器控件，保存前通过实际 C ABI 的纯校验接口复用 Go 严格解析。升级仅补齐缺失默认值、按明确清单清理废弃键，保留有效 aTrust 设置、未知键及其他账户。旧协议保留服务器值供人工确认，但不能自动连接；配置版本和旧分组迁移由 SettingsMigrator 维护。真实校园样本、生产 TLS、Clash 共存与透明入口按 [plan.md](../plan.md) 独立验收。

导入／重置先编辑草稿，取消不改原文件；保存失败不关闭窗口或清认证缓存。只有成功保存且服务器／认证身份变化时，才清当前配置的旧缓存；网络参数、废弃字段和登录 URL 预览更新不据此清除认证材料。安全凭据存储、账户级复用与完整配置用例分别继续按 S2-04／07／08 实施。

主窗口仍处理配置菜单和托盘；`ProfileService::settings()` 仍暴露 QSettings，平台代理与自启动按操作系统拆分，由共享 CMake 选择，只返回结构化结果；状态区分失败／取消／权限／超时／不支持及可能已修改，界面负责提示。代理查询失败不能触发设置，部分失败保留待清理状态；自启动或偏好保存失败时保留设置窗口和认证材料。代理快照、按所有权恢复与完整有界退出仍按 S2-06／S3-05 实施。领域和应用层允许 Qt Core 类型，与 Widgets 分离不表示脱离 Qt。针对性重构随功能推进，不增加协议插件框架或通用工具目录。

S2-03 将 TLS 信任策略收敛到会话配置，查询用例只复制端点与 TLS 策略，不携带账户密码。服务器编辑控件维护验证开关及可选学校 CA；旧配置默认验证系统证书，显式关闭会显示持续提示。认证、节点探测与隧道复用同一个带取消的 TLS 握手实现，失败类型通过 ABI 和 Qt 保留；不再把上游历史兼容行为当作跳过证书验证的默认值。

平台实现按 `infrastructure/platform/linux/`、`macos/`、`windows/` 归档，未支持平台的回退实现位于 `unsupported/`。外层保留公共端口适配声明、命令执行、代理校验和自启动共用规则；Windows 的原生代理 API 注入声明归 Windows 目录。`cmake/Platform.cmake` 只按目标系统选择对应目录，主应用与原生测试复用同一入口，调用方继续使用公共接口。

系统凭据存储端口位于 `application/credentialstore.h`，提供有界不透明值的读／写／删和明确状态，平台工厂位于 `infrastructure/platform/systemcredentialstore.h`。`windows/credentialstore.cpp` 使用当前用户 Credential Manager，`macos/` 使用 Keychain，`linux/` 使用 Qt DBus 调用 Secret Service；锁定和权限状态不会被当作空凭据或成功。原生回归使用隔离条目／临时 Keychain／私有总线。安全迁移及界面接入仍在 S2-04 进行，应用旧配置中的凭据尚未因添加此端口自动迁移。
