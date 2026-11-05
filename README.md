# JustConnect

面向 Windows 和 macOS 的 aTrust 校园网络客户端，支持 x64／ARM64。校园浏览器与终端访问共用连接，保留原网络及 Tailscale 等已有网络的选择。

当前仍在开发；实际可用范围与未验收项见 [实施计划](plan.md)。构建、配置与测试入口见 [开发说明](docs/DEVELOPMENT.md)，模块职责见 [架构说明](docs/ARCHITECTURE.md)。

无需自行申请代码签名证书；系统网络修改仍遵循正常管理员授权，恢复只撤销自身拥有的修改。
