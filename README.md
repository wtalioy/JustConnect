# JustConnect

面向 Windows 和 macOS 的 aTrust 校园网络客户端，支持 x64／ARM64。校园浏览器与终端访问共用连接，保留原网络及 Tailscale 等已有网络的选择。

当前可按 [预览包实测步骤](docs/DEVELOPMENT.md#s8-实测步骤) 安装。Windows 完整解压 ZIP 后运行 `JustConnect.exe`，macOS 从 DMG 将应用拖到「应用程序」。

在主窗口选择 Fudan 或自己的 aTrust 连接，点击连接，按需完成学校登录和系统授权。显示已连接后，直接用现有浏览器和终端访问校园网页或运行普通 `ssh`。断开时，应用只撤销自己管理的网络设置。

Windows 登录需要 WebView2 Runtime，macOS 使用系统 WebKit。预览无需自行申请证书，首次打开的系统提示及 macOS 下载限制见[签名与部署说明](docs/DEVELOPMENT.md#不需申请签名的开发与发行)。

[域名专用 DNS](docs/DEVELOPMENT.md#域名专用-dns) · [实施计划](plan.md) · [开发说明](docs/DEVELOPMENT.md) · [架构说明](docs/ARCHITECTURE.md)
