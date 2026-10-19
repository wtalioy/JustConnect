# JustConnect

基于 [EZ4Connect](https://github.com/chenx-dust/EZ4Connect) 继续开发，由 [wtalioy](https://github.com/wtalioy) 维护。

![Action](https://github.com/wtalioy/JustConnect/actions/workflows/build.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/wtalioy/JustConnect)
![Downloads](https://img.shields.io/github/downloads/wtalioy/JustConnect/total)
![License](https://img.shields.io/github/license/wtalioy/JustConnect)

支持 aTrust 的 ZJU-Connect 图形客户端。

问题反馈请提交到本仓库的 [Issues](https://github.com/wtalioy/JustConnect/issues)。校园网透明访问、三平台 Clash 自动共存仍在开发计划中，当前版本尚不具备这些完整能力，见 [计划](plan.md)。

<div align="center">
<img src="docs/main.png" width="600px">
</div>

## 使用方式

在本项目的 [Releases](https://github.com/wtalioy/JustConnect/releases) 页面下载最新版本：

- **Windows 用户**：下载 `JustConnect-vX.X.X-windows-ARCH.zip` ，解压至同一目录下，双击运行 `JustConnect.exe` ；
  - 如果遇到缺少 DLL 等问题，请先下载安装 Microsoft Visual C++ 可再发行程序包版本（[x64](https://aka.ms/vs/17/release/vc_redist.x64.exe) | [arm64](https://aka.ms/vs/17/release/vc_redist.arm64.exe)），再运行程序；
- **macOS 用户**：下载 `JustConnect-vX.X.X-macOS-ARCH.dmg` ，将 JustConnect 移动到应用程序目录中；
  - macOS 包仅在维护者配置 Apple 凭据后执行开发者签名及公证；未配置时提供临时签名的测试包，不能视为已公证版本；
- **Linux 用户**：下载 `JustConnect-vX.X.X-linux-ARCH.AppImage` ，赋予执行权限，运行即可；
  - AppImage x64 仅支持系统 `glibc >= 2.31` 的发行版，Ubuntu 22.04 及以上版本可以正常运行（受限于 GitHub Actions Runner）；
  - AppImage arm64 仅支持系统 `glibc >= 2.38` 的发行版，Ubuntu 24.04 及以上版本可以正常运行（受限于 Qt 官方：[参考](https://doc.qt.io/qt-6/supported-platforms.html)）；
  - 如果遇到因依赖问题无法运行的情况，请自行编译运行。

1. 跟随配置向导进行服务器与账户设置，或在“设置”中手动配置；

2. 在主界面中点击“连接服务器”。如果只需进行校园网页浏览，则选择“设置系统代理”后即可使用。

如果需要配合 Clash / Mihomo 进行高级的分流操作，可以参见： [高级使用方式](docs/ADVANCED_USAGE.md)

## 路线图

功能建议和问题请在本仓库的 Issues 中提出。

- [X] 支持 macOS 系统
- [X] 支持 Linux 系统
- [X] 支持手动设置 Proxy Bypass
- [ ] 使用密钥链存储密码等信息

## 开发

项目的分层、依赖方向和新增代码归属规则见
[架构说明](docs/ARCHITECTURE.md)。

本地构建、Actions 触发方式、发布及可选签名凭据见 [构建与发布](docs/DEVELOPMENT.md)。

## 许可证

本项目遵循 [GNU General Public License Version 3](LICENSE) 开源。

## 致谢

- [chenx-dust/EZ4Connect](https://github.com/chenx-dust/EZ4Connect)
- [Mythologyli/ZJU-Connect-for-Windows](https://github.com/Mythologyli/ZJU-Connect-for-Windows)
- [Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)
