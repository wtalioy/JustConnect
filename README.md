# JustConnect

JustConnect is an aTrust client for campus networks on Windows and macOS. Connect once, then reach campus websites and SSH hosts from the browser and terminal you already use.

## Install

Download the package for your processor from [GitHub Releases](https://github.com/wtalioy/JustConnect/releases). Development builds are available under [Actions](https://github.com/wtalioy/JustConnect/actions/workflows/build.yml).

- **Windows (x64 or ARM64):** Run `-setup.exe` to install for your account. You can choose the destination and whether to add a Start menu shortcut. To use the ZIP instead, extract it in full and open `JustConnect.exe`. Sign-in requires the [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/).
- **macOS 14.4 or later (Apple silicon or Intel):** Open the DMG and drag JustConnect to Applications.

Windows installers are unsigned, and macOS builds are not notarized. Your system may ask you to confirm the first launch. Download only from this repository and check the release's `SHA256SUMS.txt` if you need to verify a file.

## Connect

Choose the Fudan University profile or add your own aTrust gateway, then select **Connect**. Follow the campus sign-in and system permission prompts. When you disconnect, JustConnect removes the network settings it applied.

[Release notes](docs/releases) · [License](LICENSE)
