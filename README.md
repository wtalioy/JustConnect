<p align="center">
  <img src="resource/app-icon.svg" width="72" height="72" alt="">
</p>

<h1 align="center">JustConnect</h1>

<p align="center"><strong>Connect to campus. Keep your network.</strong></p>

<p align="center">
  An open-source aTrust client for Windows and macOS.
</p>

<p align="center">
  <a href="https://github.com/wtalioy/JustConnect/releases">Download</a>
  · <a href="#get-started">Get started</a>
</p>

## Features

### Keep the rest of your network running intact.

- **Browse as usual.** Campus traffic goes through your school’s gateway. Other traffic keeps using your existing network setup.
- **Clash coexistence.** Leave Clash running when you connect. Flip the system proxy or TUN switch freely as you prefer. Quit and reopen it whenever you like. Your campus connection stays up.
- **Stay direct on Tailscale.** Avoid forcing an existing direct tailscale connection through a relay.

### Sign in once. Reconnect in a click.

Always remember your saved sign-in between launches. As long as it’s still valid, just click Connect.

### Lightweight. Ready to go.

14–22 MiB for JustConnect vs. 201–224 MiB for official aTrust client. Get onto your campus network with about a tenth of the download.

## Screenshots

<p align="center">
  <img src=".github/screenshots/overview.svg" width="764" alt="JustConnect on macOS with the main window at the upper left and Fudan connection settings at the lower right">
</p>

## Get started

### Install

| Platform | How to install |
| --- | --- |
| **Windows** · x64 or ARM64 | Run the installer, or extract the portable ZIP and open `JustConnect.exe`. |
| **macOS** · 14.4 or later, Apple silicon or Intel | Open the DMG and drag JustConnect into Applications. |

Windows installers are unsigned, so Windows may show a warning.

macOS builds are not notarized. If macOS blocks JustConnect on first launch because it can’t verify the developer or check the app for malware, confirm that you downloaded the DMG from [JustConnect Releases](https://github.com/wtalioy/JustConnect/releases). Then go to **System Settings → Privacy & Security** and click **Open Anyway**.

### Connect

Choose the built-in Fudan University profile, or add one for your own aTrust gateway. Click **Connect** and follow the sign-in and network permission prompts.

If you already use Clash Verge Rev, choose **Local proxy only** in **Edit connection**. Under **Clash campus routes**, list the exact domains or IPv4 addresses to send through JustConnect. The Fudan profile starts with `zb.fudan.edu.cn`, `icourse.fudan.edu.cn`, and `library.fudan.edu.cn`. Everything else follows your existing Clash rules.

Choose **Copy Clash extension script** from the connection menu and add it to your Clash profile’s extension script. Use Rule mode, merge with any existing script, and copy it again if you change the port or routes. **Per-domain DNS** controls how JustConnect looks up specific domains; it does not add Clash routes. In this mode, JustConnect runs a local SOCKS5 proxy and leaves your system routes, DNS, and proxy settings alone.

## License and credits

JustConnect’s own code is licensed under the [GNU General Public License v3.0](LICENSE).

See [Third-Party Notices](ThirdPartyNotices.txt) for upstream credits and license terms.
