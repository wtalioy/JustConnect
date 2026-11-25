#include "infrastructure/networkhelper/linux/networkhelperavailability.h"
#include "infrastructure/dns/linux/dnssnapshot.h"
#include "infrastructure/networkhelper/linux/networkhelperpaths.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

namespace {
// Directories whose contents only root can place or replace: a helper inside
// one of them cannot be swapped by an unprivileged archive extraction. The
// polkit action authorizes exactly the annotated path, so this list keeps the
// annotation itself pointed at a system location.
bool protectedSystemPath(const QString &path)
{
    return path.startsWith(QStringLiteral("/usr/local/libexec/"))
        || path.startsWith(QStringLiteral("/usr/libexec/"))
        || path.startsWith(QStringLiteral("/usr/local/lib/"))
        || path.startsWith(QStringLiteral("/usr/lib/"))
        || path.startsWith(QStringLiteral("/usr/sbin/"));
}

bool executableByPkexec(const QFileInfo &info)
{
    const auto protectedEntry = [](const QFileInfo &entry) {
        return !entry.isSymLink() && entry.ownerId() == 0
            && !(entry.permissions() & (QFile::WriteGroup | QFile::WriteOther));
    };
    if (!info.isFile() || !info.isExecutable() || !protectedEntry(info)) return false;
    for (auto parent = info.absoluteDir(); ;) {
        if (!protectedEntry(QFileInfo(parent.absolutePath()))) return false;
        if (parent.isRoot()) return true;
        if (!parent.cdUp()) return false;
    }
}
}

QString linuxNetworkHelperExecutable()
{
    // Only the root-owned copy at the annotated system path may be elevated:
    // pkexec executes exactly that path, and a helper inside an extracted
    // archive keeps the extractor's ownership, so no portable copy is tried.
    const QFileInfo installed{QLatin1String(JustConnectNetworkHelperPath)};
    if (!protectedSystemPath(installed.absoluteFilePath())) return {};
    if (executableByPkexec(installed)) return installed.absoluteFilePath();
    return {};
}

LinuxHelperAvailability linuxNetworkHelperAvailability()
{
    LinuxHelperAvailability report;
    const QFileInfo installed{QLatin1String(JustConnectNetworkHelperPath)};
    if (linuxNetworkHelperExecutable().isEmpty()) {
        if (!protectedSystemPath(installed.absoluteFilePath())) {
            report.helperDetail = QCoreApplication::translate("LinuxNetworkAvailability",
                "The configured helper path %1 is outside the protected system directories pkexec can trust.")
                .arg(installed.absoluteFilePath());
            report.remedy = QCoreApplication::translate("LinuxNetworkAvailability",
                "Reinstall with a system prefix (for example -DCMAKE_INSTALL_PREFIX=/usr/local) and run "
                "its setup-network-helper script, then reconnect.");
            return report;
        }
        report.helperDetail = QCoreApplication::translate("LinuxNetworkAvailability",
            "The JustConnect network helper is not installed as a root-owned executable at %1.")
            .arg(installed.absoluteFilePath());
        report.remedy = QCoreApplication::translate("LinuxNetworkAvailability",
            "Install it to %1 as a root-owned executable together with its polkit action "
            "(the package's setup-network-helper script does both), then reconnect.")
            .arg(installed.absoluteFilePath());
        return report;
    }
    if (QStandardPaths::findExecutable(QStringLiteral("pkexec")).isEmpty()) {
        report.helperDetail = QCoreApplication::translate("LinuxNetworkAvailability",
            "polkit (pkexec) is not available; automatic routing needs it to request administrator privileges.");
        report.remedy = QCoreApplication::translate("LinuxNetworkAvailability",
            "Install polkit with your package manager (for example: sudo apt install policykit-1), then reconnect.");
        return report;
    }
    const auto usesResolvedStub = linuxDnsUsesResolvedStub();
    if (!usesResolvedStub.value_or(false)) {
        report.routingDetail = usesResolvedStub.has_value()
            ? QCoreApplication::translate("LinuxNetworkAvailability", "Automatic routing requires the systemd-resolved DNS stub.")
            : QCoreApplication::translate("LinuxNetworkAvailability", "Cannot read /etc/resolv.conf; automatic routing has no supported DNS mechanism.");
        report.remedy = QCoreApplication::translate("LinuxNetworkAvailability",
            "Applications only receive split DNS when they query systemd-resolved: point /etc/resolv.conf at "
            "its stub resolver (for example: sudo ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf), "
            "then reconnect.");
        return report;
    }
    report.available = true;
    return report;
}
