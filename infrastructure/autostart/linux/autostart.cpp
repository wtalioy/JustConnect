#include "infrastructure/autostart/validation.h"
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QStandardPaths>

namespace {
// XDG autostart entry: one .desktop file per application inside $XDG_CONFIG_HOME/autostart.
QString entryPath(const QString &name)
{
    const auto config = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
    return config.isEmpty() ? QString() : config + "/autostart/" + name + ".desktop";
}

QString quoted(QString value)
{
    value.replace("\\", "\\\\"); value.replace("\"", "\\\"");
    return '"' + value + '"';
}
}

PlatformOperationResult AutoStart::setEnabled(bool enabled) {
    using Status = PlatformOperationResult::Status;
    const auto path = QCoreApplication::applicationFilePath();
    if (auto valid = AutoStartDetail::validate(path); !valid.succeeded()) return valid;
    const auto name = QCoreApplication::applicationName();
    const auto entry = entryPath(name);
    if (entry.isEmpty()) return {Status::Failed, "Cannot resolve the XDG autostart directory", enabled};
    if (!enabled) {
        if (!QFile::exists(entry)) return {Status::Success, {}, true};
        if (!QFile::remove(entry)) return {Status::Failed, "Cannot remove the XDG autostart entry", true};
        if (QFile::exists(entry)) return {Status::Failed, "XDG autostart entry readback mismatch", true};
        return {Status::Success, {}, true};
    }
    const auto directory = QFileInfo(entry).absolutePath();
    if (!QDir().mkpath(directory)) return {Status::Failed, "Cannot create the XDG autostart directory", enabled};
    const auto command = quoted(path);
    const QString content =
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Version=1.0\n"
        "Name=" + name + '\n'
        + "Exec=" + command + '\n';
    QSaveFile file(entry);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)
        || file.write(content.toUtf8()) != content.toUtf8().size() || !file.commit())
        return {Status::Failed, "Cannot save the XDG autostart entry", enabled};
    QFile::setPermissions(entry, QFile::Permissions(int(QFile::ReadOwner) | int(QFile::WriteOwner)
        | int(QFile::ReadGroup) | int(QFile::ReadOther)));
    QFile readback(entry);
    if (!readback.open(QIODevice::ReadOnly)) return {Status::Failed, "Cannot verify the XDG autostart entry", true};
    const auto lines = QString::fromUtf8(readback.readAll()).split('\n');
    // Only an entry that keeps the exact recorded command may count as durable; an external edit is rejected.
    if (!lines.contains("Exec=" + command) || !lines.contains("[Desktop Entry]") || !lines.contains("Type=Application"))
        return {Status::Failed, "XDG autostart entry readback mismatch", true};
    return {Status::Success, {}, true};
}
