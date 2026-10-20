#include "infrastructure/platform/autostartcommon.h"
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QStandardPaths>

PlatformOperationResult AutoStart::setEnabled(bool enabled) {
    using Status = PlatformOperationResult::Status;
    const auto name = QCoreApplication::applicationName();
    QString executable = qEnvironmentVariable("APPIMAGE");
    if (executable.isEmpty()) executable = QCoreApplication::applicationFilePath();
    if (auto valid = AutoStartDetail::validate(enabled ? executable : QCoreApplication::applicationFilePath()); !valid.succeeded()) return valid;
    const auto directory = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation) + "/autostart";
    const auto path = directory + '/' + name + ".desktop";
    if (QFileInfo(path).isSymLink()) return {Status::Failed, "Refusing a symlink autostart entry"};
    if (!enabled) {
        QFile entry(path);
        if (entry.exists() && !entry.remove()) return {entry.error() == QFileDevice::PermissionsError ? Status::PermissionDenied : Status::Failed, entry.errorString()};
        if (QFileInfo::exists(path)) return {Status::Failed, "Autostart removal readback failed", true};
        return {Status::Success, {}, true};
    }
    if (!QFileInfo(executable).isExecutable()) return {Status::Failed, "Autostart application is not executable"};
    if (!QDir().mkpath(directory)) return {Status::Failed, "Cannot create autostart directory"};
    const auto quote = [](QString value) {
        value.replace('%', "%%");
        for (const auto ch : {QChar('\\'), QChar('"'), QChar('$'), QChar('`')}) value.replace(ch, QString('\\') + ch);
        return '"' + value + '"';
    };
    // GIO checks the first executable before expanding %% in its path.
    QString command = "/bin/sh -c " + quote("exec \"$0\"") + ' ' + quote(executable);
    // Desktop string escapes are decoded before Exec quoting is interpreted.
    command.replace("\\", "\\\\");
    const auto contents = ("[Desktop Entry]\nType=Application\nName=" + name + "\nExec=" + command + "\nX-GNOME-Autostart-enabled=true\n").toUtf8();
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) return {file.error() == QFileDevice::PermissionsError ? Status::PermissionDenied : Status::Failed, file.errorString()};
    if (file.write(contents) != contents.size() || !file.commit()) return {Status::Failed, "Cannot commit autostart entry"};
    QFile readback(path);
    if (!readback.open(QIODevice::ReadOnly) || readback.readAll() != contents) return {Status::Failed, "Autostart file readback failed", true};
    return {Status::Success, {}, true};
}
