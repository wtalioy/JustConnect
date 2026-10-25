#include "infrastructure/autostart/validation.h"
#include <QDir>
#include <QSettings>

PlatformOperationResult AutoStart::setEnabled(bool enabled) {
    using Status = PlatformOperationResult::Status;
    const auto path = QCoreApplication::applicationFilePath();
    if (auto valid = AutoStartDetail::validate(path); !valid.succeeded()) return valid;
    const auto name = QCoreApplication::applicationName();
    const auto command = '"' + QDir::toNativeSeparators(path) + '"';
    const QString key = R"(HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run)";
    QSettings settings(key, QSettings::NativeFormat);
    if (enabled) settings.setValue(name, command); else settings.remove(name);
    settings.sync();
    if (settings.status() != QSettings::NoError) return {settings.status() == QSettings::AccessError ? Status::PermissionDenied : Status::Failed, "Cannot save Windows Run entry", true};
    QSettings readback(key, QSettings::NativeFormat);
    readback.sync();
    if (readback.status() != QSettings::NoError || (enabled ? readback.value(name).toString() != command : readback.contains(name)))
        return {Status::Failed, "Windows Run entry readback mismatch", true};
    return {Status::Success, {}, true};
}
