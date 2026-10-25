#pragma once
#include "infrastructure/autostart/autostart.h"
#include <QCoreApplication>
#include <QFileInfo>
#include <QRegularExpression>

namespace AutoStartDetail {
inline PlatformOperationResult validate(const QString &path) {
    if (!QRegularExpression("^[A-Za-z0-9_.-]+$").match(QCoreApplication::applicationName()).hasMatch())
        return {PlatformOperationResult::Status::Failed, "Invalid autostart item name"};
    if (!QFileInfo(path).isAbsolute() || path.contains('\n') || path.contains('\r') || path.contains(QChar('\0')) || !QFileInfo::exists(path))
        return {PlatformOperationResult::Status::Failed, "Autostart application path is unavailable"};
    return {};
}
}
