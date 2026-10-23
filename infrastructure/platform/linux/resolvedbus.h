#pragma once
#include <QString>

namespace LinuxResolved {
inline const QString service = QStringLiteral("org.freedesktop.resolve1");
inline const QString managerPath = QStringLiteral("/org/freedesktop/resolve1");
inline const QString managerInterface = service + QStringLiteral(".Manager");
inline const QString linkInterface = service + QStringLiteral(".Link");
}
