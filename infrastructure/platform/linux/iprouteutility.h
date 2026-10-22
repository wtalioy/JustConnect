#pragma once

#include <QFileInfo>
#include <QStandardPaths>

inline QString trustedIpRouteUtility()
{
    const QFileInfo utility(QStandardPaths::findExecutable("ip", {"/usr/sbin", "/usr/bin", "/sbin", "/bin"}));
    if (!utility.isExecutable() || utility.ownerId() != 0
        || (utility.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) return {};
    return utility.canonicalFilePath();
}
