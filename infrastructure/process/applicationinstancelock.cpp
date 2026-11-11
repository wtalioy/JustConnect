#include "applicationinstancelock.h"

#include <QDir>
#include <QStandardPaths>

namespace
{
QString instanceLockPath()
{
    const auto path = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (path.isEmpty()) return {};

    const QDir directory(path);
    return directory.mkpath(".") ? directory.filePath("instance.lock") : QString{};
}
}

ApplicationInstanceLock::ApplicationInstanceLock() : lock(instanceLockPath())
{
    if (lock.fileName().isEmpty()) return;
    lock.setStaleLockTime(0);
    lock.tryLock();
}

QLockFile::LockError ApplicationInstanceLock::error() const
{
    return lock.fileName().isEmpty() ? QLockFile::PermissionError : lock.error();
}
