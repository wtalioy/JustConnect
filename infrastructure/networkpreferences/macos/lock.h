#pragma once

#include "application/platformoperationresult.h"
#include <QDeadlineTimer>
#include <QThread>
#include <Security/Authorization.h>
#include <SystemConfiguration/SystemConfiguration.h>

namespace MacNetworkPreferences {
inline PlatformOperationResult error(const QString &operation, bool changed = false)
{
    using Status = PlatformOperationResult::Status;
    const auto code = SCError();
    const auto status = code == errAuthorizationCanceled ? Status::Cancelled
        : code == kSCStatusAccessError || code == errAuthorizationDenied ? Status::PermissionDenied
        : code == kSCStatusNoConfigFile ? Status::Unsupported : Status::Failed;
    return {status, operation + ": SystemConfiguration error " + QString::number(code), changed};
}

inline PlatformOperationResult lock(SCPreferencesRef preferences, const QString &operation, bool changed = false)
{
    // Brief external commits share this lock. Give them time to settle before reading a fresh snapshot.
    QDeadlineTimer deadline(1000);
    for (;;) {
        SCPreferencesSynchronize(preferences);
        if (SCPreferencesLock(preferences, false)) return {};
        if (SCError() != kSCStatusPrefsBusy) return error(operation, changed);
        if (deadline.hasExpired())
            return {PlatformOperationResult::Status::TimedOut, operation + ": preferences remain busy", changed};
        QThread::msleep(qMin(qint64(20), deadline.remainingTime()));
    }
}
}
