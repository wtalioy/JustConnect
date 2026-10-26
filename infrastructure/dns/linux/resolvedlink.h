#pragma once
#include "application/platformoperationresult.h"
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDeadlineTimer>
#include <QJsonObject>
#include <optional>

namespace LinuxResolved {
struct LinkSnapshot {
    PlatformOperationResult result;
    QJsonObject profile, provider, security;
    bool absent = false, extended = false;
    // Source preparation precondition; durable ownership remains with the mutation backend.
    QJsonObject expectation(int index) const;
};
// Automatic per-link forwarding requires the native stub to own system DNS routing.
bool nativeStubRouting(const QJsonObject &resolved);
// Extracts the same profile/security shape from an aggregate native snapshot.
std::optional<QJsonObject> linkInputs(const QJsonObject &resolved, const QJsonValue &index, const QString &interface);
// The unique bus owner and a held kernel socket bind reads to this network namespace.
LinkSnapshot readLink(const QDBusConnection &bus, int index, QDeadlineTimer &deadline);
bool providerIdentity(const QJsonObject &value);
QDBusMessage call(const QDBusConnection &bus, const QString &destination, const QString &path,
    const QString &interface, const QString &method, const QVariantList &arguments, QDeadlineTimer &deadline);
PlatformOperationResult replyResult(const QDBusMessage &reply);
}
