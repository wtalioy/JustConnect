#pragma once
#include "infrastructure/dns/linux/resolvedlink.h"
#include <QUuid>
#include <functional>

// Owns only a temporary DNS-server replacement on an existing native link.
// The caller authenticates saved records, persists checkpoints and supplies the trusted system bus.
class LinuxLinkDns
{
public:
    using CheckpointWriter = std::function<PlatformOperationResult(const QJsonObject &)>;
    explicit LinuxLinkDns(const QDBusConnection &bus) : bus(bus) {}
    LinuxLinkDns(const LinuxLinkDns &) = delete;
    LinuxLinkDns &operator=(const LinuxLinkDns &) = delete;
    PlatformOperationResult apply(const QUuid &owner, const QString &interface, const QString &source,
        quint16 port, const QJsonObject &expected, const CheckpointWriter &checkpoint);
    PlatformOperationResult restore(const CheckpointWriter &checkpoint);
    PlatformOperationResult recover(const QUuid &owner, const QJsonObject &saved, const CheckpointWriter &checkpoint);
    QJsonObject snapshot() const { return record; }
private:
    bool identity() const;
    PlatformOperationResult save(const CheckpointWriter &checkpoint) const;
    PlatformOperationResult clear(const CheckpointWriter &checkpoint);
    PlatformOperationResult restore(QDeadlineTimer &deadline, const CheckpointWriter &checkpoint);
    PlatformOperationResult write(const QJsonArray &servers, const QJsonObject &provider, QDeadlineTimer &deadline);
    QDBusConnection bus;
    QJsonObject record;
};
