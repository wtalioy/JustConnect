#pragma once

#include "infrastructure/tundevice/tundevice.h"
#include "infrastructure/dns/linux/resolvedlink.h"
#include <QDBusConnection>
#include <QDeadlineTimer>
#include <QStringList>
#include <functional>

class LinuxTunDns
{
public:
    using CheckpointWriter = std::function<PlatformOperationResult(const QJsonObject &)>;
    // Blocking privileged worker API; the caller supplies its trusted bus, never request fields.
    explicit LinuxTunDns(const QDBusConnection &bus) : bus(bus) {}
    LinuxTunDns(const LinuxTunDns &) = delete;
    LinuxTunDns &operator=(const LinuxTunDns &) = delete;
    PlatformOperationResult apply(const UnixTunDevice &device, const QStringList &domains, const CheckpointWriter &checkpoint = {});
    PlatformOperationResult restore(const UnixTunDevice &device, const CheckpointWriter &checkpoint = {});
    // The caller authenticates the privileged owner's protected journal before recovery.
    PlatformOperationResult recover(const QUuid &owner, const QJsonObject &saved, const CheckpointWriter &checkpoint = {});
    QJsonObject snapshot() const { return record; }
private:
    using State = LinuxResolved::LinkSnapshot;
    State read(QDeadlineTimer &deadline) const;
    PlatformOperationResult change(const QJsonObject &next, bool restoring, QDeadlineTimer &deadline, const CheckpointWriter &checkpoint);
    PlatformOperationResult restore(QDeadlineTimer &deadline, const CheckpointWriter &checkpoint);
    PlatformOperationResult save(const CheckpointWriter &checkpoint) const;
    PlatformOperationResult clear(const CheckpointWriter &checkpoint);
    bool identity() const;
    QDBusConnection bus;
    QJsonObject record;
    bool recovered = false, attempted = false;
};
