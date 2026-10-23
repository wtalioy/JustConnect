#include "dnssnapshot.h"
#include "resolvedbus.h"
#include <QDBusArgument>
#include <QDBusError>
#include <QDBusMessage>
#include <QDeadlineTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <arpa/inet.h>
#include <net/if.h>
#include <QScopeGuard>

namespace {
constexpr qsizetype maxFile = 65536;
constexpr qsizetype maxSnapshot = 262144;
using LinuxResolved::service;
using LinuxResolved::managerPath;
using LinuxResolved::managerInterface;

bool servers(const QVariant &value, bool extended, QJsonArray &output)
{
    const auto argument = qvariant_cast<QDBusArgument>(value);
    if (argument.currentSignature() != (extended ? "a(iiayqs)" : "a(iiay)")) return false;
    argument.beginArray();
    while (!argument.atEnd()) {
        int index = 0, family = 0;
        QByteArray bytes;
        quint16 port = 0;
        QString name;
        argument.beginStructure();
        argument >> index >> family >> bytes;
        if (extended) argument >> port >> name;
        argument.endStructure();
        char address[INET6_ADDRSTRLEN]{};
        if (index < 0 || (family != AF_INET && family != AF_INET6)
            || bytes.size() != (family == AF_INET ? 4 : 16)
            || !inet_ntop(family, bytes.constData(), address, sizeof(address))) return false;
        output.append(QJsonObject{{"interface_index", index}, {"family", family},
                                  {"address", QString::fromLatin1(address)}, {"port", port},
                                  {"server_name", name}});
    }
    argument.endArray();
    return true;
}

bool domains(const QVariant &value, QJsonArray &output)
{
    const auto argument = qvariant_cast<QDBusArgument>(value);
    if (argument.currentSignature() != "a(isb)") return false;
    argument.beginArray();
    while (!argument.atEnd()) {
        int index = 0;
        QString domain;
        bool routeOnly = false;
        argument.beginStructure();
        argument >> index >> domain >> routeOnly;
        argument.endStructure();
        if (index < 0 || domain.isEmpty()) return false;
        output.append(QJsonObject{{"interface_index", index}, {"domain", domain}, {"route_only", routeOnly}});
    }
    argument.endArray();
    return true;
}
}

DnsSnapshot readLinuxDnsSnapshot(const QDBusConnection &bus, const QString &resolvConf)
{
    using Status = PlatformOperationResult::Status;
    auto failure = [](Status status, const QString &detail) {
        return DnsSnapshot{{status, detail}, {}};
    };
    auto complete = [&](const QJsonObject &data) {
        if (QJsonDocument(data).toJson(QJsonDocument::Compact).size() > maxSnapshot)
            return failure(Status::Failed, "System resolver snapshot too large");
        return DnsSnapshot{{}, data};
    };
    QFile file(resolvConf);
    if (!file.open(QIODevice::ReadOnly)) return failure(Status::Failed, "Cannot read system resolver file");
    const auto content = file.read(maxFile + 1);
    if (file.error() != QFileDevice::NoError || content.size() > maxFile)
        return failure(Status::Failed, "System resolver file unreadable or too large");
    const auto text = QString::fromUtf8(content);
    if (text.toUtf8() != content) return failure(Status::Failed, "System resolver file is not valid UTF-8");
    QJsonObject data{{"resolv_conf", QJsonObject{{"path", resolvConf},
                                               {"target", QFileInfo(file).canonicalFilePath()},
                                               {"contents", text}}}};
    if (!bus.isConnected()) return failure(Status::Failed, "Cannot inspect system resolver bus");
    QDeadlineTimer deadline(5000);
    auto call = [&](const QString &destination, const QString &path, const QString &interface,
                    const QString &method, const QVariantList &arguments = {}) {
        auto message = QDBusMessage::createMethodCall(destination, path, interface, method);
        message.setAutoStartService(false);
        message.setArguments(arguments);
        if (deadline.hasExpired()) return QDBusMessage::createError(QDBusError::Timeout, "Resolver snapshot timed out");
        return bus.call(message, QDBus::Block, int(qMin<qint64>(1000, deadline.remainingTime())));
    };
    const auto owner = call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                            "NameHasOwner", {service});
    if (owner.type() != QDBusMessage::ReplyMessage || owner.signature() != "b")
        return failure(Status::Failed, "Cannot inspect system resolver service");
    if (!owner.arguments().first().toBool()) {
        data.insert("resolved", QJsonObject{{"status", "unavailable"}});
        return complete(data);
    }
    const auto reply = call(service, managerPath, "org.freedesktop.DBus.Properties", "GetAll", {managerInterface});
    if (reply.type() != QDBusMessage::ReplyMessage || reply.signature() != "a{sv}")
        return failure(Status::Failed, "Cannot read system resolver properties");
    const auto properties = qdbus_cast<QVariantMap>(reply.arguments().first());
    QJsonObject resolved{{"status", "available"}};
    for (const auto &key : {"ResolvConfMode", "DNSOverTLS", "DNSSEC", "LLMNR", "MulticastDNS"}) {
        if (!properties.contains(key)) continue;
        if (properties[key].metaType() != QMetaType::fromType<QString>())
            return failure(Status::Failed, "Invalid system resolver property");
        resolved.insert(key, properties[key].toString());
    }
    for (const auto &base : {QStringLiteral("DNS"), QStringLiteral("FallbackDNS")}) {
        const bool extended = properties.contains(base + "Ex");
        const auto key = extended ? base + "Ex" : base;
        QJsonArray rows;
        if (!properties.contains(key) || !servers(properties[key], extended, rows))
            return failure(Status::Failed, "Invalid system resolver servers");
        resolved.insert(base, rows);
    }
    QJsonArray domainRows;
    if (!properties.contains("Domains") || !domains(properties["Domains"], domainRows))
        return failure(Status::Failed, "Invalid system resolver domains");
    resolved.insert("Domains", domainRows);
    auto *interfaces = if_nameindex();
    if (!interfaces) return failure(Status::Failed, "Cannot inspect resolver interfaces");
    const auto release = qScopeGuard([&] { if_freenameindex(interfaces); });
    QJsonArray linkRows;
    for (auto *interface = interfaces; interface->if_index; ++interface) {
        const int index = int(interface->if_index);
        const auto link = call(service, managerPath, managerInterface, "GetLink", {index});
        if (link.type() == QDBusMessage::ErrorMessage && link.errorName() == "org.freedesktop.resolve1.NoSuchLink") continue;
        if (link.type() != QDBusMessage::ReplyMessage || link.signature() != "o")
            return failure(Status::Failed, "Cannot read system resolver link");
        const auto path = qvariant_cast<QDBusObjectPath>(link.arguments().first());
        const auto linkReply = call(service, path.path(), "org.freedesktop.DBus.Properties", "GetAll",
                                    {LinuxResolved::linkInterface});
        if (linkReply.type() != QDBusMessage::ReplyMessage || linkReply.signature() != "a{sv}")
            return failure(Status::Failed, "System resolver link changed or could not be read");
        const auto values = qdbus_cast<QVariantMap>(linkReply.arguments().first());
        QJsonObject row{{"interface_index", index}, {"name", QString::fromUtf8(interface->if_name)}};
        for (const auto &key : {"DefaultRoute", "DNSOverTLS", "DNSSEC", "LLMNR", "MulticastDNS"}) {
            if (!values.contains(key)) continue;
            const auto expected = QString(key) == "DefaultRoute" ? QMetaType::fromType<bool>() : QMetaType::fromType<QString>();
            if (values[key].metaType() != expected) return failure(Status::Failed, "Invalid system resolver link property");
            row.insert(key, QJsonValue::fromVariant(values[key]));
        }
        linkRows.append(row);
    }
    resolved.insert("Links", linkRows);
    data.insert("resolved", resolved);
    return complete(data);
}
