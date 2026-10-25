#include "infrastructure/dns/linux/dnssnapshot.h"
#include <QCoreApplication>
#include <QDBusArgument>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusVirtualObject>
#include <QFile>
#include <QJsonArray>
#include <QProcess>
#include <QTemporaryDir>
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}

struct Server { int index, family; QByteArray address; };
struct ServerEx { int index, family; QByteArray address; quint16 port; QString name; };
struct Domain { int index; QString name; bool routeOnly; };
Q_DECLARE_METATYPE(Server)
Q_DECLARE_METATYPE(ServerEx)
Q_DECLARE_METATYPE(Domain)
QDBusArgument &operator<<(QDBusArgument &a, const Server &v) {
    a.beginStructure(); a << v.index << v.family << v.address; a.endStructure(); return a;
}
const QDBusArgument &operator>>(const QDBusArgument &a, Server &v) {
    a.beginStructure(); a >> v.index >> v.family >> v.address; a.endStructure(); return a;
}
QDBusArgument &operator<<(QDBusArgument &a, const ServerEx &v) {
    a.beginStructure(); a << v.index << v.family << v.address << v.port << v.name; a.endStructure(); return a;
}
const QDBusArgument &operator>>(const QDBusArgument &a, ServerEx &v) {
    a.beginStructure(); a >> v.index >> v.family >> v.address >> v.port >> v.name; a.endStructure(); return a;
}
QDBusArgument &operator<<(QDBusArgument &a, const Domain &v) {
    a.beginStructure(); a << v.index << v.name << v.routeOnly; a.endStructure(); return a;
}
const QDBusArgument &operator>>(const QDBusArgument &a, Domain &v) {
    a.beginStructure(); a >> v.index >> v.name >> v.routeOnly; a.endStructure(); return a;
}

class Resolver final : public QDBusVirtualObject
{
public:
    QString mode;
    QString introspect(const QString &) const override { return {}; }
    bool handleMessage(const QDBusMessage &message, const QDBusConnection &bus) override {
        QVariant value;
        if (message.interface() == "org.freedesktop.resolve1.Manager" && message.member() == "GetLink") {
            if (mode == "nolinks") {
                bus.send(message.createErrorReply("org.freedesktop.resolve1.NoSuchLink", "No managed link"));
                return true;
            }
            value = QVariant::fromValue(QDBusObjectPath("/org/freedesktop/resolve1/link/_7"));
        } else if (message.interface() == "org.freedesktop.DBus.Properties" && message.member() == "GetAll") {
            if (mode == "timeout") return true;
            if (message.path().contains("/link/")) {
                if (mode == "vanished") {
                    bus.send(message.createErrorReply(QDBusError::UnknownObject, "fixture disappeared"));
                    return true;
                }
                value = QVariantMap{{"DefaultRoute", false}, {"DNSOverTLS", "yes"}};
            } else {
                const bool extended = mode != "legacy";
                const auto address = mode == "invalid" ? QByteArray(3, '\0') : QByteArray::fromHex("c0000235");
                const auto ipv6 = QByteArray::fromHex("20010db8000000000000000000000053");
                const auto servers = extended ? QVariant::fromValue(QList<ServerEx>{{7, 2, address, 853, "resolver.example.test"}, {7, 10, ipv6, 853, "v6.example.test"}})
                                              : QVariant::fromValue(QList<Server>{{7, 2, address}, {7, 10, ipv6}});
                const auto domains = QVariant::fromValue(QList<Domain>{{7, "overlay.test", true}, {7, "search.test", false}});
                value = QVariantMap{{extended ? "DNSEx" : "DNS", servers},
                                    {extended ? "FallbackDNSEx" : "FallbackDNS", servers},
                                    {"Domains", domains}, {"ResolvConfMode", "foreign"},
                                    {"DNSOverTLS", "opportunistic"}};
            }
        } else {
            bus.send(message.createErrorReply(QDBusError::UnknownMethod, "Read-only fixture"));
            return true;
        }
        bus.send(message.createReply({value}));
        return true;
    }
};

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    qDBusRegisterMetaType<Server>(); qDBusRegisterMetaType<QList<Server>>();
    qDBusRegisterMetaType<ServerEx>(); qDBusRegisterMetaType<QList<ServerEx>>();
    qDBusRegisterMetaType<Domain>(); qDBusRegisterMetaType<QList<Domain>>();
    if (app.arguments().contains("--native")) {
        const auto snapshot = readSystemDnsSnapshot();
        check(snapshot.result.succeeded(), qPrintable(snapshot.result.detail));
        check(!snapshot.data["resolv_conf"].toObject()["target"].toString().isEmpty(), "Native resolver source missing");
        std::cout << "Native resolver file and service inspected without writes\n";
        return 0;
    }
    auto bus = QDBusConnection::sessionBus();
    if (app.arguments().size() == 3 && app.arguments()[1] == "--serve") {
        Resolver resolver;
        resolver.mode = app.arguments()[2];
        check(bus.registerVirtualObject("/org/freedesktop/resolve1", &resolver, QDBusConnection::SubPath), "Register fixture path");
        check(bus.registerService("org.freedesktop.resolve1"), "Register private resolver service");
        std::cout << "ready\n" << std::flush;
        return app.exec();
    }
    QTemporaryDir directory;
    check(directory.isValid(), "Temporary resolver directory");
    const auto source = directory.filePath("resolv.conf");
    const QByteArray original = "# generated fixture\nnameserver 127.0.0.53\nsearch search.test\noptions edns0 trust-ad\n";
    QFile file(source);
    check(file.open(QIODevice::WriteOnly) && file.write(original) == original.size(), "Write resolver fixture");
    file.close();
    const auto absent = readLinuxDnsSnapshot(bus, source);
    check(absent.result.succeeded() && absent.data["resolved"].toObject()["status"] == "unavailable", "Absent service remains unavailable");
    for (const auto &mode : {"modern", "legacy", "nolinks", "invalid", "vanished", "timeout"}) {
        QProcess server;
        server.start(app.applicationFilePath(), {"--serve", mode});
        check(server.waitForReadyRead(3000) && server.readLine() == "ready\n", "Start private resolver fixture");
        const auto snapshot = readLinuxDnsSnapshot(bus, source);
        const bool valid = QString(mode) == "modern" || QString(mode) == "legacy" || QString(mode) == "nolinks";
        check(snapshot.result.succeeded() == valid, qPrintable(QString(mode) + ": " + snapshot.result.detail));
        if (valid) {
            const auto resolved = snapshot.data["resolved"].toObject();
            const auto dns = resolved["DNS"].toArray().first().toObject();
            check(dns["interface_index"] == 7 && dns["address"] == "192.0.2.53", "Per-link DNS identity preserved");
            check(dns["port"] == (QString(mode) == "legacy" ? 0 : 853), "Extended port or legacy unspecified port preserved");
            check(dns["server_name"] == (QString(mode) == "legacy" ? "" : "resolver.example.test"), "TLS server identity preserved");
            check(resolved["DNS"].toArray()[1].toObject()["address"] == "2001:db8::53", "IPv6 resolver address preserved");
            const auto domains = resolved["Domains"].toArray();
            check(domains.size() == 2 && domains[0].toObject()["route_only"] == true
                  && domains[1].toObject()["route_only"] == false, "Routing domains kept distinct from search domains");
            const auto links = resolved["Links"].toArray();
            check(QString(mode) == "nolinks" ? links.isEmpty() : !links.isEmpty() && links.first().toObject()["DefaultRoute"] == false,
                  "Unmanaged links skipped and managed default-route preference preserved");
            check(resolved["ResolvConfMode"] == "foreign", "Foreign resolver mode preserved");
            check(snapshot.data["resolv_conf"].toObject()["contents"].toString().toUtf8() == original, "Actual resolver directives preserved");
        } else check(snapshot.data.isEmpty(), "Failure must not publish partial DNS facts");
        server.terminate(); check(server.waitForFinished(3000), "Stop private fixture");
    }
    check(file.open(QIODevice::ReadOnly) && file.readAll() == original, "Read-only snapshot changed resolver fixture");
    file.close();
    check(file.open(QIODevice::WriteOnly | QIODevice::Truncate) && file.write(QByteArray(65537, 'x')) == 65537, "Oversized fixture");
    file.close();
    const auto oversized = readLinuxDnsSnapshot(bus, source);
    check(!oversized.result.succeeded() && oversized.data.isEmpty(), "Oversized resolver file must fail without truncation");
    check(file.open(QIODevice::WriteOnly | QIODevice::Truncate) && file.write(QByteArray(60000, '\1')) == 60000, "Escaped output boundary fixture");
    file.close();
    const auto escaped = readLinuxDnsSnapshot(bus, source);
    check(!escaped.result.succeeded() && escaped.data.isEmpty(), "Output bound also applies when resolver service is absent");
    const auto invalidText = QByteArray("nameserver 192.0.2.53\n#\xff\n");
    check(file.open(QIODevice::WriteOnly | QIODevice::Truncate) && file.write(invalidText) == invalidText.size(), "Invalid encoding fixture");
    file.close();
    const auto invalidEncoding = readLinuxDnsSnapshot(bus, source);
    check(!invalidEncoding.result.succeeded() && invalidEncoding.data.isEmpty(), "Resolver bytes silently replaced during text decoding");
    check(!readLinuxDnsSnapshot(bus, directory.filePath("missing")).result.succeeded(), "Missing resolver file must fail");
    std::cout << "Resolver source, split DNS, legacy protocol and failure boundaries passed\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
