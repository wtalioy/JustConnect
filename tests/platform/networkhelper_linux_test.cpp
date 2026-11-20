#include "infrastructure/networkhelper/linux/networkhelperclient.h"
#include "infrastructure/networkhelper/linux/networkhelperavailability.h"
#include "infrastructure/networkhelper/linux/networkhelperpreparation.h"
#include "infrastructure/networkhelper/linux/networkownership.h"
#include "application/campuscapture.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <qendian.h>
#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <fcntl.h>
#include <cstdio>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

static void check(bool ok, const QString &message) { if (!ok) throw std::runtime_error(message.toStdString()); }

// In-process stand-in for the privileged helper: dials the client's private
// abstract socket, speaks the framed JSON protocol and passes a socketpair end
// through SCM_RIGHTS on apply. No QProcess is involved, so the client's
// process-exit paths stay silent while the socket paths are exercised.
struct FakeHelper final
{
    std::thread worker;
    bool stallApply = false;    // hold the reply to exercise cancellation
    bool dropAfterApply = false; // close the channel right after the apply reply

    FakeHelper() = default;
    FakeHelper(const FakeHelper &) = delete;
    FakeHelper &operator=(const FakeHelper &) = delete;
    ~FakeHelper() { join(); }
    void start(const QString &socketName)
    {
        join();
        worker = std::thread([this, socketName] { run(socketName); });
    }
    void join()
    {
        if (worker.joinable()) worker.join();
    }

private:
    static bool readAll(int fd, char *target, int bytes)
    {
        for (int offset = 0; offset < bytes;) {
            const auto received = ::recv(fd, target + offset, size_t(bytes - offset), 0);
            if (received <= 0) {
                if (received < 0 && errno == EINTR) continue;
                return false;
            }
            offset += received;
        }
        return true;
    }
    static QByteArray readFrame(int fd)
    {
        char header[4];
        if (!readAll(fd, header, 4)) return {};
        const auto length = qFromBigEndian<quint32>(header);
        QByteArray body(int(length), Qt::Uninitialized);
        if (length > 0 && !readAll(fd, body.data(), int(length))) return {};
        return body;
    }
    static bool sendFrame(int fd, const QByteArray &body, const int *descriptor)
    {
        QByteArray frame(4 + body.size(), Qt::Uninitialized);
        qToBigEndian<quint32>(quint32(body.size()), frame.data());
        std::memcpy(frame.data() + 4, body.constData(), size_t(body.size()));
        msghdr message{};
        iovec vector{frame.data(), size_t(frame.size())};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        char control[CMSG_SPACE(sizeof(int))];
        if (descriptor) {
            std::memset(control, 0, sizeof(control));
            message.msg_control = control;
            message.msg_controllen = sizeof(control);
            const auto header = CMSG_FIRSTHDR(&message);
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            std::memcpy(CMSG_DATA(header), descriptor, sizeof(int));
        }
        for (;;) {
            if (::sendmsg(fd, &message, MSG_NOSIGNAL) == frame.size()) return true;
            if (errno == EINTR) continue;
            return false;
        }
    }
    static QJsonObject respond(const QJsonObject &request, int &descriptor)
    {
        const auto operation = request["operation"].toString();
        QJsonObject reply{{"version", LinuxHelperProtocol}, {"operation", operation},
            {"owner", request["owner"]}, {"request_id", request["request_id"]}, {"status", "ok"}};
        if (operation == "probe") reply["dns_mode"] = QStringLiteral("resolved");
        else if (operation == "apply") {
            // A socketpair end stands in for the configured TUN descriptor; the
            // client's duplicate stays open regardless of our copies.
            int pair[2];
            if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0) {
                descriptor = pair[0];
                ::close(pair[1]);
            }
            reply["dns_mode"] = QStringLiteral("resolved");
            reply["device"] = QJsonObject{{"name", QStringLiteral("jc0")}, {"index", 42}, {"mtu", 1400},
                {"address", request["address"]}, {"peer", request["peer"]}};
        }
        return reply;
    }
    void run(const QString &socketName)
    {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return;
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        const auto name = socketName.toUtf8();
        std::memcpy(address.sun_path + 1, name.constData(), size_t(name.size()));
        const socklen_t length = socklen_t(offsetof(sockaddr_un, sun_path) + 1 + name.size());
        if (::connect(fd, reinterpret_cast<const sockaddr *>(&address), length) != 0) {
            std::fprintf(stderr, "fake helper dial failed: errno=%d\n", errno);
            ::close(fd);
            return;
        }
        const struct timeval timeout {10, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        for (;;) {
            const auto frame = readFrame(fd);
            if (frame.isEmpty()) break;
            const auto request = QJsonDocument::fromJson(frame).object();
            const auto operation = request["operation"].toString();
            if (stallApply && operation == "apply") continue; // stay silent until the client hangs up
            int descriptor = -1;
            const auto reply = respond(request, descriptor);
            const bool sent = sendFrame(fd, QJsonDocument(reply).toJson(QJsonDocument::Compact),
                descriptor >= 0 ? &descriptor : nullptr);
            if (descriptor >= 0) ::close(descriptor);
            if (!sent || operation == "close" || (dropAfterApply && operation == "apply")) break;
        }
        ::close(fd);
    }
};

struct Step
{
    std::optional<PlatformOperationResult> finished;
    std::optional<PlatformOperationResult> lost;
};

// Drives one client action and captures exactly one terminal report; both the
// finished and ownershipLost signals are attached because a helper that dies
// right after its reply coalesces both into one socket activation.
Step awaitStep(LinuxNetworkHelperClient &helper, const char *label, std::function<void()> trigger)
{
    Step step;
    QEventLoop loop;
    const auto finished = QObject::connect(&helper, &LinuxNetworkHelperClient::finished,
        [&](LinuxNetworkHelperClient::Operation, const PlatformOperationResult &result) { step.finished = result; loop.quit(); });
    const auto lost = QObject::connect(&helper, &LinuxNetworkHelperClient::ownershipLost,
        [&](const PlatformOperationResult &result) { step.lost = result; loop.quit(); });
    QTimer watchdog;
    watchdog.setSingleShot(true);
    QObject::connect(&watchdog, &QTimer::timeout, &loop, &QEventLoop::quit);
    watchdog.start(15000);
    trigger();
    if (!step.finished && !step.lost) loop.exec();
    watchdog.stop();
    QObject::disconnect(finished);
    QObject::disconnect(lost);
    if (!step.finished && !step.lost)
        throw std::runtime_error(QString("Client interaction timed out without a terminal report: %1").arg(QLatin1String(label)).toStdString());
    return step;
}

static void protocolChecks()
{
    const auto owner = QUuid::createUuid(), request = QUuid::createUuid();
    const LinuxHelperConfiguration configuration{"198.18.0.1", "198.18.0.2", 1400,
        {"198.18.0.6/32", "198.18.1.0/24"}, {"campus.example.test"}};
    const auto packet = linuxHelperApplyRequest(owner, request, configuration);
    check(validLinuxHelperRequest(packet) && packet.size() == 9 && packet["address"] == "198.18.0.1"
        && packet["peer"] == "198.18.0.2" && packet["mtu"] == 1400
        && packet["prefixes"] == QJsonArray{QJsonValue("198.18.0.6/32"), QJsonValue("198.18.1.0/24")}
        && packet["dns_domains"] == QJsonArray{QJsonValue("campus.example.test")},
        QStringLiteral("Valid configuration lost its semantics"));
    for (const auto *operation : {"probe", "restore", "cleanup", "close"})
        check(validLinuxHelperRequest(linuxHelperRequest(operation, owner, request)),
            QStringLiteral("Bound owner operation was rejected"));
    check(validLinuxHelperRequest(linuxHelperExtendRequest(owner, request, {"198.18.0.9"}))
        && validLinuxHelperRequest(linuxHelperRoutesRequest(owner, request, {"198.18.1.0/24"})),
        QStringLiteral("DNS publication or capture replacement request was rejected"));
    for (const auto *key : {"version", "owner", "request_id", "operation", "address", "peer", "mtu", "prefixes", "dns_domains"}) {
        auto broken = packet; broken.remove(key);
        check(!validLinuxHelperRequest(broken), QStringLiteral("Incomplete request crossed the privilege boundary"));
    }
    auto braced = packet; braced["owner"] = owner.toString();
    check(!validLinuxHelperRequest(braced), QStringLiteral("Noncanonical owner crossed the boundary"));
    auto injected = packet; injected["program"] = "/bin/sh";
    check(!validLinuxHelperRequest(injected), QStringLiteral("Arbitrary execution field was accepted"));
    auto fractional = packet; fractional["mtu"] = 1400.5;
    check(!validLinuxHelperRequest(fractional), QStringLiteral("Non-integer MTU was accepted"));

    const auto probeRequest = linuxHelperRequest("probe", owner, request);
    const auto bare = QJsonObject{{"version", LinuxHelperProtocol}, {"operation", QStringLiteral("probe")},
        {"owner", owner.toString(QUuid::WithoutBraces)}, {"request_id", request.toString(QUuid::WithoutBraces)},
        {"status", QLatin1String(LinuxHelperStatusOk)}};
    const auto probeResult = parseLinuxHelperResponse(bare, probeRequest);
    check(probeResult && probeResult->succeeded() && !probeResult->mayHaveChanged && probeResult->detail.isEmpty(),
        QStringLiteral("Probe success lost its non-mutating semantics"));
    auto withDetail = bare; withDetail["detail"] = QStringLiteral("ready");
    check(parseLinuxHelperResponse(withDetail, probeRequest).has_value(),
        QStringLiteral("Optional detail was treated as a protocol violation"));
    for (const auto *mode : {"resolved", "file", ""}) {
        auto withMode = bare; withMode["dns_mode"] = QLatin1String(mode);
        check(parseLinuxHelperResponse(withMode, probeRequest).has_value(),
            QStringLiteral("Known DNS mechanism was rejected"));
    }
    for (const auto &mode : {QJsonValue("multicast"), QJsonValue(1), QJsonValue("resolved-dns")}) {
        auto broken = bare; broken["dns_mode"] = mode;
        check(!parseLinuxHelperResponse(broken, probeRequest), QStringLiteral("Unknown DNS mechanism was accepted"));
    }
    for (const auto &mutation : {std::pair<const char *, QJsonValue>{"operation", "extend"},
            std::pair<const char *, QJsonValue>{"owner", QUuid::createUuid().toString(QUuid::WithoutBraces)},
            std::pair<const char *, QJsonValue>{"request_id", request.toString()},
            std::pair<const char *, QJsonValue>{"version", 2},
            std::pair<const char *, QJsonValue>{"status", "granted"},
            std::pair<const char *, QJsonValue>{"detail", 1}}) {
        auto broken = bare; broken[mutation.first] = mutation.second;
        check(!parseLinuxHelperResponse(broken, probeRequest), QStringLiteral("Drifted reply envelope was accepted"));
    }
    auto padded = bare; padded["unexpected"] = true;
    check(!parseLinuxHelperResponse(padded, probeRequest), QStringLiteral("Reply with an extra field was accepted"));

    // Status mapping and the mutating flag for owned operations.
    const QJsonObject applyBare{{"version", LinuxHelperProtocol}, {"operation", QStringLiteral("apply")},
        {"owner", owner.toString(QUuid::WithoutBraces)}, {"request_id", request.toString(QUuid::WithoutBraces)},
        {"status", QLatin1String(LinuxHelperStatusOk)}};
    const auto applyResult = parseLinuxHelperResponse(applyBare, packet);
    check(applyResult && applyResult->succeeded() && applyResult->mayHaveChanged,
        QStringLiteral("Apply success lost its mutating semantics"));
    for (const auto &status : {std::pair<const char *, PlatformOperationResult::Status>{LinuxHelperStatusFailed, PlatformOperationResult::Status::Failed},
            std::pair<const char *, PlatformOperationResult::Status>{LinuxHelperStatusPermissionDenied, PlatformOperationResult::Status::PermissionDenied},
            std::pair<const char *, PlatformOperationResult::Status>{LinuxHelperStatusUnsupported, PlatformOperationResult::Status::Unsupported}}) {
        auto failed = applyBare; failed["status"] = QLatin1String(status.first); failed["detail"] = QStringLiteral("reason");
        const auto result = parseLinuxHelperResponse(failed, packet);
        check(result && result->status == status.second && result->mayHaveChanged,
            QStringLiteral("Failure status mapping lost the actual status"));
    }
    for (const auto *carried : {"device", "dns_mode"}) {
        auto failed = applyBare; failed["status"] = QLatin1String(LinuxHelperStatusFailed);
        if (QLatin1String(carried) == QLatin1String("device")) failed["device"] = QJsonObject{};
        else failed["dns_mode"] = QStringLiteral("file");
        check(!parseLinuxHelperResponse(failed, packet), QStringLiteral("Failure reply carried ownership data"));
    }

    // Device envelope: exactly five typed fields with a canonical unicast pair.
    const QJsonObject device{{"name", QStringLiteral("jc0")}, {"index", 42}, {"mtu", 1400},
        {"address", QStringLiteral("198.18.0.1")}, {"peer", QStringLiteral("198.18.0.2")}};
    auto applied = applyBare; applied["device"] = device;
    const auto parsed = parseLinuxHelperDevice(applied);
    check(parsed && parsed->name == QStringLiteral("jc0") && parsed->index == 42 && parsed->mtu == 1400
        && parsed->address == QStringLiteral("198.18.0.1") && parsed->peer == QStringLiteral("198.18.0.2"),
        QStringLiteral("Valid device envelope lost its semantics"));
    for (const auto &mutation : {std::pair<const char *, QJsonValue>{"name", QStringLiteral("jc0123456789abcd")},
            std::pair<const char *, QJsonValue>{"index", 0}, std::pair<const char *, QJsonValue>{"mtu", 1400.5},
            std::pair<const char *, QJsonValue>{"mtu", 65536}, std::pair<const char *, QJsonValue>{"address", "127.0.0.1"},
            std::pair<const char *, QJsonValue>{"address", "198.18.0.2"}, std::pair<const char *, QJsonValue>{"address", "198.18.00.1"},
            std::pair<const char *, QJsonValue>{"peer", "0.0.0.0"}, std::pair<const char *, QJsonValue>{"peer", "224.0.0.1"}}) {
        auto broken = applied; auto envelope = broken["device"].toObject(); envelope[mutation.first] = mutation.second;
        broken["device"] = envelope;
        check(!parseLinuxHelperDevice(broken), QStringLiteral("Unsafe device envelope was accepted"));
    }
    auto shortDevice = applied; auto envelope = shortDevice["device"].toObject(); envelope.remove("mtu");
    shortDevice["device"] = envelope;
    check(!parseLinuxHelperDevice(shortDevice), QStringLiteral("Device envelope with a missing field was accepted"));
    check(parseLinuxHelperDnsMode(applied).isEmpty() && parseLinuxHelperDnsMode(bare).isEmpty(),
        QStringLiteral("Missing dns_mode was not reported as absent"));
}

static void availabilityChecks()
{
    const auto report = linuxNetworkHelperAvailability();
    const auto helper = linuxNetworkHelperExecutable();
    check(helper.isEmpty() || QFileInfo::exists(helper), QStringLiteral("Resolved helper path does not exist"));
    if (report.available)
        check(!helper.isEmpty(), QStringLiteral("Available routing lost its helper executable"));
    else
        check(!report.helperDetail.isEmpty() || !report.routingDetail.isEmpty(),
            QStringLiteral("Unavailable routing lost its diagnostic"));
    if (!helper.isEmpty())
        check(QFileInfo(helper).ownerId() == 0, QStringLiteral("Resolved helper is not root-owned"));
}

static void preparationChecks()
{
    const auto resources = QJsonDocument::fromJson(R"({"ip_resources":[{"ip_min":"203.0.113.8","ip_max":"203.0.113.9","protocol":"tcp","port_min":22,"port_max":22}],
        "domain_resources":{"campus.test":[{"protocol":"tcp","port_min":22,"port_max":22}]},"dns_records":{},
        "campus_dns":"203.0.113.53","campus_dns_enabled":true,"underlay_interface":""})").object();
    const QJsonObject protection{{"protected", QJsonArray{"192.0.2.0/24"}}, {"campus", QJsonArray{}},
        {"protected_names", QJsonArray{}}, {"campus_names", QJsonArray{}}};
    const QJsonObject network{{"interfaces", QJsonArray{QJsonObject{{"addresses", QJsonArray{"192.0.2.1/24"}}}}},
        {"routes", QJsonArray{QJsonObject{{"destination", "0.0.0.0/0"}}}}};
    const QJsonObject dns{{"resolv_conf", QJsonObject{{"nameservers", QJsonArray{"10.0.0.1", "10.0.0.2"}}}}};
    const auto prepared = prepareLinuxNetworkHelper(resources, protection, network, dns, "10.0.0.3:53", 1400);
    check(prepared.result.succeeded() && prepared.configuration.capturePrefixes == QStringList{"203.0.113.8/31", "203.0.113.53/32"}
        && prepared.configuration.dnsDomains == QStringList{"campus.test"} && prepared.configuration.mtu == 1400
        && prepared.configuration.address == QStringLiteral("10.0.0.4") && prepared.configuration.peer == QStringLiteral("10.0.0.5"),
        QStringLiteral("Linux preparation lost actual resource scopes or captured an existing DNS endpoint (%1: %2)")
            .arg(prepared.result.detail, prepared.configuration.capturePrefixes.join(QChar(','))));
    const auto unchanged = updatedLinuxCapturePrefixes(resources, protection, prepared.configuration, network, dns);
    check(unchanged && *unchanged == prepared.configuration.capturePrefixes, QStringLiteral("Unchanged scope drifted"));
    auto drifted = resources; drifted["campus_dns"] = QStringLiteral("203.0.113.99");
    const auto updated = updatedLinuxCapturePrefixes(drifted, protection, prepared.configuration, network, dns);
    check(updated && updated->contains(QStringLiteral("203.0.113.99/32")) && *updated != prepared.configuration.capturePrefixes,
        QStringLiteral("Campus DNS drift was ignored"));
    auto domainDrift = resources;
    domainDrift["domain_resources"] = QJsonObject{{"campus.test", QJsonArray{QJsonValue("203.0.113.20")}},
        {"other.test", QJsonArray{QJsonValue("203.0.113.21")}}};
    check(!updatedLinuxCapturePrefixes(domainDrift, protection, prepared.configuration, network, dns),
        QStringLiteral("Campus domain drift was ignored"));
    auto missing = resources; missing["underlay_interface"] = QStringLiteral("justconnect-nonexistent-interface");
    check(!prepareLinuxNetworkHelper(missing, protection, network, dns, {}, 1400).result.succeeded(),
        QStringLiteral("Missing selected underlay was silently ignored"));

    // A policy that protects a campus-covered suffix needs original resolver
    // rows: the covered campus scope drops from the installed answer set and
    // the resolvers leave the capture, so fall-through keeps them working.
    const auto coveredPolicy = QJsonObject{{"protected", protection["protected"]}, {"campus", QJsonArray{}},
        {"protected_names", QJsonArray{QJsonObject{{"kind", QStringLiteral("suffix")}, {"value", QStringLiteral("campus.test")}}}},
        {"campus_names", QJsonArray{}}};
    const auto forwarded = prepareLinuxNetworkHelper(resources, coveredPolicy, network, dns, QStringLiteral("10.0.0.3:53"), 1400);
    check(forwarded.result.succeeded() && forwarded.configuration.dnsDomains.isEmpty()
        && forwarded.configuration.capturePrefixes == QStringList{QStringLiteral("203.0.113.8/31"), QStringLiteral("203.0.113.53/32")},
        QStringLiteral("Protected campus-covered scope lost its capture plan (%1: %2)")
            .arg(forwarded.result.detail, forwarded.configuration.dnsDomains.join(QChar(','))));
    const auto sources = linuxOriginalDnsSources(dns, requiredOriginalDnsNames(resources, coveredPolicy).value_or(QJsonArray{}));
    check(sources && sources->size() == 1 && sources->at(0).toObject()["name"] == coveredPolicy["protected_names"].toArray().at(0)
        && sources->at(0).toObject()["servers"].toArray() == QJsonArray{QJsonValue("10.0.0.1:53"), QJsonValue("10.0.0.2:53")},
        QStringLiteral("Original DNS rows lost the required rule or the snapshot resolvers"));
    const auto stable = updatedLinuxCapturePrefixes(resources, coveredPolicy, forwarded.configuration, network, dns);
    check(stable && *stable == forwarded.configuration.capturePrefixes,
        QStringLiteral("Forwarded protected names drifted without a change"));
    const QJsonObject dry{{"resolv_conf", QJsonObject{{"nameservers", QJsonArray{}}}}};
    check(!updatedLinuxCapturePrefixes(resources, coveredPolicy, forwarded.configuration, network, dry),
        QStringLiteral("Losing every original resolver kept the session alive"));
    check(!prepareLinuxNetworkHelper(resources, coveredPolicy, network, dry, QStringLiteral("10.0.0.3:53"), 1400).result.succeeded(),
        QStringLiteral("A required protected name survived without any original resolver"));
    check(linuxOriginalDnsSources(dns, QJsonArray{}).has_value() && linuxOriginalDnsSources(dns, QJsonArray{})->isEmpty(),
        QStringLiteral("No required names invented original rows"));
    const QJsonObject literalDns{{"resolv_conf", QJsonObject{{"nameservers", QJsonArray{
        QJsonValue("2001:db8::1"), QJsonValue("doh.invalid"), QJsonValue("0.0.0.0"), QJsonValue("10.0.0.9")}}}}};
    const auto literals = linuxOriginalDnsSources(literalDns, requiredOriginalDnsNames(resources, coveredPolicy).value_or(QJsonArray{}));
    check(literals && literals->at(0).toObject()["servers"].toArray() == QJsonArray{
            QJsonValue("[2001:db8::1]:53"), QJsonValue("10.0.0.9:53")},
        QStringLiteral("Original DNS endpoints lost their canonical addr:port form"));
    const QJsonObject splitDns{{"resolved", QJsonObject{{"links", QJsonArray{
        QJsonObject{{"default_route", true}, {"servers", QJsonArray{"10.0.0.1"}}, {"domains", QJsonArray{}}},
        QJsonObject{{"servers", QJsonArray{"100.100.100.100"}}, {"domains", QJsonArray{"~campus.example.test"}}},
        QJsonObject{{"servers", QJsonArray{"10.0.0.9"}}, {"domains", QJsonArray{"lab.campus.example.test"}}},
    }}}}};
    const auto scoped = linuxOriginalDnsSources(splitDns, QJsonArray{
        QJsonObject{{"kind", "suffix"}, {"value", "campus.example.test"}},
        QJsonObject{{"kind", "exact"}, {"value", "node.lab.campus.example.test"}},
        QJsonObject{{"kind", "single_label"}, {"value", ""}},
    });
    check(scoped && scoped->size() == 3
        && scoped->at(0).toObject()["servers"].toArray() == QJsonArray{"100.100.100.100:53"}
        && scoped->at(1).toObject()["servers"].toArray() == QJsonArray{"10.0.0.9:53"}
        && scoped->at(2).toObject()["servers"].toArray() == QJsonArray{"10.0.0.9:53"},
        QStringLiteral("Split DNS names were forwarded to the wrong resolvers"));
}

static void ownershipChecks()
{
    const LinuxHelperConfiguration configuration{"198.18.0.1", "198.18.0.2", 1400,
        {"198.18.0.6/32", "198.18.1.0/24"}, {"campus.example.test"}};
    const LinuxHelperDevice device{QStringLiteral("jc0"), 42, 1400, QStringLiteral("198.18.0.1"), QStringLiteral("198.18.0.2")};
    check(!linuxOriginalNetworkView(configuration, {QString(), 42, 1400, QStringLiteral("198.18.0.1"), QStringLiteral("198.18.0.2")},
            QStringLiteral("resolved")), QStringLiteral("Nameless device acquired a network view"));
    check(!linuxOriginalNetworkView(configuration, device, QStringLiteral("dhcp")),
        QStringLiteral("Unknown DNS mode acquired a network view"));
    check(!linuxOriginalNetworkView(configuration, device, QStringLiteral("file")),
        QStringLiteral("The removed resolv.conf file mode acquired a network view"));
    check(!linuxOriginalNetworkView({"127.0.0.1", "198.18.0.2", 1400, {}, {}}, device, QStringLiteral("resolved")),
        QStringLiteral("Loopback ownership acquired a network view"));
    const QJsonObject network{{"interfaces", QJsonArray{
            QJsonObject{{"name", "eth0"}, {"index", 2}, {"up", true}, {"addresses", QJsonArray{"192.0.2.5/24"}}},
            QJsonObject{{"name", "jc0"}, {"index", 42}, {"up", true}, {"addresses", QJsonArray{"198.18.0.1/30"}}}}},
        {"routes", QJsonArray{QJsonObject{{"destination", "198.18.0.6/32"}, {"interface_index", 42}},
            QJsonObject{{"destination", "198.18.1.0/24"}, {"interface_index", 42}},
            QJsonObject{{"destination", "198.18.0.7/32"}, {"interface_index", 2}}}}};
    // Per-link resolver state: the helper's entry rides the owned TUN link; a
    // foreign split-DNS entry on the underlay must survive every subtraction.
    const QJsonObject dns{
        {"resolv_conf", QJsonObject{
            {"nameservers", QJsonArray{"10.0.0.1"}},
            {"search", QJsonArray{"campus.example.test"}}}},
        {"resolved", QJsonObject{
            {"links", QJsonArray{
                QJsonObject{
                    {"index", 2}, {"interface", "eth0"},
                    {"servers", QJsonArray{"10.0.0.1"}},
                    {"domains", QJsonArray{"~foreign.example"}}},
                QJsonObject{
                    {"index", 42}, {"interface", "jc0"},
                    {"servers", QJsonArray{"198.18.0.2"}},
                    {"domains", QJsonArray{"~campus.example.test"}}}}}}}};
    const auto filter = linuxOriginalNetworkView(configuration, device, QStringLiteral("resolved"));
    check(static_cast<bool>(filter), QStringLiteral("Valid ownership lost its network view"));
    const auto view = filter(network, dns, nullptr);
    check(view && view->first["interfaces"].toArray().size() == 1
        && view->first["interfaces"].toArray().at(0).toObject()["name"] == "eth0"
        && view->first["routes"].toArray().size() == 1
        && view->first["routes"].toArray().at(0).toObject()["destination"] == "198.18.0.7/32",
        QStringLiteral("Resolved-mode view kept the owned interface, its routes or lost the original exit"));
    const auto links = view->second["resolved"].toObject()["links"].toArray();
    check(links.size() == 1 && links.at(0).toObject()["interface"] == "eth0"
        && links.at(0).toObject()["domains"].toArray() == QJsonArray{QJsonValue("~foreign.example")},
        QStringLiteral("Resolved-mode view kept the owned per-link resolver or lost a foreign split-DNS entry"));
    check(view->second["resolv_conf"].toObject()["nameservers"].toArray() == QJsonArray{QJsonValue("10.0.0.1")},
        QStringLiteral("Resolved-mode view changed the host resolver snapshot"));
    const auto dnslessView = linuxOriginalNetworkView(configuration, device, QString())(network, dns, nullptr);
    check(dnslessView && dnslessView->second == dns, QStringLiteral("DNS-less ownership changed the snapshot"));
    // Drift in the owned interface, its identity or its resolver entry fails closed.
    QString reason;
    check(!filter(QJsonObject{{"interfaces", QJsonArray{QJsonObject{{"name", "eth0"}, {"index", 2}, {"up", true}}}},
        {"routes", QJsonArray{}}}, dns, &reason) && reason.contains("missing from the network snapshot"),
        QStringLiteral("Missing owned device kept a network view"));
    // A desktop network manager may briefly flip the foreign device's up flag
    // while adopting it; the row is still subtracted by name and index.
    auto down = network; auto rows = down["interfaces"].toArray(); auto owned = rows.at(1).toObject();
    owned["up"] = false; rows.replace(1, owned); down["interfaces"] = rows;
    const auto downView = filter(down, dns, &reason);
    check(downView.has_value() && view.has_value() && *downView == *view,
        QStringLiteral("A torn-down owned device still lost its network view"));
    auto duplicate = network; rows = duplicate["interfaces"].toArray(); rows.append(rows.at(1));
    duplicate["interfaces"] = rows;
    check(!filter(duplicate, dns, &reason) && reason.contains("duplicated"),
        QStringLiteral("Duplicated owned device kept a network view"));
    auto unresolved = dns;
    auto resolved = unresolved["resolved"].toObject();
    resolved["links"] = QJsonArray{QJsonObject{{"index", 2}, {"interface", "eth0"},
        {"servers", QJsonArray{"10.0.0.1"}}, {"domains", QJsonArray{"~foreign.example"}}}};
    unresolved["resolved"] = resolved;
    check(!filter(network, unresolved, &reason) && reason.contains("owned per-link resolver is missing"),
        QStringLiteral("Missing owned per-link resolver kept a resolved-mode view"));
    auto unlisted = dns;
    unlisted["resolved"] = QJsonObject{{"global", true}};
    check(!filter(network, unlisted, &reason) && reason.contains("link list"),
        QStringLiteral("A resolver snapshot without a link list kept a resolved-mode view"));
    auto withOwnedLink = [&dns](const std::function<void(QJsonObject &)> &change) {
        auto resolved = dns["resolved"].toObject();
        QJsonArray rows;
        for (const auto &value : resolved["links"].toArray()) {
            auto row = value.toObject();
            if (row["interface"] == "jc0") change(row);
            rows.append(row);
        }
        resolved["links"] = rows;
        auto updated = dns;
        updated["resolved"] = resolved;
        return updated;
    };
    const auto addedServer = withOwnedLink([](QJsonObject &row) {
        row["servers"] = QJsonArray{"198.18.0.2", "10.0.0.1"};
    });
    const auto searchDomain = withOwnedLink([](QJsonObject &row) { row["domains"] = QJsonArray{"campus.example.test"}; });
    const auto extraScope = withOwnedLink([](QJsonObject &row) {
        row["domains"] = QJsonArray{"~campus.example.test", "~."};
    });
    check(!filter(network, addedServer, &reason) && !filter(network, searchDomain, &reason)
        && !filter(network, extraScope, &reason),
        QStringLiteral("A change to the owned DNS servers or route-only domains was hidden"));
}

static void clientScenarios()
{
    const LinuxHelperConfiguration configuration{"198.18.0.1", "198.18.0.2", 1400,
        {"198.18.0.6/32", "198.18.1.0/24"}, {"campus.example.test"}};
    // A dialer with the test user's uid must never be accepted by the default
    // (root-only) client.
    if (::getuid() != 0) {
        FakeHelper fake;
        int launches = 0;
        LinuxNetworkHelperClient helper(nullptr, [&](QProcess *, const QStringList &arguments) {
            ++launches;
            fake.start(arguments.at(2).mid(1));
        });
        const auto step = awaitStep(helper, "rejection probe", [&] { helper.inspect(QUuid::createUuid()); });
        check(step.finished && step.finished->status == PlatformOperationResult::Status::Failed
            && step.finished->detail.contains(QStringLiteral("unexpected process")),
            QStringLiteral("Unauthorized helper dial was not rejected"));
        check(launches == 1 && helper.state() == LinuxNetworkHelperClient::State::Idle,
            QStringLiteral("Rejected dial left the client inconsistent"));
        fake.join();
    }
    // Full authorized flow: one launch serves probe, apply, extend, routes,
    // restore, a reused probe and the final close. The authorized client must
    // trust this process's uid, which is what the privileged helper would own.
    {
        FakeHelper fake;
        int launches = 0;
        LinuxNetworkHelperClient helper(nullptr, [&](QProcess *, const QStringList &arguments) {
            ++launches;
            fake.start(arguments.at(2).mid(1));
        }, ::getuid());
        const auto probe = awaitStep(helper, "authorized probe", [&] { helper.inspect(QUuid::createUuid()); });
        check(probe.finished && probe.finished->succeeded() && !probe.finished->mayHaveChanged
            && helper.dnsMode() == QStringLiteral("resolved") && launches == 1,
            QStringLiteral("Probe did not complete without authorization (finished=%1 lost=%2 status=%3 detail=%4 dnsMode=%5 launches=%6)")
                .arg(probe.finished.has_value() ? QStringLiteral("yes") : QStringLiteral("no"),
                    probe.lost.has_value() ? QStringLiteral("yes") : QStringLiteral("no"),
                    probe.finished ? QString::number(int(probe.finished->status)) : QStringLiteral("-"),
                    probe.finished ? probe.finished->detail : QString(),
                    helper.dnsMode(), QString::number(launches)));
        const auto owner = QUuid::createUuid();
        const auto apply = awaitStep(helper, "authorized apply", [&] { helper.apply(owner, configuration); });
        check(apply.finished && apply.finished->succeeded() && apply.finished->mayHaveChanged
            && helper.state() == LinuxNetworkHelperClient::State::Active && helper.owner() == owner
            && helper.descriptor() >= 0 && helper.dnsMode() == QStringLiteral("resolved"),
            QStringLiteral("Apply did not activate the owned session"));
        check(::fcntl(helper.descriptor(), F_GETFD) >= 0 && (::fcntl(helper.descriptor(), F_GETFD) & FD_CLOEXEC),
            QStringLiteral("Received descriptor lost its close-on-exec flag"));
        check(helper.ownedDevice() && helper.ownedDevice()->name == QStringLiteral("jc0")
            && helper.ownedDevice()->address == configuration.address && helper.ownedConfiguration()
            && helper.ownedConfiguration()->capturePrefixes == configuration.capturePrefixes,
            QStringLiteral("Owned envelope lost its configuration"));
        const auto extend = awaitStep(helper, "authorized extend", [&] { helper.extend({"198.18.0.9"}); });
        check(extend.finished && extend.finished->succeeded()
            && helper.state() == LinuxNetworkHelperClient::State::Active && launches == 1,
            QStringLiteral("Extend did not complete or re-launched the helper"));
        const auto reconcile = awaitStep(helper, "authorized routes", [&] { helper.reconcile({"198.18.1.0/24"}); });
        check(reconcile.finished && reconcile.finished->succeeded()
            && helper.state() == LinuxNetworkHelperClient::State::Active,
            QStringLiteral("Capture replacement did not complete"));
        const auto restore = awaitStep(helper, "authorized restore", [&] { helper.restore(); });
        check(restore.finished && restore.finished->succeeded() && helper.state() == LinuxNetworkHelperClient::State::Idle
            && helper.descriptor() == -1 && !helper.ownedDevice() && !helper.restorationPending(),
            QStringLiteral("Restore did not withdraw the owned session"));
        const auto probedAgain = awaitStep(helper, "reused probe", [&] { helper.inspect(QUuid::createUuid()); });
        check(probedAgain.finished && probedAgain.finished->succeeded() && launches == 1,
            QStringLiteral("A reused helper was launched again"));
        const auto close = awaitStep(helper, "authorized close", [&] { helper.close(); });
        check(close.finished && close.finished->succeeded() && !close.lost,
            QStringLiteral("Close did not complete or lost ownership"));
        fake.join();
    }
    // pkexec-style denial: exit status 126 maps to a permission failure.
    {
        LinuxNetworkHelperClient helper(nullptr, [](QProcess *process, const QStringList &) {
            process->setProgram(QStringLiteral("sh"));
            process->setArguments({QStringLiteral("-c"), QStringLiteral("exit 126")});
            process->start();
        });
        const auto step = awaitStep(helper, "pkexec denial probe", [&] { helper.inspect(QUuid::createUuid()); });
        check(step.finished && step.finished->status == PlatformOperationResult::Status::PermissionDenied,
            QStringLiteral("Authorization refusal did not surface as a permission denial"));
    }
    // A silent helper may be abandoned: cancel reports Cancelled, not a failure.
    {
        FakeHelper fake; fake.stallApply = true;
        int launches = 0;
        LinuxNetworkHelperClient helper(nullptr, [&](QProcess *, const QStringList &arguments) {
            ++launches;
            fake.start(arguments.at(2).mid(1));
        }, ::getuid());
        const auto probe = awaitStep(helper, "stalled probe", [&] { helper.inspect(QUuid::createUuid()); });
        check(probe.finished && probe.finished->succeeded(), QStringLiteral("Probe did not complete"));
        const auto apply = awaitStep(helper, "stalled apply", [&] {
            helper.apply(QUuid::createUuid(), configuration);
            QTimer::singleShot(150, &helper, [&helper] { helper.cancel(); });
        });
        check(apply.finished && apply.finished->status == PlatformOperationResult::Status::Cancelled
            && helper.state() == LinuxNetworkHelperClient::State::Idle && helper.restorationPending() && launches == 1,
            QStringLiteral("Cancelled apply released unconfirmed ownership"));
        fake.join();
    }
    // A helper that dies while owning state surfaces ownershipLost; the reply
    // and the EOF can be coalesced into one socket activation, so both
    // terminals are captured in one loop instead of two sequential waits.
    {
        FakeHelper fake; fake.dropAfterApply = true;
        int launches = 0;
        LinuxNetworkHelperClient helper(nullptr, [&](QProcess *, const QStringList &arguments) {
            ++launches;
            fake.start(arguments.at(2).mid(1));
        }, ::getuid());
        const auto probe = awaitStep(helper, "dying probe", [&] { helper.inspect(QUuid::createUuid()); });
        check(probe.finished && probe.finished->succeeded(), QStringLiteral("Probe did not complete"));
        Step step;
        QEventLoop loop;
        const auto record = [&loop, &step] {
            if (step.finished && step.lost) loop.quit();
        };
        const auto finishedConnection = QObject::connect(&helper, &LinuxNetworkHelperClient::finished,
            [&](LinuxNetworkHelperClient::Operation, const PlatformOperationResult &result) { step.finished = result; record(); });
        const auto lostConnection = QObject::connect(&helper, &LinuxNetworkHelperClient::ownershipLost,
            [&](const PlatformOperationResult &result) { step.lost = result; record(); });
        QTimer watchdog;
        watchdog.setSingleShot(true);
        QObject::connect(&watchdog, &QTimer::timeout, &loop, &QEventLoop::quit);
        watchdog.start(15000);
        helper.apply(QUuid::createUuid(), configuration);
        loop.exec();
        watchdog.stop();
        QObject::disconnect(finishedConnection);
        QObject::disconnect(lostConnection);
        check(step.finished && step.finished->succeeded() && step.lost && step.lost->mayHaveChanged
            && helper.state() == LinuxNetworkHelperClient::State::Idle && helper.descriptor() == -1
            && helper.restorationPending() && launches == 1,
            QStringLiteral("Helper death did not report apply success and ownership loss (finished=%1 lost=%2 state=%3 descriptor=%4)")
                .arg(step.finished.has_value() ? QStringLiteral("yes") : QStringLiteral("no"),
                    step.lost.has_value() ? QStringLiteral("yes") : QStringLiteral("no"),
                    QString::number(int(helper.state())), QString::number(helper.descriptor())));
        fake.join();
        const auto recovered = awaitStep(helper, "replacement helper confirmed recovery", [&] { helper.inspect(QUuid::createUuid()); });
        check(recovered.finished && recovered.finished->succeeded() && !helper.restorationPending() && launches == 2,
            QStringLiteral("Recovery could not be confirmed by a replacement helper"));
        const auto close = awaitStep(helper, "close replacement helper", [&] { helper.close(); });
        check(close.finished && close.finished->succeeded(), QStringLiteral("Closing the replacement helper failed"));
        fake.join();
    }
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    protocolChecks();
    availabilityChecks();
    preparationChecks();
    ownershipChecks();
    clientScenarios();
    std::cout << "networkhelper_linux_test: all checks passed" << std::endl;
    return 0;
}
catch (const std::exception &error)
{
    std::cerr << error.what() << std::endl;
    return 1;
}
