#pragma once
#include "application/coexistencenetworkaccess.h"
#include "infrastructure/systemproxy/proxyrecovery.h"
#include "infrastructure/systemproxy/proxychanges.h"
#include "infrastructure/process/command.h"
#include <QLocalSocket>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <sys/socket.h>

static int exerciseCoexistenceNetworkAccess(const ConnectionProfile &profile)
{
    const auto fixture = QJsonDocument::fromJson(qgetenv("JC_NATIVE_COEXISTENCE_RUNTIME")).object();
    const auto controller = fixture["controller"].toString();
    const auto pid = fixture["pid"].toInteger();
    const auto port = fixture["port"].toInt();
    check(QFileInfo(controller).isAbsolute() && pid > 0 && port > 0 && port <= 65535
        && qgetenv("GSETTINGS_BACKEND") == "keyfile", "requires an owned runtime and private desktop scope");
    const auto patch = [&](const QJsonObject &values) {
        QLocalSocket socket;
        socket.connectToServer(controller);
        check(socket.waitForConnected(3000), "connect the fixture's controller");
        ucred peer{}; socklen_t size = sizeof(peer);
        check(::getsockopt(socket.socketDescriptor(), SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && peer.uid == 0 && peer.pid == pid,
            "only the actual owned root runtime may receive fixture changes");
        const auto payload = QJsonDocument(values).toJson(QJsonDocument::Compact);
        const auto request = "PATCH /configs HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
            + QByteArray::number(payload.size()) + "\r\n\r\n" + payload;
        check(socket.write(request) == request.size() && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(3000)), "send owned fixture changes");
        QByteArray reply;
        while (!reply.contains("\r\n\r\n")) {
            check(socket.bytesAvailable() || socket.waitForReadyRead(3000), "owned fixture acknowledged changes");
            reply += socket.readAll();
            check(reply.size() <= 8192, "bounded fixture controller acknowledgement");
        }
        check(reply.startsWith("HTTP/1.1 204"), "runtime accepted the exact mode/TUN update");
    };
    const auto setting = [&](const QString &schema, const QString &key, const QString &value) {
        const auto result = runPlatformCommand("gsettings", {"set", schema, key, value});
        check(result.result.succeeded(), qPrintable(result.result.detail));
    };
    const auto systemProxy = [&](bool enabled) {
        if (enabled) for (const auto *protocol : {"http", "https", "socks"}) {
            const auto schema = QStringLiteral("org.gnome.system.proxy.") + protocol;
            setting(schema, "host", "'127.0.0.1'");
            setting(schema, "port", QString::number(port));
        }
        setting("org.gnome.system.proxy", "mode", enabled ? "'manual'" : "'none'");
    };
    auto *engine = new EmbeddedCoreEngine;
    NetworkPolicySession policy(engine, readSystemDnsSnapshot);
    SystemProxySession proxy(std::make_unique<ProxyRecoveryBackend>());
    QObject::connect(&proxy,&SystemProxySession::inspectionFinished,[](const SystemProxyCheck &view) {
        std::cerr << "CHECK: proxy inspect status=" << int(view.result.status) << " active=" << view.active
            << " managed=" << view.managed << " endpoints=" << view.endpoints.join(',').toStdString()
            << " detail=" << view.result.detail.toStdString() << '\n';
    });
    auto *native = new LinuxNetworkAccess(engine, &policy,
        EmbeddedCoreEngine::buildInfo()["capabilities"].toObject()["tunnel_mtu"].toInt());
    QJsonObject originalNetwork;
    QObject::connect(&policy,&NetworkPolicySession::changed,[&] {
        if (originalNetwork.isEmpty() && !policy.isBusy() && policy.status() == CoreEngine::RequestStatus::Success)
            originalNetwork = policy.model()["network"].toObject();
    });
    QObject::connect(native,&NetworkAccess::restartRequired,[&] {
        const auto current = policy.model()["network"].toObject();
        QJsonObject changes;
        for (const auto *key : {"routes","policy_rules"}) {
            QJsonArray added, removed;
            const auto before = originalNetwork[key].toArray(), after = current[key].toArray();
            for (const auto &row : after) if (!before.contains(row)) added.append(row);
            for (const auto &row : before) if (!after.contains(row)) removed.append(row);
            changes[key] = QJsonObject{{"added",added},{"removed",removed}};
        }
        std::cerr << "CHECK: native network change " << QJsonDocument(changes).toJson(QJsonDocument::Compact).toStdString() << '\n';
    });
    auto *network = new CoexistenceNetworkAccess(native, engine, &policy, &proxy);
    ProxyChanges changes;
    QObject::connect(&changes,&ProxyChanges::changed,network,&CoexistenceNetworkAccess::systemProxyChanged);
    ConnectionSession session(engine,nullptr,network);
    QObject::connect(&session,&ConnectionSession::diagnostic,[](const QString &message) { std::cerr << message.toStdString() << '\n'; });
    QObject::connect(&session,&ConnectionSession::authenticationRequired,[engine](const QJsonObject &request) {
        engine->respond(CoreEngine::responseFor(request,{{"action","submit"},{"code","fixture-code"}}));
    });
    QJsonObject resources, coexistence;
    int observations = 0;
    QObject::connect(engine,&CoreEngine::snapshotReady,[&](CoreEngine::Snapshot kind,const QString &,const QJsonObject &data,CoreEngine::RequestStatus status) {
        if (status != CoreEngine::RequestStatus::Success) return;
        if (kind == CoreEngine::Snapshot::Resources) resources = data["resources"].toObject();
        if (kind == CoreEngine::Snapshot::Coexistence) { coexistence = data["coexistence"].toObject(); ++observations; }
    });
    int finished = 0;
    QObject::connect(&session,&ConnectionSession::finished,[&](ConnectionError error) {
        check(error == ConnectionError::NONE,"the composed native session restored successfully"); ++finished;
    });
    auto connectionProfile = profile;
    connectionProfile.proxy.socksBind = "127.0.0.1:0";
    connectionProfile.proxy.httpBind = "127.0.0.1:0";
    QTimer startupDeadline;
    startupDeadline.setSingleShot(true);
    QObject::connect(&startupDeadline,&QTimer::timeout,[&] {
        std::cerr << "coexistence state=" << int(session.state()) << " phase=" << int(session.phase())
            << " proxy_busy=" << proxy.isBusy() << " owned=" << proxy.needsCleanup() << " TUN_refs=" << tunReferences()
            << " policy_busy=" << policy.isBusy() << " state=" << QJsonDocument(coexistence).toJson(QJsonDocument::Compact).toStdString() << '\n';
    });
    startupDeadline.start(9000);
    check(session.start(connectionProfile,{}),"start the actual composed application connection");
    until([&] { return session.state() == ConnectionState::Running || !session.isActive(); });
    startupDeadline.stop();
    check(session.state() == ConnectionState::Running && session.phase() == ConnectionPhase::CampusReady && tunReferences() == 2,
        "both actual network and browser ownership settle before readiness");
    QNetworkAccessManager browser;
    const auto get = [&](const QString &address, bool proxyEnabled) {
        int httpPort = 0;
        if (proxyEnabled) {
            const auto result = runPlatformCommand("gsettings",{"get","org.gnome.system.proxy.http","port"});
            httpPort = result.output.toInt();
            check(result.result.succeeded() && httpPort > 0,"read the actual current browser proxy endpoint");
            check(resources["listeners"].toObject()["http"].toString() == "127.0.0.1:" + QString::number(httpPort),
                "browser traffic uses the installed JustConnect frontend");
        }
        browser.setProxy(proxyEnabled ? QNetworkProxy(QNetworkProxy::HttpProxy,"127.0.0.1",quint16(httpPort)) : QNetworkProxy(QNetworkProxy::NoProxy));
        QNetworkRequest request{QUrl(address)};
        request.setTransferTimeout(5000);
        request.setAttribute(QNetworkRequest::Http2AllowedAttribute,false);
        auto *reply = browser.get(request);
        until([&] { return reply->isFinished(); });
        const auto body = reply->readAll();
        const bool okay = reply->error() == QNetworkReply::NoError && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200;
        reply->deleteLater();
        return qMakePair(okay,body);
    };
    const auto traffic = [&](const QString &mode, bool proxyEnabled, bool tun) {
        const auto campus = get("http://campus.test/",proxyEnabled);
        check(campus.first && campus.second == "vpn-response","campus web reaches VPN before the original Clash mode");
        auto addresses = std::async(std::launch::async,[] { return systemAddresses("campus.test"); });
        until([&] { return addresses.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
        const auto targets = addresses.get();
        check(targets.size() == 1,"campus DNS supplies one actual fixture destination");
        exerciseNativeTUNTraffic(QHostAddress(targets.first()));
        exerciseNativeSSH(QHostAddress(targets.first()));
        const bool rejected = mode == "global" && (proxyEnabled || tun);
        const auto ordinary = get("http://198.18.0.5:8080/",proxyEnabled);
        check(rejected ? !ordinary.first : ordinary.first && ordinary.second == "original-http",
            "ordinary web preserves the selected Clash exit; both switches OFF remains direct");
        const auto protectedTarget = get("http://192.0.2.2:8080/",proxyEnabled);
        check(protectedTarget.first && protectedTarget.second == "original-http","protected original network bypasses campus and ordinary upstream selection");
        const auto endpoint = resources["listeners"].toObject()["socks"].toString();
        const auto separator = endpoint.lastIndexOf(':');
        check(separator > 0,"actual SOCKS endpoint is published");
        QUdpSocket udp;
        udp.setProxy(QNetworkProxy(QNetworkProxy::Socks5Proxy,endpoint.left(separator),quint16(endpoint.mid(separator+1).toUShort())));
        udp.connectToHost(QHostAddress("198.18.0.5"),53);
        for (const auto &packet : {QByteArray("ordinary-proxy-udp"),QByteArray{}}) {
            check(udp.write(packet) == packet.size(),"ordinary UDP accepted by the actual frontend");
            const bool received = udp.waitForReadyRead(rejected ? 250 : 5000);
            if (rejected) { check(!received,"GLOBAL REJECT did not fall back to a direct ordinary UDP exit"); continue; }
            const QByteArray expected = "original:"+packet;
            QByteArray reply(expected.size(),Qt::Uninitialized);
            check(received && udp.readDatagram(reply.data(),reply.size()) == expected.size() && reply == expected,
                "actual ordinary upstream preserves UDP and empty datagrams");
        }
    };
    for (const auto *mode : {"rule","global","direct"}) {
        for (const auto &flags : {qMakePair(true,false),qMakePair(true,true),qMakePair(false,true),qMakePair(false,false)}) {
            const bool proxyEnabled = flags.first, tun = flags.second;
            const auto previous = observations;
            std::cerr << "CHECK: coexistence mode=" << mode << " system_proxy=" << proxyEnabled << " tun=" << tun << '\n';
            patch({{"mode",mode},{"tun",QJsonObject{{"enable",tun}}}});
            systemProxy(proxyEnabled);
            startupDeadline.start(9000);
            until([&] {
                if (session.state() != ConnectionState::Running) return true;
                if (observations <= previous || proxy.isBusy() || policy.isBusy() || coexistence["mode"] != mode
                    || coexistence["tun"].toBool() != tun || coexistence["active"].toBool() != (proxyEnabled || tun)
                    || proxy.isEnabled() != proxyEnabled || (proxyEnabled ? !proxy.isAutomatic() : proxy.needsCleanup())) return false;
                const auto current = runPlatformCommand("gsettings",proxyEnabled
                    ? QStringList{"get","org.gnome.system.proxy.http","port"} : QStringList{"get","org.gnome.system.proxy","mode"});
                return current.result.succeeded() && (proxyEnabled
                    ? resources["listeners"].toObject()["http"].toString() == "127.0.0.1:" + current.output
                    : current.output == "'none'");
            });
            startupDeadline.stop();
            check(session.state() == ConnectionState::Running,"runtime mode and independent switches retain campus readiness");
            traffic(mode,proxyEnabled,tun);
            std::cout << "PASS: native coexistence case mode=" << mode << " system_proxy=" << proxyEnabled << " tun=" << tun << '\n' << std::flush;
        }
    }
    session.stop();
    until([&] { return !session.isActive(); });
    check(finished == 1 && tunReferences() == 0 && !proxy.needsCleanup(),"composed stop restores browser settings before releasing native ownership");
    patch({{"mode","rule"},{"tun",QJsonObject{{"enable",true}}}});
    systemProxy(true);
    // The local authentication fixture cannot observe a physical transport socket.
    connectionProfile.behavior.bindInterface = fixture["original_interface"].toString();
    check(!connectionProfile.behavior.bindInterface.isEmpty(),"the isolated peer supplies its actual original interface");
    check(session.start(connectionProfile,{}),"start while the original proxy TUN is already active");
    until([&] { return session.state() == ConnectionState::Running || !session.isActive(); });
    check(session.state() == ConnectionState::Running && proxy.isAutomatic(),"initial protection recognizes the verified original proxy TUN");
    traffic("rule",true,true);
    session.stop();
    until([&] { return !session.isActive(); });
    check(finished == 2 && tunReferences() == 0 && !proxy.needsCleanup(),"restart with the original TUN restores ownership");
    std::cout << "PASS: native coexistence initial TUN startup and restoration\n";
    return 0;
}
