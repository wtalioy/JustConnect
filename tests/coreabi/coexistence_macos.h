#pragma once
#include "application/coexistencenetworkaccess.h"
#include "infrastructure/systemproxy/platformsystemproxybackend.h"
#include "infrastructure/systemproxy/proxychanges.h"
#include "infrastructure/process/command.h"
#include <QLocalSocket>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <sys/socket.h>
#include <sys/un.h>

class MacCoexistenceFixture
{
public:
    QJsonObject runtime = QJsonDocument::fromJson(qgetenv("JC_NATIVE_MAC_COEXISTENCE")).object();
    QJsonObject resources, coexistence;
    int observations = 0;
    MacProxyApi api;

    explicit MacCoexistenceFixture(const AuthorizationExternalForm &grant)
    {
        if (runtime.isEmpty()) return;
        check(QFileInfo(runtime["controller"].toString()).isAbsolute() && runtime["pid"].toInteger() > 0
            && runtime["port"].toInt() > 0 && runtime["port"].toInt() <= 65535,"parent-owned native runtime facts");
        api.open = [grant](AuthorizationRef *authorization) {
            if (AuthorizationCreateFromExternalForm(&grant,authorization) != errAuthorizationSuccess) return SCPreferencesRef(nullptr);
            return SCPreferencesCreateWithAuthorization(nullptr,CFSTR("JustConnect disposable coexistence"),nullptr,*authorization);
        };
        original = std::make_unique<PlatformSystemProxyBackend>(api);
        config.httpPort = config.socksPort = quint16(runtime["port"].toInt());
        check(original->apply(config).succeeded(),"apply the original proxy using a real preauthorized system right");
    }
    void observe(CoreEngine *engine)
    {
        QObject::connect(engine,&CoreEngine::snapshotReady,engine,[this](CoreEngine::Snapshot kind,const QString &,const QJsonObject &data,CoreEngine::RequestStatus status) {
            if (status != CoreEngine::RequestStatus::Success) return;
            if (kind == CoreEngine::Snapshot::Resources) resources = data["resources"].toObject();
            if (kind == CoreEngine::Snapshot::Coexistence) { coexistence = data["coexistence"].toObject(); ++observations; }
        });
    }
    void restore()
    {
        patch({{"mode","rule"},{"tun",QJsonObject{{"enable",false}}}});
        systemProxy(true);
        check(original->clear().succeeded(),"restore original service proxy fields after releasing application ownership");
    }
    void exercise(ConnectionSession &session,SystemProxySession &proxy,NetworkPolicySession &policy)
    {
        const auto get = [&](const QString &url,bool enabled) {
            const auto port = httpPort();
            if (enabled) check(port > 0 && resources["listeners"].toObject()["http"].toString() == "127.0.0.1:"+QString::number(port),
                "actual service browser endpoint belongs to the published frontend");
            else check(port == 0,"OFF remains disabled in actual network preferences");
            browser.setProxy(enabled ? QNetworkProxy(QNetworkProxy::HttpProxy,"127.0.0.1",quint16(port)) : QNetworkProxy(QNetworkProxy::NoProxy));
            QNetworkRequest request{QUrl(url)}; request.setTransferTimeout(5000);
            request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,QNetworkRequest::ManualRedirectPolicy);
            request.setRawHeader("Connection","close");
            auto *reply = browser.get(request); until([&] { return reply->isFinished(); });
            const auto code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const auto body = reply->readAll();
            const bool okay = reply->error() == QNetworkReply::NoError && code >= 200 && code < 400;
            reply->deleteLater(); return qMakePair(okay,body);
        };
        systemProxy(false);
        until([&] { return !proxy.isBusy() && !proxy.needsCleanup(); });
        check(get(runtime["ordinary_url"].toString(),false).first,"actual public HTTP baseline is reachable");
        for (const auto *mode : {"rule","global","direct"}) {
            for (const auto &flags : {qMakePair(true,false),qMakePair(true,true),qMakePair(false,true),qMakePair(false,false)}) {
                const bool enabled = flags.first, tun = flags.second; const auto previous = observations;
                std::cerr << "CHECK: macOS composed mode=" << mode << " system_proxy=" << enabled << " tun=" << tun << '\n';
                patch({{"mode",mode},{"tun",QJsonObject{{"enable",tun}}}}); systemProxy(enabled);
                until([&] {
                    if (session.state() != ConnectionState::Running) return true;
                    return observations > previous && !policy.isBusy() && !proxy.isBusy() && coexistence["mode"] == mode
                        && coexistence["tun"].toBool() == tun && coexistence["active"].toBool() == (enabled || tun)
                        && proxy.isEnabled() == enabled && (enabled ? proxy.isAutomatic() : !proxy.needsCleanup())
                        && (enabled ? resources["listeners"].toObject()["http"].toString() == "127.0.0.1:"+QString::number(httpPort()) : httpPort() == 0);
                });
                check(session.state() == ConnectionState::Running,"independent switches retain the authenticated campus session");
                until([&] {
                    const auto route = runPlatformCommand("/sbin/route",{"-n","get","-inet",runtime["ordinary_address"].toString()});
                    const auto match = QRegularExpression("(?:^|\\n)\\s*interface:\\s*(\\S+)").match(route.output);
                    return route.result.succeeded() && match.hasMatch()
                        && match.captured(1) == runtime[tun ? "tun_device" : "original_interface"].toString();
                });
                auto lookup = std::async(std::launch::async,[] { return addresses("campus.test"); });
                until([&] { return lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
                const auto targets = lookup.get();
                check(!targets.isEmpty(),"actual system campus DNS returns its fixture answer");
                for (const auto &target : targets) check(target == "198.18.0.7","actual system campus DNS remains ahead of the original mode");
                exerciseNativeTUNTraffic(QHostAddress(targets.first())); exerciseNativeSSH(QHostAddress(targets.first()));
                const auto campus = get("http://campus.test/",enabled);
                check(campus.first && campus.second == "vpn-response","actual browser campus request reaches VPN before the original mode");
                const auto ordinary = get(runtime["ordinary_url"].toString(),enabled);
                const bool rejected = QByteArray(mode) == "global" && (enabled || tun);
                check(rejected ? !ordinary.first : ordinary.first,"ordinary web preserves selected Clash mode and both-off direct");
                const auto protectedPeer = get(runtime["protected_url"].toString(),enabled);
                check(protectedPeer.first && protectedPeer.second == "original-http","protected loopback HTTP retains its original peer under GLOBAL REJECT");
                std::cout << "PASS: macOS composed coexistence case mode=" << mode << " system_proxy=" << enabled << " tun=" << tun << '\n';
            }
        }
    }
private:
    SystemProxyConfig config;
    std::unique_ptr<PlatformSystemProxyBackend> original;
    QNetworkAccessManager browser;

    int httpPort()
    {
        AuthorizationRef authorization = nullptr; auto preferences = api.open(&authorization);
        check(preferences,"read actual service proxy settings");
        const auto release = qScopeGuard([&] { CFRelease(preferences); if (authorization) AuthorizationFree(authorization,0); });
        const auto services = SCNetworkServiceCopyAll(preferences); check(services,"actual network services");
        const auto releaseServices = qScopeGuard([&] { CFRelease(services); });
        int port = 0;
        for (CFIndex i=0;i<CFArrayGetCount(services);++i) {
            const auto service = static_cast<SCNetworkServiceRef>(CFArrayGetValueAtIndex(services,i));
            if (!SCNetworkServiceGetEnabled(service)) continue;
            const auto protocol = SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeProxies);
            if (!protocol) continue;
            const auto value = SCNetworkProtocolGetConfiguration(protocol);
            int enabled = 0, current = 0;
            if (value) {
                const auto flag = static_cast<CFNumberRef>(CFDictionaryGetValue(value,kSCPropNetProxiesHTTPEnable));
                const auto number = static_cast<CFNumberRef>(CFDictionaryGetValue(value,kSCPropNetProxiesHTTPPort));
                if (flag) check(CFNumberGetValue(flag,kCFNumberIntType,&enabled),"actual HTTP enable flag");
                if (number) check(CFNumberGetValue(number,kCFNumberIntType,&current),"actual HTTP port");
            }
            CFRelease(protocol);
            if (enabled) { check(current > 0 && (!port || port == current),"service HTTP ports agree"); port = current; }
        }
        return port;
    }
    void systemProxy(bool enabled)
    {
        if (enabled) {
            PlatformSystemProxyBackend external(api);
            check(external.apply(config).succeeded(),"external fixture selects the original system proxy"); return;
        }
        AuthorizationRef authorization = nullptr; auto preferences = api.open(&authorization);
        check(preferences,"open authorized preferences for the external OFF switch");
        const auto release = qScopeGuard([&] { CFRelease(preferences); if (authorization) AuthorizationFree(authorization,0); });
        check(SCPreferencesLock(preferences,true),"lock actual external proxy update");
        const auto unlock = qScopeGuard([&] { SCPreferencesUnlock(preferences); });
        SCPreferencesSynchronize(preferences);
        const auto services = SCNetworkServiceCopyAll(preferences); check(services,"actual network service inventory");
        const auto releaseServices = qScopeGuard([&] { CFRelease(services); });
        for (CFIndex i=0;i<CFArrayGetCount(services);++i) {
            const auto service = static_cast<SCNetworkServiceRef>(CFArrayGetValueAtIndex(services,i));
            if (!SCNetworkServiceGetEnabled(service)) continue;
            const auto path = CFStringCreateWithFormat(nullptr,nullptr,CFSTR("/NetworkServices/%@/Proxies"),SCNetworkServiceGetServiceID(service));
            const auto before = static_cast<CFDictionaryRef>(SCPreferencesPathGetValue(preferences,path));
            const auto value = before ? CFDictionaryCreateMutableCopy(nullptr,0,before)
                : CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
            int flag = 0; const auto zero = CFNumberCreate(nullptr,kCFNumberIntType,&flag);
            for (const auto key : {kSCPropNetProxiesHTTPEnable,kSCPropNetProxiesHTTPSEnable,kSCPropNetProxiesSOCKSEnable}) CFDictionarySetValue(value,key,zero);
            const bool written = SCPreferencesPathSetValue(preferences,path,value);
            CFRelease(zero); CFRelease(value); CFRelease(path); check(written,"disable the external service proxy flags");
        }
        check(SCPreferencesCommitChanges(preferences) && SCPreferencesApplyChanges(preferences),"commit and activate the actual OFF switch");
    }
    void patch(const QJsonObject &fields)
    {
        QLocalSocket socket; socket.connectToServer(runtime["controller"].toString());
        check(socket.waitForConnected(3000),"connect the owned root runtime");
        uid_t uid = -1; gid_t gid = -1; pid_t pid = 0; socklen_t size = sizeof(pid);
        check(getpeereid(socket.socketDescriptor(),&uid,&gid) == 0 && uid == 0
            && getsockopt(socket.socketDescriptor(),SOL_LOCAL,LOCAL_PEERPID,&pid,&size) == 0 && pid == runtime["pid"].toInteger(),
            "only the actual parent-owned root runtime receives fixture updates");
        const auto body = QJsonDocument(fields).toJson(QJsonDocument::Compact);
        const auto request = "PATCH /configs HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
            + QByteArray::number(body.size())+"\r\n\r\n"+body;
        check(socket.write(request) == request.size() && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(3000)),"write owned runtime update");
        QByteArray reply;
        while (!reply.contains("\r\n\r\n")) {
            check(socket.bytesAvailable() || socket.waitForReadyRead(3000),"owned runtime acknowledged update");
            reply += socket.readAll(); check(reply.size() <= 8192,"bounded owned controller reply");
        }
        check(reply.startsWith("HTTP/1.1 204"),"owned runtime accepted the exact update");
    }
};
