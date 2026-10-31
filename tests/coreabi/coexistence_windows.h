#pragma once
#include "application/coexistencenetworkaccess.h"
#include "infrastructure/systemproxy/proxychanges.h"
#include "infrastructure/systemproxy/proxyrecovery.h"
#include <QLocalSocket>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <functional>
#include <cstdlib>
#include <iphlpapi.h>
#include <wininet.h>

class WindowsCoexistenceFixture
{
public:
    QJsonObject runtime = QJsonDocument::fromJson(qgetenv("JC_WINDOWS_COEXISTENCE_RUNTIME")).object();
    QJsonObject resources, coexistence;
    int observations = 0;

    explicit WindowsCoexistenceFixture()
    {
        if (runtime.isEmpty()) return;
        check(runtime["controller"].toString().startsWith(QStringLiteral("\\\\.\\pipe\\verge-mihomo-test-"))
            && runtime["pid"].toInteger() > 0 && runtime["port"].toInt() > 0 && runtime["port"].toInt() <= 65535,
            "requires the parent-owned native runtime");
        const auto state = read();
        originalFlags = state.first; originalServer = state.second; owned = true;
        current = this;
        check(std::atexit(cleanup) == 0,"retain fixture proxy cleanup on assertion exit");
        systemProxy(true);
    }
    ~WindowsCoexistenceFixture()
    {
        cleanup(); current = nullptr;
    }
    bool protectionMatches(const QJsonObject &initial,const QJsonObject &actual,const QJsonObject &network)
    {
        if (initial["protected_names"] != actual["protected_names"]) return false;
        const auto before = initial["protected"].toArray(), after = actual["protected"].toArray();
        if (runtime.isEmpty()) return before == after;
        // The external proxy adds its own original network; JustConnect's owned scopes must stay absent.
        QSet<int> indexes;
        QList<QPair<QHostAddress,int>> originalPrefixes;
        for (const auto &value : network["interfaces"].toArray()) {
            const auto row = value.toObject();
            if (row["name"] != runtime["tun_device"]) continue;
            indexes.insert(row["index"].toInt());
            for (const auto &address : row["addresses"].toArray()) originalPrefixes.append(QHostAddress::parseSubnet(address.toString()));
        }
        for (const auto &value : network["routes"].toArray()) {
            const auto row = value.toObject();
            const auto prefix = QHostAddress::parseSubnet(row["destination"].toString());
            if (indexes.contains(row["interface_index"].toInt()) && prefix.second > 1) originalPrefixes.append(prefix);
        }
        for (const auto &prefix : before) if (!after.contains(prefix)) {
            std::cerr << "missing original protection: " << prefix.toString().toStdString() << '\n'; return false;
        }
        for (const auto &value : after) {
            if (before.contains(value)) continue;
            const auto added = QHostAddress::parseSubnet(value.toString());
            bool external = false;
            for (const auto &prefix : originalPrefixes)
                external |= prefix.second > 1 && added.second >= prefix.second && added.first.isInSubnet(prefix);
            if (!external) {
                std::cerr << "unexpected original protection: " << value.toString().toStdString() << '\n'; return false;
            }
        }
        return true;
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
        check(write(originalFlags,originalServer) && read() == qMakePair(originalFlags,originalServer),
            "restore exact fixture flags and server after application ownership is released");
        owned = false;
    }
    void exercise(ConnectionSession &session, SystemProxySession &proxy, NetworkPolicySession &policy,
                  const std::function<void()> &nativeTraffic)
    {
        const auto get = [&](const QString &url,bool enabled) {
            const auto state = read();
            QNetworkProxy endpoint(QNetworkProxy::NoProxy);
            if (enabled) {
                const auto address = resources["listeners"].toObject()["http"].toString();
                check((state.first & PROXY_TYPE_PROXY) && state.second.contains("http="+address),
                    "actual WinINet browser endpoint belongs to the published JustConnect frontend");
                endpoint = QNetworkProxy(QNetworkProxy::HttpProxy,"127.0.0.1",address.section(':',-1).toUShort());
            } else check(!(state.first & PROXY_TYPE_PROXY),"OFF remains disabled in actual WinINet settings");
            browser.setProxy(endpoint);
            QNetworkRequest request{QUrl(url)};
            request.setTransferTimeout(5000);
            request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,QNetworkRequest::ManualRedirectPolicy);
            request.setRawHeader("Connection","close");
            auto *reply = browser.get(request);
            until("complete actual browser request",[&] { return reply->isFinished(); });
            const auto code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const auto body = reply->readAll();
            const bool okay = reply->error() == QNetworkReply::NoError && code >= 200 && code < 400;
            reply->deleteLater();
            return qMakePair(okay,body);
        };
        // A rejected request is meaningful only after the same public peer answered directly.
        systemProxy(false);
        until("release original frontend before the public baseline",[&] { return !proxy.isBusy() && !proxy.needsCleanup(); });
        check(get(runtime["ordinary_url"].toString(),false).first,"actual public HTTP baseline is reachable");
        for (const auto *mode : {"rule","global","direct"}) {
            for (const auto &flags : {qMakePair(true,false),qMakePair(true,true),qMakePair(false,true),qMakePair(false,false)}) {
                const bool enabled = flags.first, tun = flags.second;
                std::cerr << "CHECK: Windows composed mode=" << mode << " system_proxy=" << enabled << " tun=" << tun << '\n';
                const auto previous = observations;
                patch({{"mode",mode},{"tun",QJsonObject{{"enable",tun}}}});
                systemProxy(enabled);
                until("settle actual native/browser coexistence",[&] {
                    if (session.state() != ConnectionState::Running) return true;
                    if (!(observations > previous && !policy.isBusy()
                        && !proxy.isBusy() && coexistence["mode"] == mode && coexistence["tun"].toBool() == tun
                        && coexistence["active"].toBool() == (enabled || tun) && proxy.isEnabled() == enabled
                        && (enabled ? proxy.isAutomatic() : !proxy.needsCleanup()))) return false;
                    const auto state = read();
                    return enabled ? (state.first & PROXY_TYPE_PROXY)
                        && state.second.contains("http="+resources["listeners"].toObject()["http"].toString())
                        : !(state.first & PROXY_TYPE_PROXY);
                });
                check(session.state() == ConnectionState::Running,"mode and independent switches retain the authenticated campus session");
                until("kernel route follows the actual TUN switch",[&] {
                    SOCKADDR_INET destination{},source{}; destination.si_family = AF_INET;
                    const auto address = runtime["ordinary_address"].toString();
                    check(InetPtonW(AF_INET,reinterpret_cast<PCWSTR>(address.utf16()),&destination.Ipv4.sin_addr) == 1,
                        "parent supplied the actual resolved public IPv4 peer");
                    MIB_IPFORWARD_ROW2 route{};
                    if (GetBestRoute2(nullptr,0,nullptr,&destination,0,&route,&source) != NO_ERROR) return false;
                    WCHAR alias[IF_MAX_STRING_SIZE+1]{};
                    return ConvertInterfaceLuidToAlias(&route.InterfaceLuid,alias,IF_MAX_STRING_SIZE+1) == NO_ERROR
                        && QString::fromWCharArray(alias) == runtime[tun ? "tun_device" : "original_interface"].toString();
                });
                nativeTraffic();
                const auto campus = get("http://campus.test/",enabled);
                check(campus.first && campus.second == "vpn-response","actual browser campus request precedes original Clash selection");
                const auto ordinary = get(runtime["ordinary_url"].toString(),enabled);
                const bool reject = QByteArray(mode) == "global" && (enabled || tun);
                check(reject ? !ordinary.first : ordinary.first,"actual ordinary request preserves GLOBAL REJECT, DIRECT/RULE and both-off direct");
                const auto protectedPeer = get(runtime["protected_url"].toString(),enabled);
                check(protectedPeer.first && protectedPeer.second == "original-http","protected loopback HTTP retains its original peer even under GLOBAL REJECT");
                std::cout << "PASS: Windows composed coexistence case mode=" << mode << " system_proxy=" << enabled << " tun=" << tun << '\n';
            }
        }
    }
private:
    DWORD originalFlags = 0;
    QString originalServer;
    bool owned = false;
    QNetworkAccessManager browser;
    inline static WindowsCoexistenceFixture *current = nullptr;

    static void cleanup()
    {
        if (current && current->owned) {
            if (!write(current->originalFlags,current->originalServer)) std::cerr << "FAIL: restore the fixture's original WinINet settings\n";
            current->owned = false;
        }
    }

    static QPair<DWORD,QString> read()
    {
        INTERNET_PER_CONN_OPTIONW options[2]{};
        options[0].dwOption = INTERNET_PER_CONN_FLAGS_UI; options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        INTERNET_PER_CONN_OPTION_LISTW list{}; list.dwSize = sizeof(list); list.dwOptionCount = 2; list.pOptions = options;
        DWORD size = sizeof(list);
        check(InternetQueryOptionW(nullptr,INTERNET_OPTION_PER_CONNECTION_OPTION,&list,&size),"read actual ordinary-user WinINet settings");
        const auto server = QString::fromWCharArray(options[1].Value.pszValue ? options[1].Value.pszValue : L"");
        if (options[1].Value.pszValue) GlobalFree(options[1].Value.pszValue);
        return {options[0].Value.dwValue,server};
    }
    static bool write(DWORD flags,const QString &server)
    {
        INTERNET_PER_CONN_OPTIONW options[2]{};
        options[0].dwOption = INTERNET_PER_CONN_FLAGS; options[0].Value.dwValue = flags;
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        options[1].Value.pszValue = const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(server.utf16()));
        INTERNET_PER_CONN_OPTION_LISTW list{}; list.dwSize = sizeof(list); list.dwOptionCount = 2; list.pOptions = options;
        return InternetSetOptionW(nullptr,INTERNET_OPTION_PER_CONNECTION_OPTION,&list,sizeof(list))
            && InternetSetOptionW(nullptr,INTERNET_OPTION_SETTINGS_CHANGED,nullptr,0)
            && InternetSetOptionW(nullptr,INTERNET_OPTION_REFRESH,nullptr,0);
    }
    void systemProxy(bool enabled)
    {
        const auto endpoint = "127.0.0.1:"+QString::number(runtime["port"].toInt());
        check(write(PROXY_TYPE_DIRECT | (enabled ? PROXY_TYPE_PROXY : 0),
            "http="+endpoint+";https="+endpoint+";socks="+endpoint),"external fixture toggles the original system proxy");
    }
    void patch(const QJsonObject &fields)
    {
        QLocalSocket socket;
        socket.connectToServer(runtime["controller"].toString());
        check(socket.waitForConnected(3000),"connect the parent-owned native controller pipe");
        ULONG pid = 0;
        check(GetNamedPipeServerProcessId(reinterpret_cast<HANDLE>(socket.socketDescriptor()),&pid)
            && pid == runtime["pid"].toInteger(),"only the actual parent-owned process receives fixture changes");
        const auto payload = QJsonDocument(fields).toJson(QJsonDocument::Compact);
        const auto request = "PATCH /configs HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
            + QByteArray::number(payload.size())+"\r\n\r\n"+payload;
        check(socket.write(request) == request.size() && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(3000)),"write the owned runtime update");
        QByteArray reply;
        while (!reply.contains("\r\n\r\n")) {
            check(socket.bytesAvailable() || socket.waitForReadyRead(3000),"owned runtime acknowledges the update");
            reply += socket.readAll(); check(reply.size() <= 8192,"bounded owned controller acknowledgement");
        }
        check(reply.startsWith("HTTP/1.1 204"),"owned runtime accepted the exact mode/TUN update");
    }
};
