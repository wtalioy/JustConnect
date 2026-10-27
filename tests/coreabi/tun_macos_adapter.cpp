#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/networkaccess/macos/networkaccess.h"
#include "infrastructure/routing/macos/tunroutes.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "application/networkprotection.h"
#include "application/applicationshutdown.h"
#include "application/systemproxysession.h"
#include "infrastructure/systemproxy/proxyrecovery.h"
#include "tuntraffic.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QFileInfo>
#include <QFile>
#include <QDeadlineTimer>
#include <QScopeGuard>
#include <QSaveFile>
#include <QStandardPaths>
#include <future>
#include <atomic>
#include <netdb.h>
#include <dns_sd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <unistd.h>

using ProxyCheck::check;
struct AuthorizationWait {
    std::atomic_int calls{0}, entered{0};
    std::atomic_bool oldReturned{false};
    std::promise<void> first, current;
    std::shared_future<void> releaseFirst = first.get_future().share(), releaseCurrent = current.get_future().share();
};
template<class Predicate> static void until(Predicate done,int timeout = 10000)
{
    QElapsedTimer timer; timer.start();
    while (!done() && timer.elapsed() < timeout) QCoreApplication::processEvents(QEventLoop::AllEvents,10);
    check(done(),"macOS Qt network operation completed within deadline");
}
static QStringList addresses(const char *hostname,int family=AF_INET)
{
    addrinfo hints{}; hints.ai_family = family; hints.ai_socktype = SOCK_STREAM; addrinfo *result = nullptr;
    const auto error = ::getaddrinfo(hostname,nullptr,&hints,&result);
    if (error || !result) std::cerr << "System DNS lookup for " << hostname << " failed: " << error << " (" << ::gai_strerror(error) << ")\n";
    check(error == 0 && result,"Ordinary macOS system DNS lookup succeeds");
    QStringList values;
    for (auto *row = result;row;row = row->ai_next) {
        char value[NI_MAXHOST]; check(::getnameinfo(row->ai_addr,row->ai_addrlen,value,sizeof(value),nullptr,0,NI_NUMERICHOST) == 0,"Numeric system DNS address");
        values.append(QString::fromLatin1(value));
    }
    ::freeaddrinfo(result); return values;
}
static QStringList ipv6Records(const char *hostname)
{
    struct Answer { QStringList addresses; DNSServiceErrorType error=kDNSServiceErr_NoError; bool ready=false; } answer;
    const auto receive=[](DNSServiceRef,DNSServiceFlags flags,uint32_t,DNSServiceErrorType error,const char *,uint16_t type,
        uint16_t klass,uint16_t length,const void *data,uint32_t,void *context){
        auto &answer=*static_cast<Answer *>(context);answer.error=error;
        if(error==kDNSServiceErr_NoError){
            char address[INET6_ADDRSTRLEN]{};
            if(!(flags&kDNSServiceFlagsAdd) || type!=kDNSServiceType_AAAA || klass!=kDNSServiceClass_IN || length!=16
                || !data || !::inet_ntop(AF_INET6,data,address,sizeof(address)))answer.error=kDNSServiceErr_BadParam;
            else if(!answer.addresses.contains(QString::fromLatin1(address)))answer.addresses.append(QString::fromLatin1(address));
        }
        answer.ready=answer.error!=kDNSServiceErr_NoError || !(flags&kDNSServiceFlagsMoreComing);
    };
    DNSServiceRef service=nullptr;
    check(DNSServiceQueryRecord(&service,0,kDNSServiceInterfaceIndexAny,hostname,kDNSServiceType_AAAA,kDNSServiceClass_IN,receive,&answer)==kDNSServiceErr_NoError,
        "Start an ordinary native AAAA record query");
    const auto release=qScopeGuard([&]{DNSServiceRefDeallocate(service);});
    const int descriptor=DNSServiceRefSockFD(service);check(descriptor>=0,"Native DNS query exposes its result descriptor");
    QDeadlineTimer deadline(10000);
    while(!answer.ready && !deadline.hasExpired()){
        pollfd event{descriptor,POLLIN,0};
        check(::poll(&event,1,int(deadline.remainingTime()))>0 && (event.revents&POLLIN),"Native AAAA record query completes within deadline");
        check(DNSServiceProcessResult(service)==kDNSServiceErr_NoError,"Process native AAAA records");
    }
    check(answer.ready && answer.error==kDNSServiceErr_NoError && !answer.addresses.isEmpty(),"Original native AAAA record query succeeds");
    return answer.addresses;
}
int main(int argc,char **argv)
{
    QCoreApplication app(argc,argv); QCoreApplication::setOrganizationName("JustConnectNativeFixture"); QStandardPaths::setTestModeEnabled(true);
    check(argc == 4 && QByteArray(argv[1]) == "--tun-gateway" && ::getuid() == ::geteuid() && ::getuid() != 0
        && qgetenv("GITHUB_ACTIONS") == "true" && qgetenv("RUNNER_OS") == "macOS","Disposable ordinary macOS Qt/core fixture only");
    const int authorizationFd = QByteArray(argv[3]).toInt(); check(authorizationFd >= 3,"Inherited network authorization pipe");
    const auto authorizationMode = qgetenv("JC_NATIVE_NETWORK_AUTHORIZATION");
    const bool cancelAuthorization = authorizationMode == "cancel", exitAuthorization = authorizationMode == "exit";
    check(authorizationMode.isEmpty() || cancelAuthorization || exitAuthorization,"Known native authorization scenario");
    const auto waiting = std::make_shared<AuthorizationWait>();
    auto authorization = [authorizationFd,waiting,cancelAuthorization,exitAuthorization](AuthorizationRef *reference) {
        const int call = ++waiting->calls;
        AuthorizationExternalForm external{};
        if (::read(authorizationFd,&external,sizeof(external)) != sizeof(external)) return OSStatus(errAuthorizationDenied);
        const auto status = AuthorizationCreateFromExternalForm(&external,reference);
        if (status != errAuthorizationSuccess) return status;
        waiting->entered = call;
        if ((cancelAuthorization || exitAuthorization) && call == 1) waiting->releaseFirst.wait();
        if (cancelAuthorization && call == 2) waiting->releaseCurrent.wait();
        if (call == 1) waiting->oldReturned = true;
        return status;
    };
    const auto config = QJsonDocument::fromJson(argv[2]).object();
    const auto server = config["server"].toObject(), auth = config["auth"].toObject();
    ConnectionProfile profile;
    profile.endpoint.server = server["host"].toString(); profile.endpoint.port = server["port"].toInt();
    profile.endpoint.authType = auth["method"].toString().mid(QStringLiteral("auth/").size());
    profile.endpoint.phone = auth["phone"].toString(); profile.endpoint.loginDomain = auth["domain"].toString();
    profile.tls.caPem = config["tls"].toObject()["ca_pem"].toString(); profile.keepAlive.mode = "off";
    auto *engine = new EmbeddedCoreEngine;
    NetworkPolicySession policy(engine,readSystemDnsSnapshot);
    auto *access = new MacNetworkAccess(engine,&policy,1400,nullptr,authorization);
    ConnectionSession session(engine,nullptr,access);
    QObject::connect(&session,&ConnectionSession::diagnostic,[](const QString &message) { std::cerr << message.toStdString() << '\n'; });
    QObject::connect(engine,&CoreEngine::authenticationRequired,[engine](const QJsonObject &request) {
        engine->respond(CoreEngine::responseFor(request,{{"action","submit"},{"code","fixture-code"}}));
    });
    QJsonObject initial;
    QObject::connect(engine,&CoreEngine::initialProtectionApplied,[&](const QJsonObject &value) { initial = value; });
    const bool helperLoss = qgetenv("JC_NATIVE_NETWORK_HELPER_LOSS") == "1";
    const bool policyChanges = qgetenv("JC_NATIVE_NETWORK_POLICY") == "1";
    const bool originalDNS = qgetenv("JC_NATIVE_ORIGINAL_DNS") == "1";
    const bool offline = qgetenv("JC_NATIVE_NETWORK_HELPER_OFFLINE") == "1";
    const bool exitChange = qgetenv("JC_NATIVE_NETWORK_EXIT_CHANGE") == "1";
    const auto marker = QString::fromLocal8Bit(qgetenv("JC_NATIVE_TUN_READY"));
    check((!helperLoss && !policyChanges && !exitChange && authorizationMode.isEmpty()) || !marker.isEmpty(),"External native observer has a private control directory");
    const auto publish = [&](const QString &suffix) {
        QSaveFile file(marker+suffix);
        QJsonObject snapshot{{"pid",QCoreApplication::applicationPid()},{"generation",policy.currentGeneration()}};
        if (exitChange) snapshot["network"] = policy.model()["network"];
        const auto value = QJsonDocument(snapshot).toJson(QJsonDocument::Compact);
        check(file.open(QIODevice::WriteOnly) && file.write(value) == value.size() && file.commit(),"Publish actual Qt/core lifecycle boundary");
    };
    int coreFinished = 0, finished = 0; bool wasPreparing = false;
    QObject::connect(engine,&CoreEngine::finished,[&] { ++coreFinished; });
    QObject::connect(&session,&ConnectionSession::progressChanged,[&] { wasPreparing |= session.phase() == ConnectionPhase::NetworkPreparing; });
    QObject::connect(&session,&ConnectionSession::finished,[&](ConnectionError error) {
        const auto expected = helperLoss && finished == 0 ? ConnectionError::OTHER : ConnectionError::NONE;
        if (error != expected) std::cerr << "CHECK: native routes after failed connection " << QJsonDocument(readMacRoutes().rows).toJson(QJsonDocument::Compact).constData() << '\n';
        check(error == expected,"macOS connection retained its actual terminal result"); ++finished;
    });
    QByteArray previousDifference; bool changingNetwork = false;
    const auto viewMatches = [&] {
        const auto model = policy.model();
        const auto actual = protectionConfiguration(model["targets"].toArray(),model["name_targets"].toArray());
        const bool matches = actual["protected"] == initial["protected"] && actual["protected_names"] == initial["protected_names"];
        if (!matches) {
            const auto difference = QJsonDocument(QJsonObject{{"initial",initial},{"current",actual},{"model",model}}).toJson(QJsonDocument::Compact);
            if (difference != previousDifference) std::cerr << difference.toStdString() << '\n';
            previousDifference = difference;
        }
        return matches;
    };
    QObject::connect(&policy,&NetworkPolicySession::changed,[&] {
        if (!changingNetwork && !initial.isEmpty() && !policy.isBusy() && policy.status() == CoreEngine::RequestStatus::Success) viewMatches();
    });
    const auto originalView = [&] {
        until([&] { return !policy.isBusy(); });
        check(policy.status() == CoreEngine::RequestStatus::Success && viewMatches(),"Owned macOS routes/DNS did not become original protection scopes");
    };
    const auto refresh = [&] {
        until([&] { return !policy.isBusy(); });
        check(policy.refresh(),"Read actual native network after the current observation completes");
    };
    if (cancelAuthorization || exitAuthorization) {
        check(session.start(profile,{false,1000}),"Start a real core before blocking system authorization");
        until([&] { return waiting->entered == 1; });
        check(session.phase() == ConnectionPhase::NetworkPreparing,"System authorization precedes network and campus readiness");
        publish(".authorizing"); until([&] { return QFileInfo::exists(marker+".cancel"); });
        if (exitAuthorization) {
            SystemProxySession proxy(std::make_unique<ProxyRecoveryBackend>());
            ApplicationShutdown shutdown(&session,&proxy,[] { return false; });
            bool closed = false;
            QObject::connect(&shutdown,&ApplicationShutdown::ready,&app,[&] { closed = true; app.quit(); });
            QObject::connect(&shutdown,&ApplicationShutdown::failed,[](const QString &) { check(false,"Pending authorization cannot block ordered application exit"); });
            QTimer::singleShot(0,&app,[&] { shutdown.request(); shutdown.request(); });
            QTimer::singleShot(10000,&app,[] { check(false,"Ordered exit completed while authorization was still pending"); });
            check(app.exec() == 0 && closed && coreFinished == 1 && finished == 1 && !session.isActive()
                && !session.start(profile,{}) && !waiting->oldReturned,"Ordered shutdown joins the real core without waiting for system authorization");
            ::close(authorizationFd);
            std::cout << "PASS: macOS ordered application exit while system authorization is still pending\n";
            return 0;
        }
        session.stop(); session.stop(); until([&] { return !session.isActive(); });
        check(coreFinished == 1 && finished == 1 && session.state() == ConnectionState::Disconnected && !waiting->oldReturned,
            "Cancellation releases the real core and network responsibility before authorization returns");
        publish(".cancelled");
    }
    QString previousGeneration;
    for (int round=0;round<2;++round) {
        if (!round || !exitChange) check(session.start(profile,{exitChange,1000}),"Start actual macOS application network session");
        if (cancelAuthorization && round == 0) {
            until([&] { return waiting->entered == 2; }); publish(".current-authorizing");
            until([&] { return QFileInfo::exists(marker+".release-old"); });
            waiting->first.set_value(); until([&] { return waiting->oldReturned.load(); }); publish(".old-returned");
            until([&] { return QFileInfo::exists(marker+".approve"); });
            check(session.state() == ConnectionState::Starting && session.phase() == ConnectionPhase::NetworkPreparing,
                "Late cancelled authorization cannot approve the new pending connection");
            waiting->current.set_value();
        }
        until([&] { return session.state() == ConnectionState::Running || !session.isActive(); });
        check(session.state() == ConnectionState::Running && session.phase() == ConnectionPhase::CampusReady && wasPreparing,"Campus readiness follows helper ownership and real Go attachment");
        if (exitChange && round == 1) {
            check(session.reconnectAttempt() == 1 && policy.currentGeneration() != previousGeneration,
                "Changed exit reuses the bounded reconnect policy with a fresh core generation");
            changingNetwork = false;
        }
        originalView();
        if(originalDNS){
            until([&]{return !policy.isBusy();});
            check(policy.setCampusName("campus.test",true),"Select the exact campus name within its original native namespace");
            until([&]{return !policy.isBusy();});
            check(policy.policyStatus()==CoreEngine::RequestStatus::Success,"Initial campus name selection completed both confirmations");
        }
        if (exitChange && round == 1) {
            publish(".exit-reconnected"); until([&] { return QFileInfo::exists(marker+".traffic"); });
        }
        if ((helperLoss && round == 1) || (!helperLoss && !policyChanges && !exitChange && authorizationMode.isEmpty() && !marker.isEmpty() && round == 0)) {
            publish(".reconnected"); until([&] { return QFileInfo::exists(marker+".traffic"); });
        }
        auto lookup = std::async(std::launch::async,[] { return addresses("campus.test"); });
        until([&] { return lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
        const auto resolved = lookup.get();
        for (const auto &address : resolved) check(address == "198.18.0.7","Actual CNAME campus DNS answer");
        exerciseNativeTUNTraffic(QHostAddress(resolved.first()));
        exerciseNativeSSH(QHostAddress(resolved.first()));
        for (const auto &address : addresses("localhost")) check(QHostAddress(address).isLoopback(),"localhost remains on this computer");
        originalView();
        refresh(); originalView();
        if (exitChange && round == 0) {
            previousGeneration = policy.currentGeneration(); changingNetwork = true;
            const auto barrier = QObject::connect(&session,&ConnectionSession::reconnectScheduled,&session,[&](int) {
                check(finished == 0 && session.state() == ConnectionState::Reconnecting,
                    "Changed exit restores ownership and stops its old core before scheduling reconnect");
                publish(".exit-restored"); until([&] { return QFileInfo::exists(marker+".continue"); });
            });
            publish(".exit-ready");
            until([&] { return session.state() == ConnectionState::Reconnecting || !session.isActive(); });
            QObject::disconnect(barrier);
            check(coreFinished == 1 && session.state() == ConnectionState::Reconnecting,"Changed original exit stops its old core and preserves automatic restart");
            continue;
        }
        if(originalDNS && round==0){
            changingNetwork=true;
            auto lookup=std::async(std::launch::async,[]{return addresses("host.campus.test");});
            until([&]{return lookup.wait_for(std::chrono::milliseconds(0))==std::future_status::ready;});
            const auto original=lookup.get();
            check(original.contains("198.18.0.6") && original.contains("198.18.0.7"),"Prepared native source retained both original A answers after cache prewarm");
            auto nativeAddresses=std::async(std::launch::async,[]{return addresses("host.campus.test",AF_INET6);});
            until([&]{return nativeAddresses.wait_for(std::chrono::milliseconds(0))==std::future_status::ready;});
            auto actualAddresses=nativeAddresses.get();actualAddresses.sort();
            QFile baseline(marker+".dns-native-ipv6");check(baseline.open(QIODevice::ReadOnly),"Read the native address baseline before capture");
            const auto expected=QJsonDocument::fromJson(baseline.readAll());check(expected.isArray(),"Valid native IPv6 address baseline");
            QStringList expectedAddresses;for(const auto &value:expected.array()){check(value.isString(),"Native address baseline is complete");expectedAddresses.append(value.toString());}
            expectedAddresses.sort();check(actualAddresses==expectedAddresses,"Original native address selection changed after DNS redirection");
            auto ipv6=std::async(std::launch::async,[]{return ipv6Records("host.campus.test");});
            until([&]{return ipv6.wait_for(std::chrono::milliseconds(0))==std::future_status::ready;});
            check(ipv6.get()==QStringList{"2001:db8::9"},"Original AAAA was replaced by the campus IPv4 restriction");
            publish(".original-ready");until([&]{return QFileInfo::exists(marker+".original-traffic");});
            exerciseOriginalNetworkTraffic();
            publish(".protected");until([&]{return QFileInfo::exists(marker+".select-campus");});
            until([&]{return !policy.isBusy();});check(policy.setCampusName("host.campus.test",true),"Select a cached original DNS name for campus");
            until([&]{return !policy.isBusy();});check(policy.policyStatus()==CoreEngine::RequestStatus::Success,"Campus name choice completed native and core confirmation");
            exerciseNativeTUNTraffic(QHostAddress("198.18.0.7"));exerciseNonCampusNetworkTraffic();
            publish(".campus-selected");until([&]{return QFileInfo::exists(marker+".select-original");});
            until([&]{return !policy.isBusy();});check(policy.setCampusName("host.campus.test",false),"Withdraw the original DNS name's campus choice");
            until([&]{return !policy.isBusy();});check(policy.policyStatus()==CoreEngine::RequestStatus::Success,"Name withdrawal completed both confirmations");
            auto withdrawn=std::async(std::launch::async,[]{return addresses("withdrawn.campus.test");});
            until([&]{return withdrawn.wait_for(std::chrono::milliseconds(0))==std::future_status::ready;});
            check(withdrawn.get().contains("198.18.0.7"),"Native original DNS TCP fallback did not retain its answer");
            publish(".original-selected");until([&]{return QFileInfo::exists(marker+".original-traffic-again");});
            exerciseOriginalNetworkTraffic();publish(".original-finished");until([&]{return QFileInfo::exists(marker+".overlay-down");});
            for(const auto *name:{"host.campus.test","withdrawn.campus.test"}){
                until([&]{return !policy.isBusy();});check(policy.setCampusName(QString::fromLatin1(name),true),"Release the original name's retained DNS exclusions");
                until([&]{return !policy.isBusy();});check(policy.policyStatus()==CoreEngine::RequestStatus::Success,"Retained DNS exclusion release completed both confirmations");
            }
            exerciseNativeTUNTraffic(QHostAddress("198.18.0.7"));changingNetwork=false;originalView();
        }else if (policyChanges && round == 0) {
            const auto generation = policy.currentGeneration();
            changingNetwork = true; publish(".policy-ready");
            until([&] { return QFileInfo::exists(marker+".overlay-up"); });
            refresh();
            until([&] { return !policy.isBusy() && policy.confirmedProtection()["protected"].toArray().contains("198.18.0.0/29"); });
            check(session.state() == ConnectionState::Running && policy.currentGeneration() == generation,"New protection did not require a new authenticated session");
            exerciseOriginalNetworkTraffic();
            publish(".protected"); until([&] { return QFileInfo::exists(marker+".select-campus"); });
            for (const auto *address : {"198.18.0.6","198.18.0.7"}) {
                check(policy.setCampusAddress(QString::fromLatin1(address),true),"Select each actual TCP and UDP campus target");
                until([&] { return !policy.isBusy(); });
                check(policy.policyStatus() == CoreEngine::RequestStatus::Success,"Core and helper confirmed the selected target");
            }
            check(policy.policyStatus() == CoreEngine::RequestStatus::Success && policy.campusAddresses().contains("198.18.0.7"),"Core and helper did not confirm the explicit campus choice");
            exerciseNativeTUNTraffic(QHostAddress("198.18.0.7"));
            exerciseNonCampusNetworkTraffic();
            publish(".campus-selected"); until([&] { return QFileInfo::exists(marker+".select-original"); });
            for (const auto *address : {"198.18.0.6","198.18.0.7"}) {
                check(policy.setCampusAddress(QString::fromLatin1(address),false),"Return each actual TCP and UDP target to its original network");
                until([&] { return !policy.isBusy(); });
                check(policy.policyStatus() == CoreEngine::RequestStatus::Success,"Core and helper confirmed the original-side target");
            }
            check(policy.policyStatus() == CoreEngine::RequestStatus::Success && policy.campusAddresses().isEmpty(),"Original-side choice did not complete both confirmations");
            exerciseOriginalNetworkTraffic();
            publish(".original-selected"); until([&] { return QFileInfo::exists(marker+".overlay-down"); });
            refresh();
            until([&] { return !policy.isBusy() && !policy.confirmedProtection()["protected"].toArray().contains("198.18.0.0/29"); });
            check(session.state() == ConnectionState::Running && policy.currentGeneration() == generation,"Original route changes lost the active generation");
            publish(".policy-restored"); until([&] { return QFileInfo::exists(marker+".traffic"); });
            exerciseNativeTUNTraffic(QHostAddress("198.18.0.7"));
            changingNetwork = false; originalView();
        }
        if (helperLoss && round == 0) {
            publish({});
            until([&] { return coreFinished == 1; },MacHelperOperationTimeoutMs);
            if (offline) {
                check(session.isActive() && session.state() == ConnectionState::Stopping
                    && session.phase() == ConnectionPhase::NetworkRestoring && !session.start(profile,{}),
                    "Unavailable helper retains restoration responsibility and blocks a fresh core after releasing the old one");
                publish(".blocked");
            } else publish(".released");
            until([&] { return QFileInfo::exists(marker+".continue"); });
        }
        session.stop(); session.stop(); until([&] { return !session.isActive(); });
        const auto expected = helperLoss && round == 0 ? ConnectionState::Failed : ConnectionState::Disconnected;
        const int completed = round+1+(cancelAuthorization ? 1 : 0);
        check(finished == (exitChange ? 1 : completed) && coreFinished == completed && session.state() == expected,"Ordered helper restoration and core stop complete before restart");
        if (helperLoss && round == 0) {
            publish(".restored"); until([&] { return QFileInfo::exists(marker+".restart"); });
        }
    }
    ::close(authorizationFd);
    if (exitChange) std::cout << "PASS: changed macOS original exit restores before automatic reconnect with a fresh generation and ownership\n";
    if (helperLoss) std::cout << "PASS: full macOS application releases core/device on helper loss and reconnects with fresh ownership\n";
    if (offline) std::cout << "PASS: unavailable macOS helper retains restoration responsibility and blocks restart until explicit recovery\n";
    if (cancelAuthorization) std::cout << "PASS: pending macOS authorization cancels promptly and its late grant cannot approve a fresh connection\n";
    if (policyChanges) std::cout << "PASS: macOS live overlap protection, cached DNS campus selection, original-side withdrawal and overlay removal without reauthentication\n";
    if(originalDNS)std::cout<<"PASS: macOS automatic original DNS source, actual endpoints, cache prewarm, TCP/AAAA, shared-IP name choices and complete restoration\n";
    std::cout << "PASS: ordinary native TCP/UDP via actual signed macOS helper, application readiness, system CNAME DNS, exact original views and ordered stop/restart\n";
}
