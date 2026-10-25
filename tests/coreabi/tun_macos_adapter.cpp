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
#include <QSaveFile>
#include <QStandardPaths>
#include <future>
#include <atomic>
#include <netdb.h>
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
static QStringList addresses(const char *hostname)
{
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; addrinfo *result = nullptr;
    check(::getaddrinfo(hostname,nullptr,&hints,&result) == 0 && result,"Ordinary macOS system resolver returned a campus answer");
    QStringList values;
    for (auto *row = result;row;row = row->ai_next) {
        char value[NI_MAXHOST]; check(::getnameinfo(row->ai_addr,row->ai_addrlen,value,sizeof(value),nullptr,0,NI_NUMERICHOST) == 0,"Numeric system DNS address");
        values.append(QString::fromLatin1(value));
    }
    ::freeaddrinfo(result); return values;
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
    const bool offline = qgetenv("JC_NATIVE_NETWORK_HELPER_OFFLINE") == "1";
    const auto marker = QString::fromLocal8Bit(qgetenv("JC_NATIVE_TUN_READY"));
    check((!helperLoss && !policyChanges && authorizationMode.isEmpty()) || !marker.isEmpty(),"External native observer has a private control directory");
    const auto publish = [&](const QString &suffix) {
        QSaveFile file(marker+suffix);
        const auto value = QJsonDocument(QJsonObject{{"pid",QCoreApplication::applicationPid()},
            {"generation",policy.currentGeneration()}}).toJson(QJsonDocument::Compact);
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
    for (int round=0;round<2;++round) {
        check(session.start(profile,{false,1000}),"Start actual macOS application network session");
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
        if ((helperLoss && round == 1) || (!helperLoss && !policyChanges && authorizationMode.isEmpty() && !marker.isEmpty() && round == 0)) {
            publish(".reconnected"); until([&] { return QFileInfo::exists(marker+".traffic"); });
        }
        originalView();
        auto lookup = std::async(std::launch::async,[] { return addresses("campus.test"); });
        until([&] { return lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
        const auto resolved = lookup.get();
        for (const auto &address : resolved) check(address == "198.18.0.7","Actual CNAME campus DNS answer");
        exerciseNativeTUNTraffic(QHostAddress(resolved.first()));
        for (const auto &address : addresses("localhost")) check(QHostAddress(address).isLoopback(),"localhost remains on this computer");
        originalView();
        refresh(); originalView();
        if (policyChanges && round == 0) {
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
        check(finished == completed && coreFinished == completed && session.state() == expected,"Ordered helper restoration and core stop complete before restart");
        if (helperLoss && round == 0) {
            publish(".restored"); until([&] { return QFileInfo::exists(marker+".restart"); });
        }
    }
    ::close(authorizationFd);
    if (helperLoss) std::cout << "PASS: full macOS application releases core/device on helper loss and reconnects with fresh ownership\n";
    if (offline) std::cout << "PASS: unavailable macOS helper retains restoration responsibility and blocks restart until explicit recovery\n";
    if (cancelAuthorization) std::cout << "PASS: pending macOS authorization cancels promptly and its late grant cannot approve a fresh connection\n";
    if (policyChanges) std::cout << "PASS: macOS live overlap protection, cached DNS campus selection, original-side withdrawal and overlay removal without reauthentication\n";
    std::cout << "PASS: ordinary native TCP/UDP via actual signed macOS helper, application readiness, system CNAME DNS, exact original views and ordered stop/restart\n";
}
