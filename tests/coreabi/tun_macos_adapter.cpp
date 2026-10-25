#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/platform/macos/networkaccess.h"
#include "infrastructure/platform/dnssnapshot.h"
#include "application/networkprotection.h"
#include "tuntraffic.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QStandardPaths>
#include <future>
#include <netdb.h>
#include <unistd.h>

using ProxyCheck::check;
template<class Predicate> static void until(Predicate done)
{
    QElapsedTimer timer; timer.start();
    while (!done() && timer.elapsed() < 10000) QCoreApplication::processEvents(QEventLoop::AllEvents,10);
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
    auto authorization = [authorizationFd](AuthorizationRef *reference) {
        AuthorizationExternalForm external{};
        if (::read(authorizationFd,&external,sizeof(external)) != sizeof(external)) return OSStatus(errAuthorizationDenied);
        return AuthorizationCreateFromExternalForm(&external,reference);
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
    int finished = 0; bool wasPreparing = false;
    QObject::connect(&session,&ConnectionSession::progressChanged,[&] { wasPreparing |= session.phase() == ConnectionPhase::NetworkPreparing; });
    QObject::connect(&session,&ConnectionSession::finished,[&](ConnectionError error) { check(error == ConnectionError::NONE,"macOS connection retained its actual terminal result"); ++finished; });
    QByteArray previousDifference;
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
        if (!initial.isEmpty() && !policy.isBusy() && policy.status() == CoreEngine::RequestStatus::Success) viewMatches();
    });
    const auto originalView = [&] {
        until([&] { return !policy.isBusy(); });
        check(policy.status() == CoreEngine::RequestStatus::Success && viewMatches(),"Owned macOS routes/DNS did not become original protection scopes");
    };
    for (int round=0;round<2;++round) {
        check(session.start(profile,{false,1000}),"Start actual macOS application network session");
        until([&] { return session.state() == ConnectionState::Running || !session.isActive(); });
        check(session.state() == ConnectionState::Running && session.phase() == ConnectionPhase::CampusReady && wasPreparing,"Campus readiness follows helper ownership and real Go attachment");
        originalView();
        auto lookup = std::async(std::launch::async,[] { return addresses("campus.test"); });
        until([&] { return lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
        const auto resolved = lookup.get();
        for (const auto &address : resolved) check(address == "198.18.0.7","Actual CNAME campus DNS answer");
        exerciseNativeTUNTraffic(QHostAddress(resolved.first()));
        for (const auto &address : addresses("localhost")) check(QHostAddress(address).isLoopback(),"localhost remains on this computer");
        check(policy.refresh(),"Read current native network after DNS route publication and traffic"); originalView();
        session.stop(); until([&] { return !session.isActive(); });
        check(finished == round+1 && session.state() == ConnectionState::Disconnected,"Ordered helper restoration and core stop complete before restart");
    }
    ::close(authorizationFd);
    std::cout << "PASS: ordinary native TCP/UDP via actual signed macOS helper, application readiness, system CNAME DNS, exact original views and ordered stop/restart\n";
}
