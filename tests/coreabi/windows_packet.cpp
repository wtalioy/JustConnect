#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "tuntraffic.h"
#include "infrastructure/dns/dnssnapshot.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QLibrary>
#include <windows.h>

using ProxyCheck::check;
template<class Predicate> static void until(Predicate done) {
    QElapsedTimer timer; timer.start();
    while (!done() && timer.elapsed() < 10000) QCoreApplication::processEvents(QEventLoop::AllEvents,10);
    check(done(),"Windows core operation completed within deadline");
}
static void handshake(HANDLE pipe, bool write) {
    HANDLE event = ::CreateEventW(nullptr,TRUE,FALSE,nullptr);
    check(event != nullptr,"Create native handshake event");
    OVERLAPPED operation{}; operation.hEvent = event;
    char value = 1; DWORD count = 0;
    const auto ok = write ? ::WriteFile(pipe,&value,1,&count,&operation) : ::ReadFile(pipe,&value,1,&count,&operation);
    const auto pending = !ok && ::GetLastError() == ERROR_IO_PENDING;
    check(ok || pending,"Start actual device handshake");
    if (pending) check(::WaitForSingleObject(event,5000) == WAIT_OBJECT_0
        && ::GetOverlappedResult(pipe,&operation,&count,FALSE),"Complete actual device handshake");
    check(count == 1 && value == 1,"Helper confirms its actual adapter before attachment");
    ::CloseHandle(event);
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    check(argc == 5 && QByteArray(argv[1]) == "--packet-gateway" && qgetenv("GITHUB_ACTIONS") == "true",
        "Disposable Windows Qt/Wintun fixture only");
    TOKEN_ELEVATION elevation{}; DWORD size = 0; HANDLE token = nullptr;
    check(::OpenProcessToken(::GetCurrentProcess(),TOKEN_QUERY,&token)
        && ::GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&size)
        && !elevation.TokenIsElevated,"Qt and Go core run with an ordinary token");
    ::CloseHandle(token);
    QLibrary runtime(QCoreApplication::applicationDirPath()+"/"+QStringLiteral(JC_SHARED_LIBRARY));
    runtime.setLoadHints(QLibrary::PreventUnloadHint);
    if (!runtime.load()) std::cerr << "Native runtime: " << runtime.errorString().toStdString() << '\n';
    check(runtime.isLoaded(),"Ordinary Windows host can load the actual embedded runtime");
    check(EmbeddedCoreEngine::buildInfo()["capabilities"].toObject()["windows_ipv4_packet_pipe"].toBool(),"Actual loaded core supports Windows helper pipes");
    const auto dns = readSystemDnsSnapshot();
    if (!dns.result.succeeded()) std::cerr << "Native original DNS: " << int(dns.result.status) << " " << dns.result.detail.toStdString() << '\n';
    check(dns.result.succeeded(),"Ordinary Windows caller can read the real original DNS snapshot");
    const auto config = QJsonDocument::fromJson(argv[2]).object();
    const auto server = config["server"].toObject(), auth = config["auth"].toObject();
    ConnectionProfile profile;
    profile.endpoint.server = server["host"].toString(); profile.endpoint.port = server["port"].toInt();
    profile.endpoint.authType = auth["method"].toString().mid(QStringLiteral("auth/").size());
    profile.endpoint.phone = auth["phone"].toString(); profile.endpoint.loginDomain = auth["domain"].toString();
    profile.tls.caPem = config["tls"].toObject()["ca_pem"].toString(); profile.keepAlive.mode = "off";
    check(EmbeddedCoreEngine::validateConfiguration(profile) == ConnectionError::NONE,"Actual fixture profile passes formal validation");
    EmbeddedCoreEngine engine;
    QString generation; bool ready = false,attached = false; int finished = 0;
    CoreEngine::RequestStatus attachment = CoreEngine::RequestStatus::Failed;
    QObject::connect(&engine,&CoreEngine::sessionStarted,[&](const QString &value) { generation = value; });
    QObject::connect(&engine,&CoreEngine::authenticationRequired,[&](const QJsonObject &request) {
        engine.respond(CoreEngine::responseFor(request,{{"action","submit"},{"code","fixture-code"}}));
    });
    QObject::connect(&engine,&CoreEngine::diagnostic,[](const QString &value) { std::cerr << value.toStdString() << '\n'; });
    QObject::connect(&engine,&CoreEngine::connectionEstablished,[&] { ready = true; });
    QObject::connect(&engine,&CoreEngine::tunAttached,[&](const QString &,CoreEngine::RequestStatus status) { attachment = status; attached = true; });
    QObject::connect(&engine,&CoreEngine::finished,[&](ConnectionError error) {
        if (error != ConnectionError::NONE) std::cerr << "Native core terminal error=" << int(error) << '\n';
        check(error == ConnectionError::NONE,"Windows core stopped normally"); ++finished;
    });
    bool validPID = false;
    const auto helperPID = QByteArray(argv[4]).toUInt(&validPID);
    check(validPID && helperPID,"Actual helper process identity");
    for (int round = 0; round < 2; ++round) {
        const auto name = QString::fromLocal8Bit(argv[3]) + QString::number(round);
        HANDLE pipe = INVALID_HANDLE_VALUE;
        QElapsedTimer timer; timer.start();
        while (pipe == INVALID_HANDLE_VALUE && timer.elapsed() < 10000) {
            pipe = ::CreateFileW(reinterpret_cast<LPCWSTR>(name.utf16()),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
            if (pipe == INVALID_HANDLE_VALUE) ::Sleep(10);
        }
        check(pipe != INVALID_HANDLE_VALUE,"Open a fresh private helper byte pipe");
        ready = false;
        check(engine.start(profile),"Start actual campus protocol before device allocation");
        until([&] { return ready; });
        handshake(pipe,true); handshake(pipe,false);
        const auto attach = [&](const QString &value, quint32 mtu, quint32 pid, CoreEngine::RequestStatus expected) {
            attached = false;
            engine.attachWindowsPipe(value,quint64(reinterpret_cast<quintptr>(pipe)),pid,mtu,"198.18.0.1","198.18.0.2");
            until([&] { return attached; }); check(attachment == expected,"Windows attachment retains validation and generation boundaries");
        };
        attach(generation,1400,helperPID+1,CoreEngine::RequestStatus::Invalid);
        attach(generation,67,helperPID,CoreEngine::RequestStatus::Invalid);
        attach("0",1400,helperPID,CoreEngine::RequestStatus::Invalid);
        attached = false;
        engine.attachWindowsPipe(generation,quint64(reinterpret_cast<quintptr>(pipe)),helperPID,1400,"198.18.0.1","198.18.0.2");
        check(::CloseHandle(pipe),"Original borrowed pipe closes immediately after queued Qt attachment");
        until([&] { return attached; }); check(attachment == CoreEngine::RequestStatus::Success,"Actual helper pipe attached through formal C ABI");
        exerciseNativeTUNTraffic();
        engine.stop(); engine.stop(); until([&] { return finished == round+1; });
    }
    std::cout << "PASS: ordinary Windows Qt/core TCP/UDP and empty datagrams through owned Wintun and authenticated packet pipe, stop and restart\n";
    return 0;
}
