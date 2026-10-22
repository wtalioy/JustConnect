#include "infrastructure/platform/proxyrecovery.h"
#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/platformcommand.h"
#include <QCoreApplication>
#include <QDir>
#include <QDeadlineTimer>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QLockFile>
#include <QProcess>
#include <QSaveFile>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QThread>
#include <iostream>
#include <stdexcept>
#include <thread>
#ifdef Q_OS_UNIX
#include <sys/socket.h>
#endif

using Result = PlatformOperationResult;
using Status = Result::Status;
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static QString root;
static const SystemProxyConfig config{11081,11080,QStringLiteral("localhost;\u6821\u56ed.test")};
static QJsonObject state()
{
    QFile file(root+"/state.json");
    check(file.open(QIODevice::ReadOnly),"Read private proxy fixture state");
    const auto document = QJsonDocument::fromJson(file.readAll());
    check(document.isObject(),"Complete fixture state");
    return document.object();
}
static void store(const QJsonObject &object)
{
    QSaveFile file(root+"/state.json");
    const auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    check(file.open(QIODevice::WriteOnly) && file.write(bytes)==bytes.size() && file.commit(),"Write private proxy fixture state");
}
static void touch(const QString &name)
{
    QFile file(root+'/'+name);check(file.open(QIODevice::WriteOnly),"Create private fixture gate");
}
static void deliver(QLocalSocket &socket, const QByteArray &bytes)
{
    check(socket.write(bytes)==bytes.size(),"Queue complete fixture frame");
    QDeadlineTimer deadline(5000);
    while (socket.bytesToWrite() && socket.state()==QLocalSocket::ConnectedState) {
        check(!deadline.hasExpired(),"Fixture frame delivery exceeded its budget");
        if (!socket.waitForBytesWritten(int(deadline.remainingTime()))) {
            check(socket.state()!=QLocalSocket::ConnectedState || socket.error()==QLocalSocket::PeerClosedError,
                  "Fixture frame stopped before delivery or peer rejection");
            break;
        }
    }
}
static QByteArray frame(QLocalSocket &socket)
{
    QDeadlineTimer deadline(5000);
    while (!socket.canReadLine())
        check(socket.bytesAvailable()<64*1024 && !deadline.hasExpired()
              && socket.waitForReadyRead(int(deadline.remainingTime())),"Read a complete bounded fixture frame");
    const auto line = socket.readLine(64*1024+1);
    check(line.size()<=64*1024 && line.endsWith('\n'),"Fixture response frame exceeded its bound");
    return line;
}
#ifdef Q_OS_MACOS
static SCPreferencesRef privatePreferences()
{
    const auto filename = root+"/preferences.plist";
    auto path = CFStringCreateWithCharacters(nullptr,reinterpret_cast<const UniChar *>(filename.utf16()),filename.size());
    const auto prefs = SCPreferencesCreate(nullptr,CFSTR("JustConnect recovery tests"),path);CFRelease(path);
    check(prefs,"Open private SystemConfiguration preferences");return prefs;
}
#endif
template<class Predicate> static void until(Predicate ready, const char *phase)
{
    QElapsedTimer timer;timer.start();
    while (!ready()) {
        if (timer.elapsed()>=5000) {
            const auto data = state();
            check(false,qPrintable(QString("%1: current=%2, applies=%3, clears=%4, owner-lock=%5")
                .arg(phase).arg(data["current"].toInt()).arg(data["applies"].toInt()).arg(data["clears"].toInt())
                .arg(QFile::exists(root+"/owner.lock"))));
        }
        QCoreApplication::processEvents();QThread::msleep(5);
    }
}
class FileBackend final : public SystemProxyBackend {
    int before = 0;
    bool owned = false;
    const QString mode = qEnvironmentVariable("JC_PROXY_RECOVERY_FIXTURE_MODE");
public:
    SystemProxyCheck check(const SystemProxyConfig &config) override
    {
        auto values = state();values["checks"] = values["checks"].toInt()+1;
        values["config"] = QJsonObject{{"http",config.httpPort},{"socks",config.socksPort},{"bypass",config.bypass}};store(values);
        return {{},false,values["current"]==111};
    }
    Result apply(const SystemProxyConfig &) override
    {
        if (owned) return {Status::Failed,"Already owned",true};
        auto values = state();before = values["current"].toInt();owned = true;
        values["current"] = 111;values["applies"] = values["applies"].toInt()+1;store(values);
        if (mode=="blocked-apply") {
            // Observers wait for publication so their Windows read handles cannot block replacement.
            touch("apply-published");
            QElapsedTimer timer;timer.start();
            while (!QFile::exists(root+"/release") && timer.elapsed()<2000) QThread::msleep(5);
        }
        return mode=="partial" ? Result{Status::Failed,"Injected partial application",true} : Result{Status::Success,{},true};
    }
    Result clear() override
    {
        if (!owned) return {};
        auto values = state();values["clears"] = values["clears"].toInt()+1;
        if (QFile::exists(root+"/deny-clear")) {
            store(values);touch("clear-denied");return {Status::PermissionDenied,"Injected cleanup denial",true};
        }
        if (values["current"]==111) values["current"] = before;
        values["recovered"] = true;store(values);owned = false;return {};
    }
};

int main(int argc, char **argv) try
{
    QCoreApplication application(argc,argv);
    root = qEnvironmentVariable("JC_PROXY_RECOVERY_FIXTURE_ROOT");
    if (argc==2) {
        check(!root.isEmpty() && QFile::exists(root+"/state.json"),"Worker requires its private fixture");
        FileBackend backend;
        const auto mode = qEnvironmentVariable("JC_PROXY_RECOVERY_FIXTURE_MODE");
        if (mode=="bad-reply" || mode=="withheld-reply") {
            QLocalSocket socket;
            socket.connectToServer(application.arguments()[1]);check(socket.waitForConnected(5000),"Connect invalid-reply fixture");
            QLockFile ownership(root+"/owner.lock");ownership.setStaleLockTime(0);check(ownership.tryLock(),"Acquire invalid-reply fixture");
            deliver(socket,"{\"protocol\":1,\"ready\":true}\n");
            check(QJsonDocument::fromJson(frame(socket)).object()["operation"]=="apply",
                  "Invalid-reply fixture requires its owned apply");
            check(backend.apply(config).succeeded(),"Apply before unconfirmed reply");
            if (mode=="bad-reply") deliver(socket,"{\"status\":999}\n");
            while (socket.state()==QLocalSocket::ConnectedState) socket.waitForReadyRead(20000);
            check(backend.clear().succeeded(),"Recover after a lost response");return 0;
        }
#ifdef Q_OS_LINUX
        if (qEnvironmentVariable("JC_PROXY_RECOVERY_FIXTURE_MODE")=="native") {
            check(qEnvironmentVariable("GSETTINGS_BACKEND")=="keyfile" && qEnvironmentVariable("XDG_CONFIG_HOME")==root+"/native-config",
                  "Refuse daily desktop proxy settings");
            PlatformSystemProxyBackend native;
            return runProxyRecoveryWorker(native,application.arguments()[1],root+"/owner.lock");
        }
#endif
#ifdef Q_OS_MACOS
        if (qEnvironmentVariable("JC_PROXY_RECOVERY_FIXTURE_MODE")=="native") {
            MacProxyApi api;
            api.open = [](AuthorizationRef *authorization) { *authorization=nullptr;return privatePreferences(); };
            PlatformSystemProxyBackend native(api);
            return runProxyRecoveryWorker(native,application.arguments()[1],root+"/owner.lock");
        }
#endif
        return runProxyRecoveryWorker(backend,application.arguments()[1],root+"/owner.lock");
    }
    if (argc==4 && application.arguments()[1]=="--hold") {
        root = application.arguments()[3];
        qputenv("JC_PROXY_RECOVERY_FIXTURE_ROOT",root.toUtf8());
        qputenv("JC_PROXY_RECOVERY_FIXTURE_MODE",application.arguments()[2].toUtf8());
        ProxyRecoveryBackend backend(QCoreApplication::applicationFilePath());
        check(backend.check(config).result.succeeded() && backend.apply(config).succeeded(),"Owned host failed to apply through its recovery worker");
        std::cout << "READY";
#ifndef Q_OS_WIN
        if (application.arguments()[2]=="crlf-ready") std::cout << '\r';
#endif
        std::cout << '\n' << std::flush;
        std::cin.get();return 0;
    }
    check(argc==1,"Unknown fixture mode");
    QTemporaryDir directory;
    check(directory.isValid(),"Create private recovery fixture");root = directory.path();
    qputenv("JC_PROXY_RECOVERY_FIXTURE_ROOT",root.toUtf8());
    const auto cleanup = qScopeGuard([] {
        touch("release");QFile::remove(root+"/deny-clear");
        QElapsedTimer timer;timer.start();
        while (QFile::exists(root+"/owner.lock") && timer.elapsed()<5000) QThread::msleep(5);
    });
    const auto reset = [&](const char *mode = "normal") {
        until([] { return !QFile::exists(root+"/owner.lock"); },"Previous worker did not release fixture ownership");
        store({{"current",17},{"applies",0},{"clears",0}});
        QFile::remove(root+"/apply-published");QFile::remove(root+"/clear-denied");
        QFile::remove(root+"/release");qputenv("JC_PROXY_RECOVERY_FIXTURE_MODE",mode);
    };
    reset();
    {
        ProxyRecoveryBackend missing(directory.filePath("missing-worker"));
        check(missing.check(config).result.status==Status::Unsupported && missing.clear().succeeded()
              && state()["applies"]==0,"Missing worker fell back to a host mutation");
    }
    {
        ProxyRecoveryBackend backend(QCoreApplication::applicationFilePath());
        check(!backend.apply({0,11080,{}}).succeeded() && state()["applies"]==0,"Invalid ports reached the independent backend");
        check(backend.check(config).result.succeeded() && state()["config"].toObject()["bypass"]==config.bypass,
              "Cross-process proxy configuration lost Unicode or endpoint fields");
        std::thread apply([&] { check(backend.apply(config).succeeded(),"Apply from a different caller thread"); });apply.join();
        check(state()["current"]==111 && !backend.apply(config).succeeded(),"Repeated apply overwrote original ownership");
        ProxyRecoveryBackend concurrent(QCoreApplication::applicationFilePath());
        check(!concurrent.apply(config).succeeded() && state()["applies"]==1,"Concurrent recovery owners changed the same proxy state");
        check(backend.clear().succeeded() && state()["current"]==17 && backend.clear().succeeded(),"Normal recovery was not acknowledged or idempotent");
        check(backend.apply(config).succeeded(),"Reapply after confirmed recovery");
        auto external = state();external["current"] = 777;store(external);
        check(backend.clear().succeeded() && state()["current"]==777,"Recovery wrapper overrode an external setting");
    }
    reset("partial");
    {
        ProxyRecoveryBackend backend(QCoreApplication::applicationFilePath());
        const auto partial = backend.apply(config);
        check(!partial.succeeded() && partial.mayHaveChanged && state()["current"]==111 && backend.clear().succeeded()
              && state()["current"]==17,"Partial failure lost its independent recovery owner");
    }
    for (const auto &mode : {QString("normal"),QString("crlf-ready"),QString("blocked-apply"),QString("denied-clear")}) {
        reset();
        if (mode=="denied-clear") touch("deny-clear");
        QProcess holder;
        holder.start(QCoreApplication::applicationFilePath(),{"--hold",mode,root},QIODevice::ReadWrite|QIODevice::Text);
        check(holder.waitForStarted(5000),"Start owned proxy host fixture");
        if (mode=="blocked-apply") {
            until([] { return QFile::exists(root+"/apply-published"); },"Blocked apply did not publish fixture state");
            check(state()["current"]==111,"Published application gate preceded the actual fixture mutation");
        }
        else check(holder.waitForReadyRead(5000) && holder.readLine()=="READY\n","Independent owner readiness");
        holder.kill();check(holder.waitForFinished(5000) && holder.exitStatus()==QProcess::CrashExit,"Kill only the owned test host");
        if (mode=="denied-clear") {
            until([] { return QFile::exists(root+"/clear-denied"); },"Orphan recovery did not attempt its first denied restore");
            ProxyRecoveryBackend concurrent(QCoreApplication::applicationFilePath());
            check(!concurrent.apply(config).succeeded(),"Restart stole ownership from unresolved orphan recovery");
            QFile::remove(root+"/deny-clear");
        }
        touch("release");
        until([] { return !QFile::exists(root+"/owner.lock") && state()["current"]==17; },"Host SIGKILL did not complete owned recovery");
        check(state()["applies"]==1,"A second owner modified the orphan recovery fixture");
        std::cout << "PASS: proxy host SIGKILL at " << mode.toStdString() << ", independent recovery restored its original state\n";
    }
    for (const auto *mode : {"bad-reply","withheld-reply"}) {
        reset(mode);
        ProxyRecoveryBackend backend(QCoreApplication::applicationFilePath());
        const auto result = backend.apply(config);
        check(!result.succeeded() && result.mayHaveChanged
              && (QString::fromLatin1(mode)!="withheld-reply" || result.status==Status::TimedOut),
              "Invalid or timed-out acknowledgement published successful application");
        until([] { return !QFile::exists(root+"/owner.lock") && state()["current"]==17; },"Lost acknowledgement did not complete independent recovery");
        check(!backend.clear().succeeded() && !backend.apply(config).succeeded() && state()["applies"]==1,
              "Lost acknowledgement invented confirmed recovery or started another owner");
        std::cout << "PASS: " << mode << ", no false acknowledgement or second owner after actual worker recovery\n";
    }
    for (const auto &invalid : {QByteArray("{\"operation\":\"execute\"}\n"),QByteArray("{\"operation\":\"clear\",\"extra\":1}\n"),
                               QByteArray("{\"operation\":\"apply\",\"config\":{\"http_port\":1.5,\"socks_port\":2,\"bypass\":\"\"}}\n"),
                               QByteArray("{\"operation\":\"\xff\"}\n"),QByteArray(64*1024+1,'x')}) {
        reset();
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
#ifdef Q_OS_WIN
        const auto endpoint = "jcpr-test-"+QString::number(QCoreApplication::applicationPid());
#else
        const auto endpoint = directory.filePath("p");
#endif
        check(server.listen(endpoint),"Listen on owned protocol fixture");
        QProcess worker;worker.start(QCoreApplication::applicationFilePath(),{endpoint});
        check(worker.waitForStarted(5000) && server.waitForNewConnection(5000),"Start owned protocol worker");
        auto *socket = server.nextPendingConnection();
#ifdef Q_OS_UNIX
        const int sendBuffer = 4096;
        check(::setsockopt(int(socket->socketDescriptor()),SOL_SOCKET,SO_SNDBUF,&sendBuffer,sizeof(sendBuffer))==0,
              "Constrain only the owned fixture socket write buffer");
#endif
        check(QJsonDocument::fromJson(frame(*socket)).object()["ready"]==true,"Protocol worker handshake");
        const auto command = QByteArray("{\"operation\":\"apply\",\"config\":{\"http_port\":11081,\"socks_port\":11080,\"bypass\":\"localhost\"}}\n");
        deliver(*socket,command);
        check(QJsonDocument::fromJson(frame(*socket)).object()["status"]==0,"Protocol fixture applies actual owned state");
        deliver(*socket,invalid);
        const bool finished = worker.waitForFinished(5000);
        check(finished && worker.exitCode()==0 && state()["current"]==17,
              qPrintable(QString("Invalid frame (%1 bytes), pending output=%2, worker error: %3")
                  .arg(invalid.size()).arg(socket->bytesToWrite()).arg(QString::fromUtf8(worker.readAllStandardError()))));
    }
#ifdef Q_OS_MACOS
    reset("native");
    auto prefs = privatePreferences();const auto releasePrefs = qScopeGuard([&] { CFRelease(prefs); });
    auto interfaces = SCNetworkInterfaceCopyAll();check(interfaces,"Read native interfaces for private proxy fixture");
    const auto releaseInterfaces = qScopeGuard([&] { CFRelease(interfaces); });
    SCNetworkInterfaceRef interface = nullptr;
    for (CFIndex i=0;i<CFArrayGetCount(interfaces);++i) {
        auto candidate = static_cast<SCNetworkInterfaceRef>(CFArrayGetValueAtIndex(interfaces,i));
        if (CFEqual(SCNetworkInterfaceGetInterfaceType(candidate),kSCNetworkInterfaceTypeEthernet)) { interface=candidate;break; }
    }
    check(interface,"Native Ethernet metadata for isolated service fixture");
    auto service = SCNetworkServiceCreate(prefs,interface);check(service,"Create private proxy service");
    const auto releaseService = qScopeGuard([&] { CFRelease(service); });
    check(SCNetworkServiceSetEnabled(service,true),"Enable only the private service fixture");
    auto path = CFStringCreateWithFormat(nullptr,nullptr,CFSTR("/NetworkServices/%@/Proxies"),SCNetworkServiceGetServiceID(service));
    const auto releasePath = qScopeGuard([&] { CFRelease(path); });
    auto initial = CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    const auto releaseInitial = qScopeGuard([&] { CFRelease(initial); });
    CFDictionarySetValue(initial,kSCPropNetProxiesHTTPProxy,CFSTR("prior.invalid"));
    CFDictionarySetValue(initial,kSCPropNetProxiesProxyAutoConfigURLString,CFSTR("https://pac.invalid/original.pac"));
    for (const auto key : {kSCPropNetProxiesHTTPEnable,kSCPropNetProxiesProxyAutoConfigEnable}) {
        int one = 1;auto value = CFNumberCreate(nullptr,kCFNumberIntType,&one);CFDictionarySetValue(initial,key,value);CFRelease(value);
    }
    int port = 3128;auto value = CFNumberCreate(nullptr,kCFNumberIntType,&port);CFDictionarySetValue(initial,kSCPropNetProxiesHTTPPort,value);CFRelease(value);
    check(SCPreferencesPathSetValue(prefs,path,initial) && SCPreferencesCommitChanges(prefs),"Commit only the private service fixture");
    auto original = CFPropertyListCreateDeepCopy(nullptr,SCPreferencesPathGetValue(prefs,CFSTR("/NetworkServices")),kCFPropertyListImmutable);
    check(original,"Save the complete private native baseline");const auto releaseOriginal = qScopeGuard([&] { CFRelease(original); });
    QProcess holder;holder.start(QCoreApplication::applicationFilePath(),{"--hold","native",root},QIODevice::ReadWrite|QIODevice::Text);
    check(holder.waitForStarted(5000) && holder.waitForReadyRead(5000) && holder.readLine()=="READY\n","Start private SystemConfiguration owner");
    SCPreferencesSynchronize(prefs);
    auto installed = static_cast<CFDictionaryRef>(SCPreferencesPathGetValue(prefs,path));
    check(installed && CFDictionaryGetValue(installed,kSCPropNetProxiesHTTPProxy)
          && CFEqual(CFDictionaryGetValue(installed,kSCPropNetProxiesHTTPProxy),CFSTR("127.0.0.1")),"Native worker did not apply the private endpoint");
    holder.kill();check(holder.waitForFinished(5000),"Kill only the private native fixture host");
    until([&] {
        SCPreferencesSynchronize(prefs);
        const auto current = SCPreferencesPathGetValue(prefs,CFSTR("/NetworkServices"));
        return !QFile::exists(root+"/owner.lock") && current && CFEqual(current,original);
    },"Private SystemConfiguration was not restored after host SIGKILL");
    std::cout << "PASS: native private SystemConfiguration restored exactly after Qt host SIGKILL\n";
#endif
#ifdef Q_OS_LINUX
    reset("native");
    qputenv("XDG_CURRENT_DESKTOP","GNOME");qputenv("GSETTINGS_BACKEND","keyfile");qputenv("XDG_CONFIG_HOME",(root+"/native-config").toUtf8());
    const auto get = [](const QStringList &args) {
        const auto result = runPlatformCommand("gsettings",args);
        check(result.result.succeeded(),"Native private GSettings operation");return result.output;
    };
    get({"set","org.gnome.system.proxy","mode","'auto'"});
    get({"set","org.gnome.system.proxy","autoconfig-url","'https://pac.invalid/original.pac'"});
    get({"set","org.gnome.system.proxy.http","host","'prior.invalid'"});
    get({"set","org.gnome.system.proxy.http","port","3128"});
    const auto original = get({"list-recursively","org.gnome.system.proxy"});
    QProcess holder;holder.start(QCoreApplication::applicationFilePath(),{"--hold","native",root},QIODevice::ReadWrite|QIODevice::Text);
    check(holder.waitForStarted(5000) && holder.waitForReadyRead(5000) && holder.readLine()=="READY\n","Start native private proxy owner");
    check(get({"get","org.gnome.system.proxy","mode"})=="'manual'","Native worker did not apply actual GSettings");
    holder.kill();check(holder.waitForFinished(5000),"Kill only the native private fixture host");
    until([&] { return !QFile::exists(root+"/owner.lock") && get({"list-recursively","org.gnome.system.proxy"})==original; },
          "Private GSettings was not restored after host SIGKILL");
    std::cout << "PASS: native private GSettings restored exactly after Qt host SIGKILL\n";
#endif
    std::cout << "PASS: independent proxy ownership, normal/partial recovery, external preservation, single owner and bounded command validation\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n';return 1; }
