#include "infrastructure/systemproxy/proxyrecovery.h"
#include "infrastructure/systemproxy/platformsystemproxybackend.h"
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QUuid>
#include <iostream>
#if defined(Q_OS_LINUX) || defined(Q_OS_WIN) || defined(Q_OS_MACOS)
#include "infrastructure/systemproxy/persistentproxy.h"
#include "infrastructure/credentialstore/systemcredentialstore.h"
#endif
#ifdef Q_OS_LINUX
#include <unistd.h>
#elif defined(Q_OS_WIN)
#include "infrastructure/systemproxy/windows/proxyrecoverylock.h"
#elif defined(Q_OS_MACOS)
#include <sys/stat.h>
#endif

int main(int argc, char **argv)
{
    QCoreApplication application(argc,argv);
    if ((argc<2 || argc>4) || application.arguments()[1].isEmpty()) return 1;
    if (application.arguments()[1]=="--version") {
        if(argc!=2)return 1;
        std::cout << QJsonDocument(QJsonObject{{"worker","system-proxy-recovery"},{"protocol",ProxyRecoveryProtocol},{"qt",qVersion()}})
                         .toJson(QJsonDocument::Compact).constData() << '\n';
        return 0;
    }
    const auto owner=application.arguments().value(2);const QUuid id(owner);
    const bool resume=argc==4;
    if(argc<3 || id.isNull() || id.toString(QUuid::WithoutBraces)!=owner
        || (resume && application.arguments()[3]!="--resume"))return 1;
    QCoreApplication::setApplicationName("JustConnect");
    const auto directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (directory.isEmpty() || !QDir().mkpath(directory)) return 1;
#if defined(Q_OS_LINUX) || defined(Q_OS_WIN) || defined(Q_OS_MACOS)
    auto credentials=createSystemCredentialStore();
    PersistentProxyBackend backend(*credentials,PersistentProxyBackend::credentialKey());
    if(!backend.configureRecovery(owner,resume).succeeded())return 1;
#else
    PlatformSystemProxyBackend backend;
#endif
#ifdef Q_OS_LINUX
    // A user owns the proxy settings across data/temp roots; do not derive this lock from XDG or TMPDIR.
    const auto lockFile=QString("/tmp/JustConnect-proxy-recovery-%1.lock").arg(geteuid());
    return runProxyRecoveryWorker(backend,application.arguments()[1],lockFile,directory+"/proxy-recovery.lock",true,owner,resume);
#elif defined(Q_OS_WIN)
    WindowsProxyRecoveryLock ownership;
    return runProxyRecoveryWorker(backend,application.arguments()[1],directory+"/proxy-recovery.lock",{},ownership.isLocked(),owner,resume);
#elif defined(Q_OS_MACOS)
    struct stat scope{};
    const bool trusted=stat("/var/tmp",&scope)==0 && S_ISDIR(scope.st_mode) && scope.st_uid==0 && (scope.st_mode&S_ISVTX);
    return runProxyRecoveryWorker(backend,application.arguments()[1],MacProxyRecoveryLockFile,
                                  directory+"/proxy-recovery.lock",trusted,owner,resume);
#else
    const auto lockFile=directory+"/proxy-recovery.lock";
    return runProxyRecoveryWorker(backend,application.arguments()[1],lockFile,{},true,owner,resume);
#endif
}
