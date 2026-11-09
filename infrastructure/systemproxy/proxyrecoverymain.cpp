#include "infrastructure/systemproxy/proxyrecovery.h"
#include "infrastructure/systemproxy/platformsystemproxybackend.h"
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QUuid>
#include <iostream>
#include "infrastructure/systemproxy/persistentproxy.h"
#include "infrastructure/credentialstore/systemcredentialstore.h"
#if defined(Q_OS_WIN)
#include "infrastructure/systemproxy/windows/proxyrecoverylock.h"
#else
#include "infrastructure/systemproxy/macos/proxyreceiptstore.h"
#include <Security/Security.h>
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
#ifdef Q_OS_MACOS
    // The detached process cannot receive interactive Keychain authorization.
    if (SecKeychainSetUserInteractionAllowed(false)!=errSecSuccess) return 1;
    MacProxyReceiptStore receipts(directory);
#endif
    auto credentials=createSystemCredentialStore();
#ifdef Q_OS_MACOS
    PersistentProxyBackend backend(*credentials,PersistentProxyBackend::credentialKey(),{},&receipts);
#else
    PersistentProxyBackend backend(*credentials,PersistentProxyBackend::credentialKey());
#endif
    if(!backend.configureRecovery(owner,resume).succeeded())return 1;
#if defined(Q_OS_WIN)
    WindowsProxyRecoveryLock ownership;
    return runProxyRecoveryWorker(backend,application.arguments()[1],directory+"/proxy-recovery.lock",{},ownership.isLocked(),owner,resume);
#else
    struct stat scope{};
    const bool trusted=stat("/var/tmp",&scope)==0 && S_ISDIR(scope.st_mode) && scope.st_uid==0 && (scope.st_mode&S_ISVTX);
    return runProxyRecoveryWorker(backend,application.arguments()[1],MacProxyRecoveryLockFile,
                                  directory+"/proxy-recovery.lock",trusted,owner,resume);
#endif
}
