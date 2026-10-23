#include "proxyrecovery.h"
#include "platformsystemproxybackend.h"
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <iostream>
#if defined(Q_OS_LINUX) || defined(Q_OS_WIN)
#include "persistentproxy.h"
#include "systemcredentialstore.h"
#endif
#ifdef Q_OS_LINUX
#include <unistd.h>
#elif defined(Q_OS_WIN)
#include "windows/proxyrecoverylock.h"
#endif

int main(int argc, char **argv)
{
    QCoreApplication application(argc,argv);
    if (argc!=2 || application.arguments()[1].isEmpty()) return 1;
    if (application.arguments()[1]=="--version") {
        std::cout << QJsonDocument(QJsonObject{{"worker","system-proxy-recovery"},{"protocol",1},{"qt",qVersion()}})
                         .toJson(QJsonDocument::Compact).constData() << '\n';
        return 0;
    }
    QCoreApplication::setApplicationName("JustConnect");
    const auto directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (directory.isEmpty() || !QDir().mkpath(directory)) return 1;
#ifdef Q_OS_LINUX
    // A user owns the proxy settings across data/temp roots; do not derive this lock from XDG or TMPDIR.
    const auto lockFile=QString("/tmp/JustConnect-proxy-recovery-%1.lock").arg(geteuid());
    auto credentials=createSystemCredentialStore();
    PersistentProxyBackend backend(*credentials,PersistentProxyBackend::credentialKey());
    return runProxyRecoveryWorker(backend,application.arguments()[1],lockFile,directory+"/proxy-recovery.lock");
#elif defined(Q_OS_WIN)
    WindowsProxyRecoveryLock ownership;
    auto credentials=createSystemCredentialStore();
    PersistentProxyBackend backend(*credentials,PersistentProxyBackend::credentialKey());
    return runProxyRecoveryWorker(backend,application.arguments()[1],directory+"/proxy-recovery.lock",{},ownership.isLocked());
#else
    const auto lockFile=directory+"/proxy-recovery.lock";
    PlatformSystemProxyBackend backend;
    return runProxyRecoveryWorker(backend,application.arguments()[1],lockFile);
#endif
}
