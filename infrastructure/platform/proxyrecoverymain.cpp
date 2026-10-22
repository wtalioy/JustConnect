#include "proxyrecovery.h"
#include "platformsystemproxybackend.h"
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <iostream>

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
    PlatformSystemProxyBackend backend;
    return runProxyRecoveryWorker(backend,application.arguments()[1],directory+"/proxy-recovery.lock");
}
