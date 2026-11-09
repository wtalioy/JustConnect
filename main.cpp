#include <QApplication>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <cstdlib>
#include <cstring>
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include <QSessionManager>
#include "infrastructure/process/applicationinstancelock.h"
#include "infrastructure/process/terminationrequests.h"

#include "application/applicationlogger.h"
#include "application/applicationconstants.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/storage/applicationpaths.h"
#include "presentation/main/mainwindow.h"
#if defined(Q_OS_MACOS)
#include <Security/Security.h>
#endif

#ifndef PROJ_VER
#define PROJ_VER "unknown"
#endif

int main(int argc, char *argv[])
{
    if (argc == 2 && std::strcmp(argv[1], "--core-self-test") == 0) {
        QCoreApplication app(argc, argv);
        auto report = EmbeddedCoreEngine::selfTest();
        report["application_version"] = PROJ_VER;
        QFile output;
        if (!output.open(stdout, QIODevice::WriteOnly)) return 1;
        const auto bytes = QJsonDocument(report).toJson(QJsonDocument::Compact) + '\n';
        if (output.write(bytes) != bytes.size() || !output.flush()) return 1;
        return report["ok"].toBool() ? 0 : 1;
    }
    QApplication app(argc, argv);
    QApplication::setApplicationName(ApplicationConstants::ApplicationName);
    QApplication::setApplicationDisplayName(ApplicationConstants::ApplicationName);
    QApplication::setApplicationVersion(PROJ_VER);

    const ApplicationInstanceLock instanceLock;
    const auto lockError = instanceLock.error();
    if (lockError == QLockFile::LockFailedError) return EXIT_SUCCESS;
    if (lockError != QLockFile::NoError) {
        qCritical() << "Cannot acquire the JustConnect instance lock:" << lockError;
        return EXIT_FAILURE;
    }
#if defined(Q_OS_MACOS)
    // An ACL from an earlier build should fall back to campus sign-in without a Keychain prompt.
    if (SecKeychainSetUserInteractionAllowed(false) != errSecSuccess)
        qWarning() << "Could not disable interactive Keychain access.";
#endif

    ApplicationLogFile applicationLogFile(ApplicationPaths::logFile());
    ApplicationLogger applicationLogger;
    QObject::connect(
        &applicationLogger,
        &ApplicationLogger::entryAdded,
        &applicationLogFile,
        &ApplicationLogFile::appendEntry
    );

    MainWindow mainWindow(&applicationLogger, &applicationLogFile);

    TerminationRequests termination;
    QObject::connect(&termination,&TerminationRequests::requested,&mainWindow,&MainWindow::gracefullyQuit);
    QObject::connect(&app,&QGuiApplication::commitDataRequest,&mainWindow,[&](QSessionManager &manager) {
        manager.setRestartHint(QSessionManager::RestartNever);
        mainWindow.endSystemSession();
    },Qt::DirectConnection);

    QObject::connect(&app, &QApplication::aboutToQuit, &mainWindow, &MainWindow::cleanUpWhenQuit);

    return QApplication::exec();
}
