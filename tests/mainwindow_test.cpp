#include "presentation/main/mainwindow.h"
#include "application/applicationlogger.h"
#include "application/defaultsettings.h"
#include "infrastructure/platform/terminationrequests.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/settings/profilemanager.h"

#include <QApplication>
#include <QAction>
#include <QDir>
#include <QEvent>
#include <QLabel>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>
#include <QThread>
#include <QProcess>
#include <QFile>
#ifdef Q_OS_UNIX
#include <unistd.h>
#endif
#include <QUuid>
#include <cstdlib>
#include <iostream>

static void check(bool ok,const char *message) {
    if (!ok) {std::cerr << message << '\n';std::exit(1);}
}
int main(int argc,char **argv) {
    QApplication app(argc,argv);
#ifdef Q_OS_UNIX
    if (app.arguments().contains("--external-signal")) {
        QProcess child;child.start(app.applicationFilePath(),{"--wait-for-signal"});
        check(child.waitForStarted(10000),"external signal child startup");
        QByteArray output;
        while (!output.contains("READY") && child.waitForReadyRead(10000)) output+=child.readAllStandardOutput();
        check(output.contains("READY"),"external signal child must be ready before termination");
        check(::kill(pid_t(child.processId()),SIGTERM)==0,"send an actual host termination signal");
        check(child.waitForFinished(10000) && child.exitStatus()==QProcess::NormalExit && child.exitCode()==0,
            "external SIGTERM must complete ordered shutdown without a crash");
        return 0;
    }
#endif
    QApplication::setApplicationName("JustConnect-window-test-"+QUuid::createUuid().toString(QUuid::Id128));
    QStandardPaths::setTestModeEnabled(true);
    const auto configRoot=QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QTemporaryDir folder;
    ApplicationLogger logger;ApplicationLogFile log(folder.filePath("app.log"));
    {
        ProfileManager manager;
        QSettings settings(manager.profilePath(""),QSettings::IniFormat);DefaultSettings::reset(settings);settings.sync();
        MainWindow window(&logger,&log);
        check(window.isVisible(),"normal startup must show the main window");
        check(window.findChild<QLabel *>("statusTitleLabel")->text()!="已连接","disconnected cannot claim campus readiness");
        window.showMinimized();QCoreApplication::processEvents();
        check(window.isVisible(),"minimization must not hide the only window");
        window.showNormal();window.close();QCoreApplication::processEvents();
        const bool tray=QSystemTrayIcon::isSystemTrayAvailable();
        check(tray ? window.isHidden() : window.isVisible(),"default close must use an available tray or keep the window reachable");
        window.show();
        bool quitIntercepted=false;
        TerminationRequests termination;
        QObject::connect(&termination,&TerminationRequests::requested,&window,[&] {
            check(QThread::currentThread()==app.thread(),"termination request must reach the GUI thread");
            quitIntercepted=true;window.gracefullyQuit();
        });
        QTimer::singleShot(0,&app,[&] {
            if (app.arguments().contains("--wait-for-signal")) {
                QFile output;check(output.open(stdout,QIODevice::WriteOnly),"signal child output");
                output.write("READY\n");output.flush();return;
            }
            if (app.arguments().contains("--system-session")) {quitIntercepted=true;window.endSystemSession();return;}
            if (app.arguments().contains("--termination")) {std::raise(SIGTERM);return;}
#ifdef Q_OS_UNIX
            if (app.arguments().contains("--interrupt")) {std::raise(SIGINT);return;}
            if (app.arguments().contains("--hangup")) {std::raise(SIGHUP);return;}
#endif
            QEvent quit(QEvent::Quit);
            quitIntercepted=QCoreApplication::sendEvent(&app,&quit);
        });
        QTimer::singleShot(10000,&app,[&]{check(false,"ordered quit did not complete");});
        check(app.exec()==0 && quitIntercepted,"application quit must enter the shared asynchronous shutdown");
    }
    check(QDir(configRoot).removeRecursively(),"isolated window-test settings cleanup");
}
