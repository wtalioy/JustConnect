#include "presentation/main/mainwindow.h"
#include "application/applicationlogger.h"
#include "application/defaultsettings.h"
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
#include <QUuid>
#include <cstdlib>
#include <iostream>

static void check(bool ok,const char *message) {
    if (!ok) {std::cerr << message << '\n';std::exit(1);}
}
int main(int argc,char **argv) {
    QApplication app(argc,argv);
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
        QTimer::singleShot(0,&app,[&] {
            QEvent quit(QEvent::Quit);
            quitIntercepted=QCoreApplication::sendEvent(&app,&quit);
        });
        QTimer::singleShot(1000,&app,[&]{check(false,"ordered quit did not complete");});
        check(app.exec()==0 && quitIntercepted,"application quit must enter the shared asynchronous shutdown");
    }
    check(QDir(configRoot).removeRecursively(),"isolated window-test settings cleanup");
}
