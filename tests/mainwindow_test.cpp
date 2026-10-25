#include "presentation/main/mainwindow.h"
#include "presentation/dialogs/networkpolicywindow.h"
#include "application/applicationlogger.h"
#include "application/defaultsettings.h"
#include "infrastructure/process/terminationrequests.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/settings/profilemanager.h"

#include <QApplication>
#include <QAction>
#include <QDir>
#include <QEvent>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QMessageBox>
#include <QTcpServer>
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
        // UI preference tests retain the real core without requesting host network privileges.
        MainWindow window(&logger,&log,nullptr,[](CoreEngine *,NetworkPolicySession *) -> NetworkAccess * { return nullptr; });
        check(window.isVisible(),"normal startup must show the main window");
        check(window.findChild<QLabel *>("statusTitleLabel")->text()!="已连接","disconnected cannot claim campus readiness");
        window.showMinimized();QCoreApplication::processEvents();
        check(window.isVisible(),"minimization must not hide the only window");
        window.showNormal();window.close();QCoreApplication::processEvents();
        const bool tray=QSystemTrayIcon::isSystemTrayAvailable();
        check(tray ? window.isHidden() : window.isVisible(),"default close must use an available tray or keep the window reachable");
        window.show();
        auto *inspectNetwork = window.findChild<QAction *>("inspectNetworkAction");
        check(inspectNetwork, "network inspection is reachable from the main menu");
        inspectNetwork->trigger();
        QPointer<NetworkPolicyWindow> inspection = window.findChild<NetworkPolicyWindow *>();
        check(inspection && inspection->isVisible(), "network inspection opens without an active connection");
        inspectNetwork->trigger();
        check(window.findChildren<NetworkPolicyWindow *>().size() == 1, "reopening network inspection reuses its window");
        inspection->close();
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        check(!inspection, "closed network inspection releases its window");
        QTcpServer stalledGateway;
        auto *connection=window.findChild<ConnectionSession *>();
        const bool activePreferences=app.arguments().contains("--active-preferences");
        if (activePreferences) {
            check(stalledGateway.listen(QHostAddress::LocalHost),"isolated active preference gateway");
            ConnectionProfile profile;profile.endpoint.server="127.0.0.1";profile.endpoint.port=stalledGateway.serverPort();
            check(connection && connection->start(profile,{}),"start a cancellable real core operation before editing preferences");
            auto *core=connection->findChild<CoreEngine *>();
            check(core,"session owns its core event source");
            const auto observedAt=QDateTime::currentDateTimeUtc();
            emit core->observation("renewal","succeeded",observedAt);
            emit core->observation("traffic","unavailable",observedAt);
            const auto detail=window.findChild<QLabel *>("statusDetailLabel")->text();
            check(detail.contains("最近会话续期：成功") && detail.contains("最近流量保活（校园 DNS）：不可用")
                && detail.contains("获授权") && detail.contains(observedAt.toLocalTime().toString(Qt::ISODate))
                && window.findChild<QSystemTrayIcon *>()->toolTip().contains(detail),
                "window and tray distinguish observed renewal from unavailable traffic probing and show its time");
        }
        auto *preferencesAction=window.findChild<QAction *>("preferencesAction");
        check(preferencesAction,"application preferences must be discoverable without a school configuration");
        const auto openPreferences=[&] {
            preferencesAction->trigger();
            auto *dialog=window.findChild<QDialog *>("applicationPreferencesDialog");
            check(dialog && dialog->isVisible(),"application preferences open independently of school settings");
            return dialog;
        };
        auto *preferences=openPreferences();
        preferences->findChild<QComboBox *>("closeBehaviorComboBox")->setCurrentIndex(1);
        preferences->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Cancel)->click();
        QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
        check(ProfileManager().closeToTray(),"cancelling preferences cannot change close behavior");
        preferences=openPreferences();
        preferences->findChild<QComboBox *>("closeBehaviorComboBox")->setCurrentIndex(1);
        if (app.arguments().contains("--preferences-failure")) {
            check(ProfileManager().setCloseToTray(true),"prepare previous global preference");
            const auto state=QDir(configRoot).filePath("state.ini");
            QFile input(state);check(input.open(QIODevice::ReadOnly),"read original preference");const auto original=input.readAll();input.close();
            check(QFile::remove(state) && QDir().mkdir(state),"inject isolated preference storage failure");
            QTimer::singleShot(0,&app,[&]{for(auto *widget:app.topLevelWidgets()) if(auto *message=qobject_cast<QMessageBox *>(widget))message->accept();});
            preferences->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Save)->click();
            check(preferences->isVisible(),"failed preference save must keep the dialog open");
            check(QDir().rmdir(state),"remove isolated failure fixture");
            QFile restore(state);check(restore.open(QIODevice::WriteOnly) && restore.write(original)==original.size(),"restore original preference fixture");restore.close();
            preferences->reject();
            check(ProfileManager().closeToTray(),"failed save cannot replace the previous preference");
        } else {
            preferences->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Save)->click();
            check(window.isVisible() && !ProfileManager().closeToTray(),"saving close behavior must persist without immediately closing the window");
            if (!app.arguments().contains("--close-exits")) check(ProfileManager().setCloseToTray(true),"restore default preference for explicit exit tests");
        }
        QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
        if (activePreferences) {
            check(connection->isActive() && connection->state()==ConnectionState::Starting,"preference saves must not stop or restart the active session");
            connection->stop();
        }
        bool quitIntercepted=false;
        TerminationRequests termination;
        QObject::connect(&termination,&TerminationRequests::requested,&window,[&] {
            check(QThread::currentThread()==app.thread(),"termination request must reach the GUI thread");
            quitIntercepted=true;window.gracefullyQuit();
        });
        QTimer::singleShot(0,&app,[&] {
            if (app.arguments().contains("--close-exits")) {quitIntercepted=true;window.close();return;}
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
