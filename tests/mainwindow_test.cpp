#include "presentation/main/mainwindow.h"
#include "presentation/i18n/applicationlanguage.h"
#include "presentation/dialogs/networkpolicywindow.h"
#include "presentation/dialogs/configurationguidedialog/configurationguidedialog.h"
#include "application/applicationlogger.h"
#include "application/defaultsettings.h"
#include "infrastructure/process/terminationrequests.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/settings/profilemanager.h"

#include <QApplication>
#include <QAction>
#include <QActionGroup>
#include <QMenu>
#include <QDir>
#include <QEvent>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QInputDialog>
#include <QTabWidget>
#include <QToolButton>
#include <QMessageBox>
#include <QTcpServer>
#include <QLabel>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>
#include <QThread>
#include <QProcess>
#include <QClipboard>
#include <QStyleHints>
#include <QLocale>
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
class RecoveryNetwork : public NetworkAccess {
public:
    QUuid attempt;
    void prepare(const QUuid &id) override {attempt=id;}
    void activate(const QUuid &,const ConnectionProfile &) override {}
    void stop(const QUuid &) override {}
};
static void recoveryStatus(ApplicationLogger &logger,ApplicationLogFile &log) {
    MainWindow window(&logger,&log,nullptr,[](CoreEngine *,NetworkPolicySession *) -> NetworkAccess * {return new RecoveryNetwork;});
    auto *session=window.findChild<ConnectionSession *>();auto *network=static_cast<RecoveryNetwork *>(session->findChild<NetworkAccess *>());
    check(session->start({},{}),"start isolated network recovery presentation");
    emit network->prepared(network->attempt,{PlatformOperationResult::Status::Failed,"fixture preparation failure",false});
    emit network->stopped(network->attempt,{PlatformOperationResult::Status::TimedOut,"fixture recovery timeout",true});
    auto *title=window.findChild<QLabel *>("statusTitleLabel");
    check(title->text()=="Recovery incomplete" && session->isActive(),"unconfirmed recovery remains visible and active");
    session->stop();
    bool errorShown=false;QTimer acknowledgeError;
    QObject::connect(&acknowledgeError,&QTimer::timeout,&window,[&]{
        for(auto *widget:QApplication::topLevelWidgets())if(auto *box=qobject_cast<QMessageBox *>(widget);box && box->isVisible()){
            errorShown=true;box->accept();
        }
    });acknowledgeError.start(1);
    emit network->stopped(network->attempt,{});acknowledgeError.stop();
    check(!session->isActive() && session->state()==ConnectionState::Failed && errorShown
        && title->text()=="Disconnected","confirmed recovery distinguishes released capture from its retained earlier error");
}
static void profileMenusDoNotAccumulateGroups(MainWindow &window,const QString &profile) {
    auto *menu=window.findChild<QMenu *>("profileMenu");
    auto *tray=window.findChild<QSystemTrayIcon *>();
    QMenu *trayMenu=nullptr;
    for (auto *action:tray->contextMenu()->actions()) if (action->menu()) trayMenu=action->menu();
    check(menu && trayMenu,"both profile menus are available");
    auto *menuButton=window.findChild<QToolButton *>("profileMenuButton");
    auto *editAction=window.findChild<QAction *>("settingAction");
    auto *addAction=window.findChild<QAction *>("newProfileAction");
    check(menuButton && menuButton->menu()==menu && menu->actions().contains(editAction)
        && menu->actions().contains(addAction),"profile menu exposes edit, add and selection together");
    editAction->trigger();
    auto *editor=window.findChild<SettingWindow *>();
    check(editor && editor->isVisible(),"edit control opens the active profile");
    auto *tabs=editor->findChild<QTabWidget *>("tabWidget");
    auto *dns=editor->findChild<QPlainTextEdit *>("domainDnsRulesEdit");
    check(tabs && dns && tabs->currentWidget()->isAncestorOf(dns),"profile editor opens on the tab containing domain DNS");
    editor->reject();
    QApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    const auto checked=[](QMenu *menu) {
        QString result;
        for (auto *action:menu->actions()) if (action->isCheckable() && action->isChecked()) {
            check(result.isEmpty(),"profile selection remains exclusive");result=action->text();
        }
        return result;
    };
    const auto initial=checked(menu);
    check(!initial.isEmpty() && checked(trayMenu)==initial,"profile menus start with the same selection");
    const auto groups=window.findChildren<QActionGroup *>().size();
    for (int i=0;i<10;++i) for (const auto &name:QStringList{profile,initial}) {
        auto *source=i%2?trayMenu:menu;
        QAction *choice=nullptr;
        for (auto *action:source->actions()) if (action->isCheckable() && action->text()==name) choice=action;
        check(choice,"target profile is present after rebuilding the menu");
        choice->trigger();
        check(checked(menu)==name && checked(trayMenu)==name,"main and tray profile selections stay synchronized");
        check(window.findChildren<QActionGroup *>().size()==groups,"profile changes retained old menu groups");
    }
    QTimer::singleShot(0,&window,[&] {
        auto *name=qobject_cast<QInputDialog *>(QApplication::activeModalWidget());
        check(name,"add control asks for the profile name");
        name->setTextValue("direct-add");
        name->accept();
    });
    addAction->trigger();
    auto *guide=window.findChild<ConfigurationGuideDialog *>();
    check(guide && guide->isVisible() && checked(menu)=="direct-add" && checked(trayMenu)=="direct-add",
        "new profile is active and opens the configuration guide");
    guide->reject();
}

static void changeLanguageFromSettings(MainWindow &window,const QString &language,bool save=true) {
    window.findChild<QAction *>("preferencesAction")->trigger();
    auto *dialog=window.findChild<QDialog *>("applicationPreferencesDialog");
    auto *choice=dialog->findChild<QComboBox *>("languageComboBox");
    check(choice && choice->findData(language)>=0,"settings expose the requested language");
    if (ApplicationLanguage::instance().current()=="zh_CN")
        check(dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Save)->text().contains(QString::fromUtf8("保存")),"standard Qt dialog buttons use the selected Chinese translation");
    choice->setCurrentIndex(choice->findData(language));
    dialog->findChild<QDialogButtonBox *>()->button(save?QDialogButtonBox::Save:QDialogButtonBox::Cancel)->click();
    QCoreApplication::processEvents();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    check(!window.findChild<QDialog *>("applicationPreferencesDialog"),"successful language save or cancel closes the settings dialog");
}
static void languagePreferences(MainWindow &window) {
    auto *action=window.findChild<QPushButton *>("connectButton");
    const auto initial=ProfileManager().language();
    check(initial=="en" && ApplicationLanguage::instance().current()=="en" && action->text()=="Connect","a fresh application defaults to English");
    changeLanguageFromSettings(window,"zh_CN",false);
    check(ProfileManager().language()==initial && action->text()=="Connect","cancelled language selection cannot alter runtime or storage");
    changeLanguageFromSettings(window,"zh_CN");
    check(ApplicationLanguage::instance().current()=="zh_CN" && ProfileManager().language()=="zh_CN" && action->text()==QString::fromUtf8("连接")
        && window.findChild<QSystemTrayIcon *>()->toolTip().contains(QString::fromUtf8("尚未连接")),"saving Chinese updates the existing main window and tray without recreating them");
    window.findChild<QPushButton *>("detailsButton")->click();
    auto *details=window.findChild<QDialog *>("detailsDialog");
    check(details->isVisible() && details->windowTitle()==QString::fromUtf8("连接详情"),"subsequent details use the selected language");
    changeLanguageFromSettings(window,"en");
    check(details->isVisible() && details->windowTitle()=="Connection details" && action->text()=="Connect","switching back updates an already open details window");
    details->reject();
}

static void nativeHome(MainWindow &window) {
    auto *details=window.findChild<QDialog *>("detailsDialog");
    auto *log=window.findChild<QPlainTextEdit *>("logPlainTextEdit");
    auto *session=window.findChild<ConnectionSession *>();
    const auto state=session->state();
    if (QGuiApplication::platformName()!="cocoa" && QGuiApplication::platformName()!="windows")
        check(!window.property("nativeBackdrop").toBool() && !window.testAttribute(Qt::WA_TranslucentBackground),"non-native Qt plugins cannot use or reinterpret native window handles");
    check(details && details->isWindow() && !details->isVisible() && !log->isVisible(),"home keeps diagnostics in a separate closed native dialog");
    check(window.findChild<QPushButton *>("connectButton")->isVisible() && qApp->styleHints()->colorScheme()!=Qt::ColorScheme::Dark,
        "redesigned home retains one accessible main action and the light appearance");
    window.findChild<QPushButton *>("detailsButton")->click();QCoreApplication::processEvents();
    check(details->isVisible() && log->isVisible() && session->state()==state,"opening diagnostics cannot change connection state");
    window.findChild<QPushButton *>("copyLogPushButton")->click();
    check(QApplication::clipboard()->text()==log->toPlainText(),"diagnostics copy the same bounded live log");
    details->reject();QCoreApplication::processEvents();
    check(window.isVisible() && !details->isVisible() && session->state()==state,"closing details preserves the accessible home and connection");
    const auto report=qEnvironmentVariable("JC_UI_REPORT_DIR");
    if (!report.isEmpty()) check(window.grab().save(QDir(report).filePath("home.png")),"save actual Qt home screenshot");
    const auto original=window.size();window.resize(320,460);QCoreApplication::processEvents();
    auto *button=window.findChild<QPushButton *>("connectButton");
    check(window.width()==320 && window.rect().contains(button->geometry()) && button->height()>=44,"compact home keeps its main action in bounds at 320 logical pixels");
    if (!report.isEmpty()) check(window.grab().save(QDir(report).filePath("home-320.png")),"save narrow Qt screenshot");
    window.resize(original);
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
    QApplication::setApplicationDisplayName("JustConnect");
    QStandardPaths::setTestModeEnabled(true);
    const auto configRoot=QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QTemporaryDir folder;
    ApplicationLogger logger;ApplicationLogFile log(folder.filePath("app.log"));
    {
        ProfileManager manager;
        QSettings settings(manager.profilePath(""),QSettings::IniFormat);DefaultSettings::reset(settings);settings.sync();
        if (app.arguments().contains("--chinese-startup")) check(manager.setApplicationPreferences("zh_CN",true),"prepare persisted Chinese preference");
        if (app.arguments().contains("--invalid-language")) {
            QSettings state(QDir(configRoot).filePath("state.ini"),QSettings::IniFormat);state.setValue("Global/Language","unsupported");state.sync();
        }
        QLocale::setDefault(QLocale(QLocale::Chinese,QLocale::China));
        QString menuProfile;
        if(app.arguments().size()==1) {
            menuProfile=manager.createProfile("menu-fixture",manager.profilePath(""));
            check(!menuProfile.isEmpty(),"create an isolated profile for menu switching");
            recoveryStatus(logger,log);
        }
        // UI preference tests retain the real core without requesting host network privileges.
        MainWindow window(&logger,&log,nullptr,[](CoreEngine *,NetworkPolicySession *) -> NetworkAccess * { return nullptr; });
        check(window.isVisible(),"normal startup must show the main window");
        if (app.arguments().contains("--chinese-startup")) {
            check(ApplicationLanguage::instance().current()=="zh_CN" && window.findChild<QPushButton *>("connectButton")->text()==QString::fromUtf8("连接"),"a new process restores the saved Chinese preference");
            changeLanguageFromSettings(window,"en");
        }
        if (app.arguments().contains("--invalid-language")) {
            check(ApplicationLanguage::instance().current()=="en" && manager.language()=="unsupported","invalid preferences fall back to English without overwriting evidence");
            window.findChild<QAction *>("preferencesAction")->trigger();
            auto *invalid=window.findChild<QDialog *>("applicationPreferencesDialog");
            bool explained=false;for (auto *label:invalid->findChildren<QLabel *>()) explained|=label->text().contains("saved language is invalid");
            check(explained,"invalid language fallback is visible in settings");invalid->reject();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
        }
        if (app.arguments().size()==1) {nativeHome(window);languagePreferences(window);profileMenusDoNotAccumulateGroups(window,menuProfile);}
        check(window.findChild<QLabel *>("statusTitleLabel")->text()!="Connected","disconnected cannot claim campus readiness");
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
            check(detail.contains("Last Session renewal: Succeeded") && detail.contains("Last Traffic keepalive (campus DNS): Unavailable")
                && detail.contains("authorized") && detail.contains(observedAt.toLocalTime().toString(Qt::ISODate))
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
            preferences->findChild<QComboBox *>("languageComboBox")->setCurrentIndex(1);
            preferences->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Save)->click();
            check(ApplicationLanguage::instance().current()=="en" && preferences->isVisible() && !preferences->findChild<QLabel *>("preferenceError")->text().isEmpty(),"failed preference save must keep the dialog open with an explicit error");
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
            const auto state=connection->state();
            const auto source=manager.profilePath("");QFile profileFile(source);check(profileFile.open(QIODevice::ReadOnly),"read active public profile");
            const auto unchanged=profileFile.readAll();profileFile.close();
            changeLanguageFromSettings(window,"zh_CN");
            check(connection->isActive() && connection->state()==state && window.findChild<QPushButton *>("connectButton")->text()==QString::fromUtf8("取消"),"language changes preserve an active pending connection and its cancel action");
            changeLanguageFromSettings(window,"en");
            check(profileFile.open(QIODevice::ReadOnly) && profileFile.readAll()==unchanged,"global language changes do not rewrite the school profile");profileFile.close();
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
