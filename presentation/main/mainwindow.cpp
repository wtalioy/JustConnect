#include <QMessageBox>
#include <QDesktopServices>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QClipboard>
#include <QAccessible>
#include <QActionGroup>
#include <QMenu>
#include <QDialog>
#include <QLineEdit>
#include <QStyle>
#include <QTimer>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QHash>
#include <QDialogButtonBox>
#include <QTemporaryDir>
#include <QVBoxLayout>
#include "presentation/widgets/connectionmenu.h"
#include <QtAlgorithms>
#include <algorithm>
#include <memory>
#include <optional>
#include "infrastructure/settings/savedconnectionstore.h"

#include "mainwindow.h"
#include "presentation/appearance/applicationappearance.h"
#include "presentation/dialogs/networkpolicywindow.h"
#include "presentation/dialogs/connectiondetailsdialog.h"
#include "presentation/dialogs/applicationpreferencesdialog.h"

#include "application/networkpolicysession.h"
#include "application/applicationconstants.h"
#include "application/defaultsettings.h"
#include "application/clashextension.h"
#include "application/commandlineoptions.h"
#include "application/settingsmigrator.h"
#include "infrastructure/update/updatechecker.h"
#include "presentation/coordinators/connectionuicontroller.h"
#include "presentation/i18n/applicationlanguage.h"
#include "presentation/presentationhelpers.h"
#include "ui_mainwindow.h"

namespace {
QString defaultConnectionLabel(const QSettings &settings)
{
    const auto server = settings.value("JustConnect/ServerAddress").toString().trimmed();
    if (server.isEmpty()) return MainWindow::tr("Unnamed connection");
    return DefaultSettings::matchesBuiltInServer(server) ? MainWindow::tr("Fudan") : server;
}

std::optional<QString> requestConnectionName(QWidget *parent,const QString &title,const QString &action,const QString &initial={})
{
    QDialog dialog(parent);
    dialog.setObjectName("connectionNameDialog");
    dialog.setWindowTitle(title);
    dialog.setMinimumWidth(320);
    auto *layout=new QVBoxLayout(&dialog);
    layout->setContentsMargins(20,20,20,20);
    layout->setSpacing(8);
    auto *label=new QLabel(MainWindow::tr("Connection name"),&dialog);
    label->setObjectName("connectionNameLabel");
    auto *name=new QLineEdit(initial,&dialog);
    name->setObjectName("connectionNameEdit");
    label->setBuddy(name);
    auto *hint=new QLabel(MainWindow::tr("Use letters, numbers, underscores or hyphens."),&dialog);
    hint->setObjectName("connectionNameHint");
    hint->setProperty("secondary",true);
    hint->setWordWrap(true);
    name->setAccessibleDescription(hint->text());
    layout->addWidget(label);
    layout->addWidget(name);
    layout->addWidget(hint);
    auto *cancel=new QPushButton(MainWindow::tr("Cancel"),&dialog);
    cancel->setObjectName("connectionNameCancel");
    auto *primary=new QPushButton(action,&dialog);
    primary->setObjectName("connectionNamePrimary");
    primary->setDefault(true);
    auto *buttons=new QHBoxLayout;
    buttons->setSpacing(12);
    buttons->addStretch();
    buttons->addWidget(cancel);
    buttons->addWidget(primary);
    layout->addLayout(buttons);
    QObject::connect(cancel,&QPushButton::clicked,&dialog,&QDialog::reject);
    QObject::connect(primary,&QPushButton::clicked,&dialog,&QDialog::accept);
    name->setFocus(Qt::OtherFocusReason);
    name->selectAll();
    if (dialog.exec()!=QDialog::Accepted) return std::nullopt;
    return name->text();
}
}

MainWindow::MainWindow(
    ApplicationLogger *logger,
    ApplicationLogFile *logFile,
    QWidget *parent,
    MainWindowCoordinator::NetworkFactory networkFactory
) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ApplicationAppearance::install();
    ApplicationLanguage::instance();
    const QString overrideConfigPath =
        CommandLineOptions::value(QCoreApplication::arguments(), "--config-path");
    coordinator = new MainWindowCoordinator(this, overrideConfigPath, this, networkFactory);
    savedConnections = coordinator->connectionSettingsService();
    currentConnectionId = savedConnections->currentConnectionId();
    settings = savedConnections->settings();

    upgradeSettings();

#ifndef Q_OS_MACOS
    // On macOS Qt would replace the Dock icon supplied by the app bundle.
    QApplication::setWindowIcon(QIcon(":/resource/icon.svg"));
#endif
    ui->setupUi(this);
    ui->centralWidget->setFocus(Qt::OtherFocusReason);
    details = new ConnectionDetailsDialog(coordinator->diagnostics(),coordinator->networkPolicy(),logger,logFile,this);
    connect(ui->detailsButton,&QPushButton::clicked,details,&ConnectionDetailsDialog::openDetails);
    connect(details,&ConnectionDetailsDialog::networkProtectionRequested,ui->inspectNetworkAction,&QAction::trigger);
    connect(ui->openLogAction,&QAction::triggered,details,&ConnectionDetailsDialog::openLogFile);
    authenticationDialogs = coordinator->authenticationDialogs();
    connectionSession = coordinator->connection();
    systemProxySession = coordinator->systemProxy();
    updateChecker = coordinator->updates();
    connect(coordinator->credentials(),&CredentialAccess::configurationSaved,this,[this](const QString &path) {
        if (settings && settings->fileName()==path) {
            updateConnectionSummary();
            refreshConnectionMenu();
        }
    });
    connect(updateChecker, &UpdateChecker::versionInfoChanged, this,
            [this](const VersionInfo &) { updateVersionInfo(); });
    connect(updateChecker, &UpdateChecker::uiUpdateAvailable, this,
            [this](const QString &latestVersion)
            {
                QMessageBox msgBox(this);
                msgBox.setWindowTitle(tr("Update available"));
                msgBox.setTextFormat(Qt::PlainText);
                msgBox.setText(tr("Version %1 is available.").arg(latestVersion));
                msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
                msgBox.button(QMessageBox::Ok)->setText(tr("Open page"));
                msgBox.setDefaultButton(QMessageBox::Ok);

                if (msgBox.exec() == QMessageBox::Ok)
                {
                    QDesktopServices::openUrl(
                        QUrl(
                            "https://github.com/" +
                            ApplicationConstants::RepositoryName +
                            "/releases/latest"
                        )
                    );
                }
            });
    connect(systemProxySession,&SystemProxySession::enabledChanged,this,[this] {
        updateConnectionState(connectionSession->state());
    });
    setupTrayIcon();
    setupConnectionMenu();
    auto *applicationMenu = new QMenu(ui->applicationMenuButton);
    applicationMenu->setToolTipsVisible(true);
    applicationMenu->addAction(ui->checkUpdateAction);
    applicationMenu->addAction(ui->aboutAction);
    ui->applicationMenuButton->setMenu(applicationMenu);
    connect(ui->preferencesButton,&QToolButton::clicked,ui->preferencesAction,&QAction::trigger);
    ui->exitAction->setShortcut(QKeySequence::Quit);
    ui->preferencesAction->setShortcut(QKeySequence::Preferences);
    addAction(ui->exitAction);
    addAction(ui->preferencesAction);
#ifndef Q_OS_MACOS
    ui->menubar->hide();
#endif


    updateConnectionSummary();
    updateVersionInfo();
    updateConnectionState(connectionSession->state());
    trayIcon->show();

    connect(connectionSession, &ConnectionSession::stateChanged, this,
            &MainWindow::updateConnectionState);
    connect(connectionSession, &ConnectionSession::progressChanged, this, [this] { updateConnectionState(connectionSession->state()); });
    connect(connectionSession, &ConnectionSession::observationsChanged, this, &MainWindow::updateMaintenanceDetails);


    // 文件-退出
    connect(ui->exitAction, &QAction::triggered, this, &MainWindow::gracefullyQuit);

    connect(ui->preferencesAction,&QAction::triggered,this,&MainWindow::showApplicationPreferences);

    // 文件-设置
    connect(ui->settingAction,&QAction::triggered,this,[this]{showConnectionSettings();});

    connect(ui->inspectNetworkAction, &QAction::triggered, this, [this] {
        if (!networkPolicyWindow) {
            networkPolicyWindow = new NetworkPolicyWindow(coordinator->networkPolicy(), this);
            networkPolicyWindow->setAttribute(Qt::WA_DeleteOnClose);
        }
        networkPolicyWindow->show();
        networkPolicyWindow->raise();
        networkPolicyWindow->activateWindow();
    });

    connect(ui->clearAuthenticationCacheAction,&QAction::triggered,this,[this] {
        connectionUiController->clearAuthenticationCache();
    });

    connect(ui->clearClientDataAction,&QAction::triggered,this,[this] {
        if (coordinator->credentials()->isBusy(settings->fileName()) || connectionUiController->isConfigurationSaving()) {
            QMessageBox::information(this,tr("Secure storage is busy"),tr("Wait for the current operation before clearing legacy data."));return;
        }
        const auto source=coordinator->credentialSource();
        if (!PresentationHelpers::actionPrompt(this,tr("Clear legacy data"),
            tr("Delete old sign-in data for this connection? Current sign-ins and saved credentials will be kept."))) return;
        coordinator->credentials()->clearLegacyCache(source).then(this,[this](const CredentialResult &result) {
            if (!result.succeeded()) QMessageBox::warning(this,tr("Legacy data cleanup incomplete"),PresentationHelpers::credentialOperationMessage(result.status));
            else qInfo().noquote()<<tr("Legacy data cleared for the current connection");
        });
    });

    // 帮助-检查更新
    connect(ui->checkUpdateAction, &QAction::triggered,
            updateChecker, &UpdateChecker::check);

    // 帮助-项目主页
    connect(ui->projectAction, &QAction::triggered,
            [&]()
            {
                QDesktopServices::openUrl(QUrl(
                    "https://github.com/" + ApplicationConstants::RepositoryName
                ));
            });

    connect(ui->aboutAction, &QAction::triggered, this, [this] { PresentationHelpers::showAboutDialog(this); });

    resetConnectionLog();
    connectionUiController = new ConnectionUiController(
        this,
        ui->connectButton,
        trayConnectAction,
        connectionSession,
        systemProxySession,
        coordinator->networkPolicy(),
        authenticationDialogs,
        logger,
        coordinator->credentials(),
        [this]() { return savedConnections->settings(); },
        [this]() { return coordinator->credentialSource(); },
        [this](
            const QString &title,
            const QString &content,
            QSystemTrayIcon::MessageIcon icon
        )
        {
            showNotification(title, content, icon);
        },
        this
    );
    connect(connectionUiController,&ConnectionUiController::configurationRequested,this,[this] {
        showConnectionSettings();
        if (settingWindow) settingWindow->setConnectAfterSave(true);
    });
    qApp->installEventFilter(this);
    QApplication::setQuitOnLastWindowClosed(false);
    connect(connectionUiController,&ConnectionUiController::readyToQuit,this,[this] {
        exitReady=true;
        emit shutdownSettled(true);
        QMetaObject::invokeMethod(qApp, &QCoreApplication::quit, Qt::QueuedConnection);
    });
    connect(connectionUiController,&ConnectionUiController::quitFailed,this,[this](const QString &code) {
        emit shutdownSettled(false);
        qWarning() << code << "core_active" << connectionSession->isActive()
            << "proxy_busy" << systemProxySession->isBusy() << "proxy_unrestored" << systemProxySession->needsCleanup()
            << "credential_work" << coordinator->credentials()->isBusy();
        if (property("systemShutdown").toBool()) return;
        PresentationHelpers::activateWindow(this);
        auto *message=new QMessageBox(QMessageBox::Warning,tr("Exit incomplete"),
            tr("Cleanup failed or timed out. New connections and reconnection are stopped. Check network recovery and retry Exit. The application remains available while the core or storage work is still running."),
            QMessageBox::Retry|QMessageBox::Cancel,this);
        message->setAttribute(Qt::WA_DeleteOnClose);
        connect(message,&QMessageBox::finished,this,[this](int result){if(result==QMessageBox::Retry) gracefullyQuit();});
        message->open();
    });

    viewsInitialized=true;
    bool shouldConnect =
        settings->value("Common/ConnectAfterStart", false).toBool();
    if (qApp->arguments().contains("--connect"))
    {
        shouldConnect = true;
    }
    if (shouldConnect)
    {
        connectionUiController->enableCampusAccess();
    }

    if (settings->value("Common/CheckUpdateAfterStart").toBool())
    {
        updateChecker->check();
    }

    if (!savedConnections->silentStartEnabled() || !QSystemTrayIcon::isSystemTrayAvailable())
    {
        show();

    }
}

void MainWindow::changeEvent(QEvent *event)
{
    QMainWindow::changeEvent(event);
    if (event->type()!=QEvent::LanguageChange || !viewsInitialized) return;
    ui->retranslateUi(this);
    copyClashScriptAction->setText(tr("Copy Clash Extend Script"));
    addConnectionAction->setText(tr("Add connection…"));renameConnectionAction->setText(tr("Rename connection…"));deleteConnectionAction->setText(tr("Delete connection…"));
    trayConnectionMenu->setTitle(tr("Connections"));trayShowAction->setText(tr("Show window"));
    trayCloseAction->setText(tr("Exit %1").arg(QApplication::applicationName()));
    connectionUiController->refreshActions();refreshConnectionMenu();updateConnectionSummary();updateVersionInfo();updateConnectionState(connectionSession->state());
}

bool MainWindow::eventFilter(QObject *watched,QEvent *event)
{
    if (watched==qApp && event->type()==QEvent::Quit && !exitReady) {
        event->ignore();
        gracefullyQuit();
        return true;
    }
    return QMainWindow::eventFilter(watched,event);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (exitReady) { event->accept();return; }
    event->ignore();
    if (SavedConnectionStore().closeToTray() && trayIcon && trayIcon->isVisible()
        && QSystemTrayIcon::isSystemTrayAvailable()) {
        hide();
    } else {
        gracefullyQuit();
    }
}


void MainWindow::showApplicationPreferences()
{
    if (!preferencesWindow) preferencesWindow=new ApplicationPreferencesDialog(this);
    PresentationHelpers::activateWindow(preferencesWindow);
}

void MainWindow::showConnectionSettings() {
    if (connectionUiController->isConfigurationSaving()) {
        QMessageBox::information(this,tr("Saving connection"),tr("Wait for the save to finish."));return;
    }
    if (!settingWindow) {
        if (!connectionSession->isActive()) connectionUiController->cancelPendingCredentials();
        settingWindow=new SettingWindow(this,coordinator->credentials(),coordinator->credentialSource());
        settingWindow->setObjectName("connectionSettingsDialog");
        const auto path=settings->fileName();
        connect(settingWindow,&SettingWindow::connectRequested,this,[this,path] {
            if (settings->fileName()==path) connectionUiController->enableCampusAccess();
        },Qt::QueuedConnection);
    }
    settingWindow->setProfileEditable(!connectionSession->isActive());
    PresentationHelpers::activateWindow(settingWindow);
}

void MainWindow::resetConnectionLog()
{
    details->resetLog(connectionName(),settings->fileName());
}

void MainWindow::resetConnectionUi()
{
    connectionUiController->cancelPendingCredentials();
    updateConnectionState(ConnectionState::Disconnected);
    updateConnectionSummary();
}

void MainWindow::updateConnectionState(ConnectionState state)
{
    if (settingWindow) settingWindow->setProfileEditable(!connectionSession->isActive());
    const auto phase = connectionSession->phase();
    const bool recoveryFailed = connectionSession->networkRecoveryFailed();
    const bool localProxyReady = connectionSession->usesLocalProxy() && phase == ConnectionPhase::TransportReady;
    QString title;
    QString detail;

    switch (state)
    {
    case ConnectionState::Disconnected:
        title = tr("Not connected");
        detail = tr("Connect to access campus resources.");
        break;
    case ConnectionState::Starting:
        switch (phase) {
        case ConnectionPhase::Initializing: title=tr("Initializing");break;
        case ConnectionPhase::Starting: title=tr("Starting session");break;
        case ConnectionPhase::Restoring: title=tr("Restoring authentication");break;
        case ConnectionPhase::Authenticating: title=tr("Waiting for sign-in");break;
        case ConnectionPhase::AuthenticationSucceeded: title=tr("Establishing tunnel");break;
        case ConnectionPhase::ReauthenticationRequired: title=tr("Sign in again");break;
        case ConnectionPhase::TransportReady: title=tr("Tunnel ready");break;
        case ConnectionPhase::NetworkRecovering: title=tr("Checking network recovery");break;
        case ConnectionPhase::NetworkPreparing: title=tr("Preparing campus access");break;
        case ConnectionPhase::NetworkRestoring: title=tr("Restoring network");break;
        case ConnectionPhase::CampusReady: title=tr("Campus access ready");break;
        }
        detail = tr("Campus access is not ready yet.");
        break;
    case ConnectionState::Running:
        if (localProxyReady) {
            title = tr("Connected");
            detail = tr("Local proxy is ready. Clash routes the selected campus traffic.");
            break;
        }
        title = phase == ConnectionPhase::CampusReady ? tr("Connected")
            : phase == ConnectionPhase::NetworkRestoring ? tr("Restoring network") : tr("Tunnel ready");
        detail = phase == ConnectionPhase::CampusReady ? tr("Campus IPv4 access is ready.")
            : phase == ConnectionPhase::NetworkRestoring ? tr("Campus access is paused until network recovery is confirmed.")
            : systemProxySession->needsCleanup() && !systemProxySession->isEnabled()
            ? tr("System proxy state is unconfirmed. Check remaining settings.")
            : systemProxySession->isEnabled()
            ? tr("Tunnel and system proxy are available; campus access is not ready yet.")
            : tr("Tunnel and local proxy are available; campus access is not ready yet.");
        break;
    case ConnectionState::Stopping:
        title = recoveryFailed ? tr("Recovery incomplete") : tr("Disconnecting");
        detail = recoveryFailed ? tr("Select Retry recovery to finish restoring your network.") : tr("Safely closing this connection.");
        break;
    case ConnectionState::Reconnecting:
        title = tr("Reconnecting");
        detail = tr("Reconnect %1/%2 is waiting for its next attempt.").arg(connectionSession->reconnectAttempt()).arg(ConnectionSessionState::MaxReconnectAttempts);
        break;
    case ConnectionState::Interrupted:
        title = tr("Connection interrupted");
        detail = tr("The core stopped unexpectedly. See Details for the log.");
        break;
    case ConnectionState::Failed:
        if(phase==ConnectionPhase::NetworkRestoring){
            title=tr("Disconnected");
            detail=tr("Network recovery is confirmed. See Details for the earlier error.");
        }else{
            title = phase==ConnectionPhase::ReauthenticationRequired ? tr("Sign in again") : tr("Connection failed");
            detail = tr("Check your network and account settings. See Details for the log.");
        }
        break;
    }

    statusTitle = title;
    statusDetail = detail;
    const bool needsAttention=state==ConnectionState::Failed || state==ConnectionState::Interrupted || recoveryFailed;
    ui->statusHintLabel->setText(needsAttention ? detail : QString());
    ui->statusHintLabel->setVisible(needsAttention);
    ui->statusTitleLabel->setText(title);
    static const QIcon idleArtwork(":/resource/connection.svg");
    static const QIcon connectedArtwork(":/resource/connection-ready.svg");
    const bool connected = state == ConnectionState::Running && (phase == ConnectionPhase::CampusReady || localProxyReady);
    ui->statusIndicator->setPixmap((connected ? connectedArtwork : idleArtwork)
        .pixmap(ui->statusIndicator->size(),devicePixelRatioF()));
    if (trayIcon) {
#ifdef Q_OS_MACOS
        static const QIcon idleTrayArtwork = [] {
            QIcon icon(":/resource/tray-link.svg");icon.setIsMask(true);return icon;
        }();
        static const QIcon connectedTrayArtwork = [] {
            QIcon icon(":/resource/tray-link-ready.svg");icon.setIsMask(true);return icon;
        }();
        const auto &trayArtwork = connected ? connectedTrayArtwork : idleTrayArtwork;
#else
        const auto trayArtwork = connected ? connectedArtwork : QApplication::windowIcon();
#endif
        if (trayIcon->icon().cacheKey() != trayArtwork.cacheKey())
            trayIcon->setIcon(trayArtwork);
    }
    updateMaintenanceDetails();

    const bool primary = state == ConnectionState::Disconnected || state == ConnectionState::Failed
        || state == ConnectionState::Interrupted || (state == ConnectionState::Stopping && recoveryFailed);
    auto *button = ui->connectButton;
    const auto oldPrimary = button->property("primaryAction");
    if (!oldPrimary.isValid() || oldPrimary.toBool() != primary) {
        button->setProperty("primaryAction",primary);
        button->style()->unpolish(button);
        button->style()->polish(button);
        button->update();
    }
}

void MainWindow::updateMaintenanceDetails()
{
    static const QHash<QString, const char *> results{
        {"running", QT_TR_NOOP("In progress")}, {"succeeded", QT_TR_NOOP("Succeeded")},
        {"failed", QT_TR_NOOP("Failed")}, {"required", QT_TR_NOOP("Sign in again")},
        {"disabled", QT_TR_NOOP("Disabled")}, {"unavailable", QT_TR_NOOP("Unavailable")},
    };
    auto detail = statusDetail;
    const auto mode = connectionSession->keepAliveOptions().mode;
    const QPair<QString, QString> maintenance[]{{"renewal",tr("Session renewal")},
        {"traffic",mode=="target" ? tr("Traffic keepalive (HTTP GET)") : mode=="off" ? tr("Traffic keepalive") : tr("Traffic keepalive (campus DNS)")},
        {"nodes",tr("Node maintenance")},{"tunnel",tr("Tunnel maintenance")}};
    bool trafficUnavailable = false;
    for (const auto &[stage,label]:maintenance) {
        const auto observed=connectionSession->observation(stage);
        detail += tr("\nLast %1: %2").arg(label, tr(results.value(observed.result, QT_TR_NOOP("Unknown"))));
        if (observed.observedAt.isValid()) detail += " · "+observed.observedAt.toLocalTime().toString(Qt::ISODate);
        if (stage=="traffic") trafficUnavailable = observed.result=="unavailable";
    }
    if (trafficUnavailable) detail += tr("\nNo authorized probe resource or campus DNS is available. Check the target and gateway authorization.");
    if (trayIcon) trayIcon->setToolTip(QApplication::applicationName()+" · "+statusTitle+"\n"+detail);
    details->setConnectionStatus(detail);
}

QString MainWindow::connectionName() const
{
    if (savedConnections->usesOverrideConfiguration())
        return QFileInfo(settings->fileName()).completeBaseName();
    return currentConnectionId.isEmpty() ? defaultConnectionLabel(*settings) : currentConnectionId;
}

void MainWindow::updateConnectionSummary()
{
    const auto name = connectionName();
    const auto server = settings->value("JustConnect/ServerAddress").toString().trimmed();
    ui->profileMenuButton->setText(name);
    ui->profileMenuButton->setAccessibleName(tr("Current connection: %1").arg(name));
    ui->profileMenuButton->setToolTip(server.isEmpty() || server == name ? name : name + "\n" + server);
    details->setConnectionSummary(QStringLiteral("aTrust · ") + name + (server.isEmpty()
        ? QStringLiteral(" · ") + tr("No server configured")
        : server == name ? QString() : QStringLiteral(" · ") + server));
}

void MainWindow::setupTrayIcon()
{
    // 系统托盘
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setToolTip(QApplication::applicationName());

    trayConnectAction = new QAction(tr("Connect"), this);
    trayConnectionMenu = new QMenu(tr("Connections"), this);
    trayShowAction = new QAction(tr("Show window"), this);trayShowAction->setObjectName("trayShowAction");
    trayCloseAction = new QAction(tr("Exit %1").arg(QApplication::applicationName()), this);
    auto *trayMenu = new QMenu(this);
    trayMenu->addAction(trayConnectAction);
    trayMenu->addSeparator();
    trayMenu->addMenu(trayConnectionMenu);
    trayMenu->addSeparator();
    trayMenu->addAction(trayShowAction);
    trayMenu->addAction(trayCloseAction);
    connect(trayShowAction, &QAction::triggered, this, [&]() {
        PresentationHelpers::activateWindow(this);
    });
    connect(trayCloseAction, &QAction::triggered, this, &MainWindow::gracefullyQuit);
    trayIcon->setContextMenu(trayMenu);
#ifndef Q_OS_MACOS
    connect(trayIcon, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason != QSystemTrayIcon::Context) PresentationHelpers::activateWindow(this);
    });
#endif
}

void MainWindow::setupConnectionMenu()
{
    // Cocoa uses separate menu surfaces. Share their actions instead of sharing submenus.
    auto *popup = new ConnectionMenu(ui->profileMenuButton);
    ui->profileMenuButton->setMenu(popup);
    switchGroup = new QActionGroup(ui->profileMenu);
    traySwitchGroup = new QActionGroup(trayConnectionMenu);
    switchGroup->setExclusive(true);
    traySwitchGroup->setExclusive(true);
    connectionActionsSeparator = ui->profileMenu->addSeparator();
    ui->profileMenu->addAction(ui->settingAction);
    copyClashScriptAction = ui->profileMenu->addAction(tr("Copy Clash Extend Script"));
    popup->setCopyAction(copyClashScriptAction);
    copyClashScriptAction->setObjectName("copyClashScriptAction");
    connect(connectionSession,&ConnectionSession::stateChanged,this,&MainWindow::updateClashExport);
    connect(coordinator->networkPolicy(),&NetworkPolicySession::changed,this,&MainWindow::updateClashExport);
    connect(copyClashScriptAction, &QAction::triggered, this, [this,popup] {
        if (connectionSession->state()!=ConnectionState::Running || !connectionSession->usesLocalProxy()) return;
        const auto script=ClashExtension::script(SavedConnectionService::load(*settings),connectionName(),
            coordinator->networkPolicy()->localProxyResources());
        if (script.isEmpty()) return;
        auto *clipboard=QApplication::clipboard();
        clipboard->setText(script);
        if (clipboard->text()!=script) return;
        popup->showCopyCheck();
        QAccessibleAnnouncementEvent announcement(ui->profileMenuButton,
            QCoreApplication::translate("PresentationHelpers","Copied to clipboard"));
        QAccessible::updateAccessibility(&announcement);
    });
    addConnectionAction = ui->profileMenu->addAction(tr("Add connection…"));
    renameConnectionAction = ui->profileMenu->addAction(tr("Rename connection…"));
    renameConnectionAction->setObjectName("renameConnectionAction");
    deleteConnectionAction = ui->profileMenu->addAction(tr("Delete connection…"));
    deleteConnectionAction->setObjectName("deleteConnectionAction");
    ui->profileMenu->addSeparator();
    ui->profileMenu->addAction(ui->clearAuthenticationCacheAction);
    ui->profileMenu->addAction(ui->clearClientDataAction);
    popup->addActions(ui->profileMenu->actions());

    connect(addConnectionAction, &QAction::triggered, this, &MainWindow::createConnection);
    addConnectionAction->setObjectName("addConnectionAction");
    connect(renameConnectionAction, &QAction::triggered, this, &MainWindow::renameCurrentConnection);
    connect(deleteConnectionAction, &QAction::triggered, this, &MainWindow::deleteCurrentConnection);

    refreshConnectionMenu();
}

void MainWindow::refreshConnectionMenu()
{
    auto connectionIds = savedConnections->connections();
    connectionIds.prepend(QString());
    const auto actions = switchGroup->actions();
    const bool rebuild = actions.size() != connectionIds.size()
        || !std::equal(actions.cbegin(), actions.cend(), connectionIds.cbegin(),
            [](const QAction *action, const QString &id) { return action->data().toString() == id; });
    const bool overrideConfiguration = savedConnections->usesOverrideConfiguration();
    const auto defaultName = currentConnectionId.isEmpty() && !overrideConfiguration
        ? connectionName()
        : defaultConnectionLabel(QSettings(SavedConnectionStore().connectionPath({}), QSettings::IniFormat));
    const auto updateMenu = [&](QMenu *menu, QActionGroup *group, QAction *before = nullptr) {
        if (rebuild) {
            qDeleteAll(group->actions());
            for (const auto &id : connectionIds) {
                auto *action = new QAction(id, menu);
                menu->insertAction(before, action);
                action->setData(id);
                action->setCheckable(true);
                group->addAction(action);
                connect(action, &QAction::triggered, this, [this, id] { switchConnection(id); });
            }
        }
        for (auto *action : group->actions()) {
            const auto id = action->data().toString();
            if (id.isEmpty()) action->setText(defaultName);
            action->setChecked(id == currentConnectionId && (id.isEmpty() || !overrideConfiguration));
        }
    };
    updateMenu(ui->profileMenu, switchGroup, connectionActionsSeparator);
    updateMenu(trayConnectionMenu, traySwitchGroup);
    if (rebuild) ui->profileMenuButton->menu()->insertActions(connectionActionsSeparator, switchGroup->actions());

    updateClashExport();
    const bool currentProfileIsManaged = !currentConnectionId.isEmpty() && !overrideConfiguration;
    renameConnectionAction->setEnabled(currentProfileIsManaged);
    deleteConnectionAction->setEnabled(currentProfileIsManaged);
}

void MainWindow::updateClashExport()
{
    copyClashScriptAction->setEnabled(connectionSession->state()==ConnectionState::Running
        && connectionSession->usesLocalProxy() && !coordinator->networkPolicy()->localProxyResources().isEmpty());
}

bool MainWindow::switchConnection(const QString &connectionId)
{
    if (!savedConnections->usesOverrideConfiguration()
        && connectionId == currentConnectionId)
    {
        return true;
    }

    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, tr("Could not switch connection"), tr("Disconnect before switching connections."));
        refreshConnectionMenu();
        return false;
    }

    if (connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving())) {
        QMessageBox::information(this,tr("Saving connection"),tr("Wait for the save before switching connections."));refreshConnectionMenu();return false;
    }
    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    if (!savedConnections->switchTo(connectionId))
    {
        QMessageBox::warning(this,tr("Could not switch connection"),tr("Could not save the current connection or read the selected connection. Check the file permissions and contents."));
        refreshConnectionMenu();
        return false;
    }
    settings = savedConnections->settings();
    currentConnectionId = savedConnections->currentConnectionId();

    upgradeSettings();
    resetConnectionUi();
    resetConnectionLog();
    refreshConnectionMenu();

    qInfo().noquote() << tr("Switched connection to %1").arg(connectionName());
    return true;
}

void MainWindow::createConnection()
{
    if (connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving())) {
        QMessageBox::information(this,tr("Saving connection"),tr("Wait for the save before adding a connection."));return;
    }
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, tr("Could not add connection"), tr("Disconnect before adding a connection."));
        return;
    }

    const auto name=requestConnectionName(this,tr("Add connection…"),tr("Continue"));
    if (!name)
    {
        return;
    }

    const auto draft=std::make_shared<QTemporaryDir>();
    if (!draft->isValid())
    {
        QMessageBox::critical(this, tr("Could not add connection"), tr("The new connection could not be created."));
        return;
    }
    QSettings draftSettings(draft->filePath("connection.ini"),QSettings::IniFormat);
    DefaultSettings::reset(draftSettings);
    const auto source=CredentialAccess::source(draftSettings,{});
    if (source.scope.isEmpty()) {
        QMessageBox::critical(this,tr("Could not add connection"),tr("The new connection could not be created."));
        return;
    }
    if (settingWindow) settingWindow->close();
    connectionUiController->cancelPendingCredentials();
    settingWindow=new SettingWindow(this,coordinator->credentials(),source,nullptr,[this,draft,requestedName=*name] {
        if (connectionSession->isActive()
            || savedConnections->createAndSwitch(requestedName,draft->filePath("connection.ini")).isEmpty()) return false;
        settings=savedConnections->settings();
        currentConnectionId=savedConnections->currentConnectionId();
        resetConnectionUi();
        resetConnectionLog();
        refreshConnectionMenu();
        return true;
    });
    settingWindow->setObjectName("connectionSettingsDialog");
    connect(settingWindow,&SettingWindow::connectRequested,connectionUiController,&ConnectionUiController::enableCampusAccess,Qt::QueuedConnection);
    PresentationHelpers::activateWindow(settingWindow);
}

void MainWindow::renameCurrentConnection()
{
    if (coordinator->credentials()->isBusy(settings->fileName()) || connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving())) {
        QMessageBox::information(this,tr("Secure storage is busy"),tr("Wait for the current operation before renaming."));return;
    }
    const auto name=requestConnectionName(this,tr("Rename connection…"),tr("Rename"),currentConnectionId);
    if (!name)
    {
        return;
    }

    const QString normalizedName = savedConnections->normalizeConnectionId(*name);
    if (normalizedName.isEmpty())
    {
        QMessageBox::warning(this, tr("Could not rename connection"), tr("The connection name cannot be empty."));
        return;
    }
    if (normalizedName == currentConnectionId)
    {
        return;
    }
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, tr("Could not rename connection"), tr("Disconnect before renaming a connection."));
        return;
    }

    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }
    connectionUiController->cancelPendingCredentials();
    const auto source=coordinator->credentialSource();
    coordinator->credentials()->migrate(source).then(this,[this,source,normalizedName](const CredentialResult &result) {
        if (!CredentialAccess::matches(source,*settings)) return;
        if (!result.succeeded()) {QMessageBox::warning(this,tr("Rename incomplete"),PresentationHelpers::credentialOperationMessage(result.status)+tr("\nComplete the legacy credential migration first, or add a new connection."));return;}
        if (!savedConnections->renameCurrent(normalizedName)) {QMessageBox::warning(this,tr("Could not rename connection"),tr("The name is already in use or the connection cannot be renamed."));return;}
        currentConnectionId=savedConnections->currentConnectionId();settings=savedConnections->settings();
        updateConnectionSummary();refreshConnectionMenu();resetConnectionLog();qInfo().noquote()<<tr("Connection renamed to: ")+currentConnectionId;
    });
}

void MainWindow::deleteCurrentConnection()
{
    if (savedConnections->usesOverrideConfiguration()) {QMessageBox::warning(this,tr("Could not delete connection"),tr("External connections cannot be deleted here."));return;}
    if (coordinator->credentials()->isBusy(settings->fileName()) || connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving())) {
        QMessageBox::information(this,tr("Secure storage is busy"),tr("Wait for the current operation before deleting the connection."));return;
    }
    if (currentConnectionId.isEmpty())
    {
        QMessageBox::warning(this, tr("Could not delete connection"), tr("The primary connection cannot be deleted."));
        return;
    }

    if (!PresentationHelpers::actionPrompt(this,tr("Delete connection"),
        tr("Delete “%1”?").arg(currentConnectionId) + "\n\n" +
        tr("This removes its settings and old cache. Clear saved credentials and sign-ins first if you want them removed too."),
        QDialogButtonBox::Yes,QDialogButtonBox::Cancel,tr("Delete"))) return;

    const QString removedConnectionId = currentConnectionId;
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, tr("Could not delete connection"), tr("Disconnect before deleting a connection."));
        return;
    }
    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }
    connectionUiController->cancelPendingCredentials();
    const auto legacy=coordinator->credentialSource().legacyCachePath;
    if (!legacy.isEmpty() && QFileInfo::exists(legacy) && !QFile::remove(legacy)) {
        QMessageBox::warning(this,tr("Delete incomplete"),tr("The legacy cache could not be removed. The connection was preserved. Check access permissions and retry."));return;
    }
    if (!savedConnections->removeCurrentAndSwitchToDefault())
    {
        QMessageBox::warning(this, tr("Could not delete connection"), tr("The connection settings file could not be deleted."));
        return;
    }

    currentConnectionId = savedConnections->currentConnectionId();
    settings = savedConnections->settings();
    upgradeSettings();
    resetConnectionUi();
    resetConnectionLog();
    refreshConnectionMenu();
    qInfo().noquote() << tr("Deleted connection: ") + removedConnectionId;
}

void MainWindow::upgradeSettings()
{
    const SettingsMigrationAction action = SettingsMigrator::prepare(*settings,
        currentConnectionId.isEmpty() && !savedConnections->usesOverrideConfiguration());
    if (action == SettingsMigrationAction::MigrateAutoStart)
    {
        if (!savedConnections->migrateAutoStartSetting(settings->value("Common/AutoStart", false).toBool())) {
            QMessageBox::warning(this, tr("Startup preference migration failed"), tr("The previous startup preference could not be saved. The old configuration is preserved for retry."));
            return;
        }
    }
    if (action == SettingsMigrationAction::Failed || !SettingsMigrator::finish(*settings))
    {
        QMessageBox::warning(this, tr("Connection settings migration incomplete"), tr("The upgraded connection settings could not be saved. The previous settings were kept for retry."));
    }
}

void MainWindow::updateVersionInfo()
{
    const VersionInfo &versionInfo = updateChecker->versionInfo();
    QString latest;
    switch(versionInfo.updateState){
    case VersionInfo::UpdateState::Checking:latest=tr("Checking…");break;
    case VersionInfo::UpdateState::Disabled:latest=tr("Disabled");break;
    case VersionInfo::UpdateState::Failed:latest=tr("Check failed");break;
    case VersionInfo::UpdateState::Ready:latest=versionInfo.uiLatest;break;
    }
    ui->checkUpdateAction->setToolTip(tr("Update status: %1").arg(latest));
}

void MainWindow::showNotification(const QString &title, const QString &content, QSystemTrayIcon::MessageIcon icon)
{
    if(!QSystemTrayIcon::isSystemTrayAvailable() || !QSystemTrayIcon::supportsMessages()){
        auto *notice=new QMessageBox(icon==QSystemTrayIcon::Warning?QMessageBox::Warning:QMessageBox::Information,
            title,content,QMessageBox::Ok,this);
        notice->setAttribute(Qt::WA_DeleteOnClose);notice->setWindowModality(Qt::NonModal);notice->show();return;
    }
    disconnect(trayIcon, &QSystemTrayIcon::messageClicked, nullptr, nullptr);
    trayIcon->showMessage(
        title,
        content,
        icon,
        10000
    );

    connect(trayIcon, &QSystemTrayIcon::messageClicked, this, [&]()
    {
        disconnect(trayIcon, &QSystemTrayIcon::messageClicked, nullptr, nullptr);

        PresentationHelpers::activateWindow(this);
    });
}

void MainWindow::cleanUpWhenQuit()
{
    settings->sync();

    if (connectionSession->isActive() || systemProxySession->isBusy() || systemProxySession->needsCleanup() || coordinator->credentials()->isBusy())
        qWarning() << "Application exited before ordered cleanup completed";
}

void MainWindow::gracefullyQuit()
{
    connectionUiController->prepareForQuit();
}

MainWindow::~MainWindow()
{
    delete details;
    delete coordinator;
    coordinator = nullptr;

    delete ui;
    ui = nullptr;
}

void MainWindow::endSystemSession()
{
    // Cocoa can ask again when the final Qt quit is delivered after cleanup.
    if (exitReady) return;
    QEventLoop cleanup;
    bool settled=false;
    const auto finished=connect(this,&MainWindow::shutdownSettled,&cleanup,[&](bool) {settled=true;cleanup.quit();});
    QTimer deadline;deadline.setSingleShot(true);deadline.setInterval(16000);
    connect(&deadline,&QTimer::timeout,&cleanup,&QEventLoop::quit);
    setProperty("systemShutdown",true);
    gracefullyQuit();
    if (!settled) {deadline.start();cleanup.exec();}
    setProperty("systemShutdown",false);
    disconnect(finished);
}
