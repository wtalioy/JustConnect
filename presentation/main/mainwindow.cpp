#include <QMessageBox>
#include <QSysInfo>
#include <QDesktopServices>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QActionGroup>
#include <QInputDialog>
#include <QStyle>
#include <QTimer>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QHash>
#include <QTabBar>
#include <QFontDatabase>
#include <QDialogButtonBox>
#include <QScrollArea>
#include <QVBoxLayout>
#include "presentation/widgets/applicationpreferenceswidget.h"
#include "presentation/widgets/localizeddialog.h"
#include <QtAlgorithms>
#include <algorithm>
#include "infrastructure/settings/savedconnectionstore.h"

#include "mainwindow.h"
#include "presentation/appearance/applicationappearance.h"
#include "presentation/dialogs/networkpolicywindow.h"

#include "application/applicationlogger.h"
#include "application/networkpolicysession.h"
#include "application/applicationconstants.h"
#include "application/defaultsettings.h"
#include "application/commandlineoptions.h"
#include "application/settingsmigrator.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/update/updatechecker.h"
#include "presentation/coordinators/connectionuicontroller.h"
#include "presentation/i18n/applicationlanguage.h"
#include "presentation/presentationhelpers.h"
#include "presentation/coordinators/connectiondiagnostics.h"
#include "ui_mainwindow.h"

namespace {
QString unnamedConnectionLabel(const QSettings &settings)
{
    const auto server = settings.value("JustConnect/ServerAddress").toString().trimmed();
    if (server.isEmpty()) return MainWindow::tr("Unnamed connection");
    return DefaultSettings::isBuiltInConnection(settings) ? MainWindow::tr("Fudan") : server;
}
}

MainWindow::MainWindow(
    ApplicationLogger *logger,
    ApplicationLogFile *logFile,
    QWidget *parent,
    MainWindowCoordinator::NetworkFactory networkFactory
) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    applicationLogger(logger),
    applicationLogFile(logFile)
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

    QApplication::setWindowIcon(QIcon(":/resource/icon.svg"));
    ui->setupUi(this);
    ui->centralWidget->setFocus(Qt::OtherFocusReason);
    ui->logPlainTextEdit->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    ui->detailsDialog->resize(640,568);
    PresentationHelpers::setButtonIcon(ui->diagnosticRulesButton,":/resource/rules.svg");
    connect(ui->detailsButton,&QPushButton::clicked,this,[this] {
        if (!ui->detailsDialog->isVisible()) {
            ui->detailsTabs->setCurrentIndex(0);
            ui->detailsTabs->tabBar()->setFocus();
        }
        updateDiagnostics();
        PresentationHelpers::activateWindow(ui->detailsDialog);
    });
    ui->diagnosticReport->header()->setSectionResizeMode(0,QHeaderView::ResizeToContents);
    ui->diagnosticReport->header()->setSectionResizeMode(1,QHeaderView::Stretch);
    ui->diagnosticReport->setSelectionMode(QAbstractItemView::NoSelection);
    ui->diagnosticReport->setFocusPolicy(Qt::TabFocus);
    connect(coordinator->diagnostics(), &ConnectionDiagnostics::changed, this, [this] {
        if (ui->overviewTab->isVisible()) updateDiagnostics();
    });
    connect(ui->detailsTabs, &QTabWidget::currentChanged, this, [this] {
        if (ui->overviewTab->isVisible()) updateDiagnostics();
    });
    connect(ui->refreshDiagnosticsButton, &QPushButton::clicked,
        coordinator->networkPolicy(), &NetworkPolicySession::refresh);
    PresentationHelpers::connectCopyButton(ui->copyDiagnosticsButton, [this] {
        return QApplication::applicationVersion() + "\n" + coordinator->diagnostics()->report();
    });
    authenticationDialogs = coordinator->authenticationDialogs();
    connectionSession = coordinator->connection();
    systemProxySession = coordinator->systemProxy();
    updateChecker = coordinator->updates();
    connect(coordinator->credentials(),&CredentialAccess::configurationSaved,this,[this](const QString &path) {
        if (settings && settings->fileName()==path) {
            updateConnectionSummary();
            if (currentConnectionId.isEmpty()) refreshConnectionMenu();
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
    logFlushTimer.setSingleShot(true);
    connect(&logFlushTimer, &QTimer::timeout, this, &MainWindow::flushLog);
    connect(applicationLogger, &ApplicationLogger::entryAdded, this, [this](const QString &entry) {
        pendingLogEntries.append(entry);
        if (pendingLogEntries.size() >= ui->logPlainTextEdit->maximumBlockCount())
            flushLog();
        else if (!logFlushTimer.isActive())
            logFlushTimer.start();
    });
    connect(systemProxySession,&SystemProxySession::enabledChanged,this,[this] {
        updateConnectionSummary();updateConnectionState(connectionSession->state());
    });
    setupTrayIcon();
    setupConnectionMenu();
    auto *applicationMenu = new QMenu(ui->applicationMenuButton);
    applicationMenu->setToolTipsVisible(true);
    applicationMenu->addAction(ui->checkUpdateAction);
    applicationMenu->addAction(ui->projectAction);
    applicationMenu->addAction(ui->aboutAction);
    applicationMenu->addSeparator();
    applicationMenu->addAction(ui->exitAction);
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

    connect(connectionSession, &ConnectionSession::stateChanged, this,
            &MainWindow::updateConnectionState);
    connect(connectionSession, &ConnectionSession::progressChanged, this, [this] { updateConnectionState(connectionSession->state()); });


    // 文件-退出
    connect(ui->exitAction, &QAction::triggered, this, &MainWindow::gracefullyQuit);

    connect(ui->preferencesAction,&QAction::triggered,this,&MainWindow::showApplicationPreferences);

    // 文件-设置
    connect(ui->settingAction,&QAction::triggered,this,[this]{showConnectionSettings();});

    connect(ui->openLogPushButton, &QPushButton::clicked,
            ui->openLogAction, &QAction::trigger);

    connect(ui->inspectNetworkAction, &QAction::triggered, this, [this] {
        if (!networkPolicyWindow) {
            networkPolicyWindow = new NetworkPolicyWindow(coordinator->networkPolicy(), this);
            networkPolicyWindow->setAttribute(Qt::WA_DeleteOnClose);
        }
        networkPolicyWindow->show();
        networkPolicyWindow->raise();
        networkPolicyWindow->activateWindow();
    });

    connect(ui->diagnosticRulesButton, &QPushButton::clicked, ui->inspectNetworkAction, &QAction::trigger);

    // 文件-打开日志文件
    connect(ui->openLogAction, &QAction::triggered, this,
            [this]()
            {
                const QString logFilePath = applicationLogFile->filePath();
                QFileInfo logFileInfo(logFilePath);

                if (logFileInfo.exists())
                {
                    QDesktopServices::openUrl(QUrl::fromLocalFile(logFilePath));
                }
                else
                {
                    QMessageBox::warning(this, tr("Log file"), tr("The log file could not be created."));
                }
            });

    connect(ui->clearAuthenticationCacheAction,&QAction::triggered,this,[this] {
        connectionUiController->clearAuthenticationCache();
    });

    connect(ui->clearClientDataAction,&QAction::triggered,this,[this] {
        if (coordinator->credentials()->isBusy(settings->fileName()) || connectionUiController->isConfigurationSaving()) {
            QMessageBox::information(this,tr("Secure storage is busy"),tr("Wait for the current operation before clearing legacy data."));return;
        }
        const auto source=coordinator->credentialSource();
        QMessageBox confirm(QMessageBox::Question,tr("Clear legacy data"),
            tr("Delete this connection's legacy cache and its quarantined copy in secure storage? This unbound data is not used for login. Current account caches, passwords, TOTP and other connections are preserved."),
            QMessageBox::Yes|QMessageBox::No,this);
        confirm.setDefaultButton(QMessageBox::No);
        if (confirm.exec()!=QMessageBox::Yes) return;
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

    // 帮助-关于本软件
    connect(ui->aboutAction, &QAction::triggered,
            [&]()
            {
                PresentationHelpers::showAboutDialog(this, updateChecker->versionInfo().coreVersion);
            });

    PresentationHelpers::connectCopyButton(ui->copyLogPushButton, [this] {
        flushLog();
        return ui->logPlainTextEdit->toPlainText();
    });
    connect(ui->clearLogPushButton, &QPushButton::clicked, this, &MainWindow::clearLog);

    resetConnectionLog();
    connectionUiController = new ConnectionUiController(
        this,
        ui->connectButton,
        trayConnectAction,
        connectionSession,
        systemProxySession,
        coordinator->networkPolicy(),
        authenticationDialogs,
        applicationLogger,
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
        QApplication::quit();
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

    if (settings->value("Common/CheckUpdateAfterStart", true).toBool())
    {
        updateChecker->check();
    }
    else
    {
        updateChecker->markDisabled();
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
    addConnectionAction->setText(tr("Add connection…"));renameConnectionAction->setText(tr("Rename connection…"));deleteConnectionAction->setText(tr("Delete connection…"));
    trayConnectionMenu->setTitle(tr("Connections"));trayShowAction->setText(tr("Show window"));
    trayCloseAction->setText(tr("Exit %1").arg(QApplication::applicationName()));
    connectionUiController->refreshActions();refreshConnectionMenu();updateConnectionSummary();updateVersionInfo();updateConnectionState(connectionSession->state());
    if (ui->overviewTab->isVisible()) updateDiagnostics();
}

bool MainWindow::eventFilter(QObject *watched,QEvent *event)
{
    if (watched==qApp && event->type()==QEvent::Quit && !exitReady) {
        gracefullyQuit();
        return true;
    }
    return QMainWindow::eventFilter(watched,event);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (exitReady) { event->accept();return; }
    event->ignore();
    if (!SavedConnectionStore().closeToTray()) { gracefullyQuit();return; }
    if (trayIcon && trayIcon->isVisible() && QSystemTrayIcon::isSystemTrayAvailable()) {
        hide();
        showNotification("JustConnect", tr("JustConnect is running in the system tray. Click its icon to restore the window; use Exit to quit."), QSystemTrayIcon::Information);
    } else {
        PresentationHelpers::activateWindow(this);
        setProperty("trayUnavailable",true);
        ui->statusHintLabel->setText(tr("System tray unavailable. Use Exit in the application menu to quit."));
        ui->statusHintLabel->show();
    }
}


void MainWindow::showApplicationPreferences() {
    if (!preferencesWindow) {
        auto *view=new LocalizedDialog<QDialog>(this);preferencesWindow=view;
        view->setObjectName("applicationSettingsDialog");view->setAttribute(Qt::WA_DeleteOnClose);
        view->setWindowModality(Qt::WindowModal);
        auto *layout=new QVBoxLayout(view);layout->setContentsMargins(24,24,24,24);layout->setSpacing(16);
        auto *scroll=new QScrollArea(view);scroll->setWidgetResizable(true);scroll->setFrameShape(QFrame::NoFrame);
        auto *contents=new ApplicationPreferencesWidget(scroll);
        connect(contents, &ApplicationPreferencesWidget::startupSaveStarted, view, [view] {
            view->setAttribute(Qt::WA_DeleteOnClose, false);
        });
        connect(contents, &ApplicationPreferencesWidget::startupSaveFinished, view, [this, view] {
            view->setAttribute(Qt::WA_DeleteOnClose);
            if (!view->isVisible()) {
                preferencesWindow = nullptr;
                view->deleteLater();
            }
        });
        scroll->setWidget(contents);layout->addWidget(scroll);
        auto *buttons=new QDialogButtonBox(QDialogButtonBox::Close,view);buttons->setObjectName("applicationSettingsButtons");
        connect(buttons,&QDialogButtonBox::rejected,view,&QDialog::reject);layout->addWidget(buttons);
        view->setTranslation([view,this]{view->setWindowTitle(tr("App settings"));});
        view->setMinimumSize(320,360);view->resize(560,560);
    }
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

void MainWindow::flushLog()
{
    logFlushTimer.stop();
    if (pendingLogEntries.isEmpty()) return;
    const auto text = pendingLogEntries.join(u'\n');
    pendingLogEntries.clear();
    ui->logPlainTextEdit->appendPlainText(text);
}

void MainWindow::clearLog()
{
    logFlushTimer.stop();
    pendingLogEntries.clear();
    ui->logPlainTextEdit->clear();
}

void MainWindow::resetConnectionLog()
{
    clearLog();
    ui->logPlainTextEdit->appendPlainText(tr("Welcome to %1\nSystem: %2\nConnection: %3\nConfiguration: %4\n")
        .arg(QApplication::applicationDisplayName(),QSysInfo::prettyProductName(),
            connectionName(),settings->fileName()));
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

    const bool needsAttention=state==ConnectionState::Failed || state==ConnectionState::Interrupted || recoveryFailed;
    const bool noTray=property("trayUnavailable").toBool();
    ui->statusHintLabel->setText(noTray ? tr("System tray unavailable. Use Exit in the application menu to quit.") : needsAttention ? detail : QString());
    ui->statusHintLabel->setVisible(noTray || needsAttention);
    static const QHash<QString, const char *> results{
        {"running", QT_TR_NOOP("In progress")}, {"succeeded", QT_TR_NOOP("Succeeded")},
        {"failed", QT_TR_NOOP("Failed")}, {"required", QT_TR_NOOP("Sign in again")},
        {"disabled", QT_TR_NOOP("Disabled")}, {"unavailable", QT_TR_NOOP("Unavailable")},
    };
    const auto traffic=connectionSession->observation("traffic");
    const auto mode=connectionSession->keepAliveOptions().mode;
    const QPair<QString, QString> maintenance[]{{"renewal",tr("Session renewal")},
        {"traffic",mode=="target" ? tr("Traffic keepalive (HTTP GET)") : mode=="off" ? tr("Traffic keepalive") : tr("Traffic keepalive (campus DNS)")},
        {"nodes",tr("Node maintenance")},{"tunnel",tr("Tunnel maintenance")}};
    for (const auto &[stage,label]:maintenance) {
        const auto observed=connectionSession->observation(stage);
        detail += tr("\nLast %1: %2").arg(label, tr(results.value(observed.result, QT_TR_NOOP("Unknown"))));
        if (observed.observedAt.isValid()) detail += " · "+observed.observedAt.toLocalTime().toString(Qt::ISODate);
    }
    if (traffic.result=="unavailable") detail += tr("\nNo authorized probe resource or campus DNS is available. Check the target and gateway authorization.");
    ui->statusTitleLabel->setText(title);
    static const QIcon idleArtwork(":/resource/connection.svg");
    static const QIcon connectedArtwork(":/resource/connection-ready.svg");
    const bool connected = state == ConnectionState::Running && phase == ConnectionPhase::CampusReady;
    ui->statusIndicator->setPixmap((connected ? connectedArtwork : idleArtwork)
        .pixmap(ui->statusIndicator->size(),devicePixelRatioF()));
    if (trayIcon) {
        trayIcon->setToolTip(QApplication::applicationName()+" · "+title+"\n"+detail);
        const auto trayArtwork = connected ? connectedArtwork : QApplication::windowIcon();
        if (trayIcon->icon().cacheKey() != trayArtwork.cacheKey())
            trayIcon->setIcon(trayArtwork);
    }
    ui->statusDetailLabel->setText(detail);

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

QString MainWindow::connectionName() const
{
    if (savedConnections->usesOverrideConfiguration())
        return QFileInfo(settings->fileName()).completeBaseName();
    return currentConnectionId.isEmpty() ? unnamedConnectionLabel(*settings) : currentConnectionId;
}

void MainWindow::updateConnectionSummary()
{
    const auto name = connectionName();
    const auto server = settings->value("JustConnect/ServerAddress").toString().trimmed();
    ui->profileMenuButton->setText(name);
    ui->profileMenuButton->setAccessibleName(tr("Current connection: %1").arg(name));
    ui->profileMenuButton->setToolTip(server.isEmpty() || server == name ? name : name + "\n" + server);
    ui->profileDetailLabel->setText(QStringLiteral("aTrust · ") + name + (server.isEmpty()
        ? QStringLiteral(" · ") + tr("No server configured")
        : server == name ? QString() : QStringLiteral(" · ") + server));
}

void MainWindow::setupTrayIcon()
{
    // 系统托盘
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setIcon(QApplication::windowIcon());
    trayIcon->setToolTip(QApplication::applicationName());
    connect(trayIcon, &QSystemTrayIcon::activated, this, [&](QSystemTrayIcon::ActivationReason reason) {
        switch (reason)
        {
        case QSystemTrayIcon::Context:
            break;
        default:
            PresentationHelpers::activateWindow(this);
            break;
        }
    });

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
    trayIcon->show();
}

void MainWindow::setupConnectionMenu()
{
    // Cocoa uses separate menu surfaces. Share their actions instead of sharing submenus.
    auto *popup = new QMenu(ui->profileMenuButton);
    ui->profileMenuButton->setMenu(popup);
    switchGroup = new QActionGroup(ui->profileMenu);
    traySwitchGroup = new QActionGroup(trayConnectionMenu);
    switchGroup->setExclusive(true);
    traySwitchGroup->setExclusive(true);
    connectionActionsSeparator = ui->profileMenu->addSeparator();
    ui->profileMenu->addAction(ui->settingAction);
    addConnectionAction = ui->profileMenu->addAction(tr("Add connection…"));
    renameConnectionAction = ui->profileMenu->addAction(tr("Rename connection…"));
    deleteConnectionAction = ui->profileMenu->addAction(tr("Delete connection…"));
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
        : unnamedConnectionLabel(QSettings(SavedConnectionStore().connectionPath({}), QSettings::IniFormat));
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

    const bool currentProfileIsManaged = !currentConnectionId.isEmpty() && !overrideConfiguration;
    renameConnectionAction->setEnabled(currentProfileIsManaged);
    deleteConnectionAction->setEnabled(currentProfileIsManaged);
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

    bool ok = false;
    const QString name = QInputDialog::getText(
        this,
        tr("Add connection…"),
        tr("Connection name:\nUse letters, numbers, underscores or hyphens."),
        QLineEdit::Normal,
        "",
        &ok
    );
    if (!ok)
    {
        return;
    }

    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    const QString newConnectionId = savedConnections->createAndSwitch(name);
    if (newConnectionId.isEmpty())
    {
        QMessageBox::critical(this, tr("Could not add connection"), tr("The new connection could not be created."));
        return;
    }

    settings = savedConnections->settings();
    currentConnectionId = savedConnections->currentConnectionId();
    upgradeSettings();
    resetConnectionUi();
    resetConnectionLog();
    refreshConnectionMenu();

    showConnectionSettings();
}

void MainWindow::renameCurrentConnection()
{
    if (coordinator->credentials()->isBusy(settings->fileName()) || connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving())) {
        QMessageBox::information(this,tr("Secure storage is busy"),tr("Wait for the current operation before renaming."));return;
    }
    bool ok = false;
    QString name = QInputDialog::getText(this, tr("Rename connection…"), tr("New connection name:\nUse letters, numbers, underscores or hyphens."), QLineEdit::Normal, currentConnectionId, &ok);
    if (!ok)
    {
        return;
    }

    const QString normalizedName = savedConnections->normalizeConnectionId(name);
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

    QMessageBox messageBox(this);
    messageBox.setWindowTitle(tr("Delete connection"));
    messageBox.setInformativeText(tr("Deleting this connection removes its settings file and legacy cache. To also remove saved credentials, clear them in Connection settings and use the cache actions in the Connections menu before deleting."));
    messageBox.setText(tr("Delete connection “%1”?").arg(currentConnectionId));
    auto *remove=messageBox.addButton(QMessageBox::Yes);remove->setText(tr("Delete"));
    PresentationHelpers::setButtonIcon(remove,":/resource/file-remove.svg");
    messageBox.addButton(QMessageBox::No)->setText(tr("Cancel"));
    messageBox.setDefaultButton(QMessageBox::No);
    if (messageBox.exec() != QMessageBox::Yes)
    {
        return;
    }

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
    delete coordinator;
    coordinator = nullptr;

    QObject::disconnect(applicationLogger, nullptr, this, nullptr);
    delete ui;
    ui = nullptr;
}

void MainWindow::endSystemSession()
{
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

void MainWindow::updateDiagnostics()
{
    const auto fields=coordinator->diagnostics()->fields();
    QList<QStringList> rows;
    for(const auto &[label,value]:fields) rows.append(QStringList{label,value});
    PresentationHelpers::setTreeRows(ui->diagnosticReport,rows);
    auto *policy = coordinator->networkPolicy();
    ui->refreshDiagnosticsButton->setEnabled(!policy->currentGeneration().isEmpty() && !policy->isBusy());
}
