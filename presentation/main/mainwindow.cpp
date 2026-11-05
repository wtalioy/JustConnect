#include <QMessageBox>
#include <QSysInfo>
#include <QClipboard>
#include <QDesktopServices>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QActionGroup>
#include <QInputDialog>
#include <QMargins>
#include <QStyle>
#include <QTimer>
#include <QPushButton>
#include <QLabel>
#include <QtAlgorithms>
#include "infrastructure/settings/profilemanager.h"

#include "mainwindow.h"
#include "presentation/appearance/applicationappearance.h"
#include "presentation/dialogs/networkpolicywindow.h"

#include "application/applicationlogger.h"
#include "application/networkpolicysession.h"
#include "application/applicationconstants.h"
#include "application/commandlineoptions.h"
#include "application/settingsmigrator.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/update/updatechecker.h"
#include "presentation/coordinators/connectionuicontroller.h"
#include "presentation/dialogs/applicationpreferences/applicationpreferencesdialog.h"
#include "presentation/i18n/applicationlanguage.h"
#include "presentation/dialogs/configurationguidedialog/configurationguidedialog.h"
#include "presentation/presentationhelpers.h"
#include "presentation/coordinators/connectiondiagnostics.h"
#include "ui_mainwindow.h"

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
    ApplicationLanguage::instance();
    const QString overrideConfigPath =
        CommandLineOptions::value(QCoreApplication::arguments(), "--config-path");
    coordinator = new MainWindowCoordinator(this, overrideConfigPath, this, networkFactory);
    profileService = coordinator->profiles();
    currentProfileId = profileService->currentProfileId();
    settings = profileService->settings();

    const bool isFirstLaunch =
        !settings->contains("Common/ConfigVersion");
    upgradeSettings();

    ApplicationAppearance::install();
    ui->setupUi(this);
    ui->detailsDialog->resize(720,700);
    connect(ui->detailsButton,&QPushButton::clicked,this,[this] {updateDiagnostics();PresentationHelpers::activateWindow(ui->detailsDialog);});
    ui->diagnosticReport->document()->setMaximumBlockCount(32);
    connect(coordinator->diagnostics(),&ConnectionDiagnostics::changed,this,[this]{if(ui->detailsDialog->isVisible())updateDiagnostics();});
    connect(ui->refreshDiagnosticsButton,&QPushButton::clicked,this,[this]{coordinator->networkPolicy()->refresh();updateDiagnostics();});
    connect(ui->copyDiagnosticsButton,&QPushButton::clicked,this,[this]{QApplication::clipboard()->setText(QApplication::applicationVersion()+"\n"+coordinator->diagnostics()->report());});
    connect(ui->closeButton,&QPushButton::clicked,this,&QWidget::close);
#ifdef Q_OS_MACOS
    const QMargins centralMargins = ui->centralWidget->contentsMargins();
    ui->centralWidget->setContentsMargins(centralMargins.left(), 12, centralMargins.right(), centralMargins.bottom());
#endif
    ui->logPlainTextEdit->setFont(
        QFontDatabase::systemFont(QFontDatabase::FixedFont)
    );
    authenticationDialogs = coordinator->authenticationDialogs();
    connectionSession = coordinator->connection();
    systemProxySession = coordinator->systemProxy();
    updateChecker = coordinator->updates();
    connect(coordinator->credentials(),&CredentialAccess::configurationSaved,this,[this](const QString &path) {
        if (settings && settings->fileName()==path) updateProfileSummary();
    });
    connect(updateChecker, &UpdateChecker::versionInfoChanged, this,
            [this](const VersionInfo &) { updateVersionInfo(); });
    connect(updateChecker, &UpdateChecker::uiUpdateAvailable, this,
            [this](const QString &latestVersion)
            {
                QMessageBox msgBox(this);
                msgBox.setText(tr("Update available"));
                msgBox.setInformativeText(
                    tr("A new version is available: ") + latestVersion + tr("\nOpen the release page?")
                );
                msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
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
    connect(applicationLogger, &ApplicationLogger::entryAdded, this,
            [this](const QString &entry)
            {
                ui->logPlainTextEdit->appendPlainText(entry);
            });
    connect(systemProxySession, &SystemProxySession::busyChanged, this,
            [this](bool busy)
            {
                ui->disableProxyAction->setEnabled(!busy && systemProxySession->needsCleanup());
            });
    connect(systemProxySession, &SystemProxySession::enabledChanged, this,
            [this](bool enabled)
            {
                ui->disableProxyAction->setEnabled(!systemProxySession->isBusy() && systemProxySession->needsCleanup());
                if (!systemProxySession->needsCleanup() && connectionSession != nullptr && !connectionSession->isActive())
                {
                    ui->proxyButton->hide();
                }
                updateProfileSummary();
                updateConnectionState(connectionSession->state());
            });
    connect(systemProxySession, &SystemProxySession::operationFinished, this,
        [this](bool, const PlatformOperationResult &result) {
            if (!result.succeeded()) QMessageBox::warning(this, tr("System proxy operation incomplete"),
                PresentationHelpers::platformOperationMessage(result));
        });
    setupTrayIcon();
    setupProfileMenu();
    auto *more=new QMenu(this);
    more->addAction(ui->preferencesAction);
    more->addAction(ui->configurationGuideAction);
    more->addAction(ui->inspectNetworkAction);
    more->addMenu(ui->helpMenu);
    more->addSeparator();
    more->addAction(ui->clearAuthenticationCacheAction);
    more->addAction(ui->clearClientDataAction);
    more->addAction(ui->exitAction);
    ui->preferencesButton->setMenu(more);
    ui->exitAction->setShortcut(QKeySequence::Quit);
    ui->preferencesAction->setShortcut(QKeySequence::Preferences);
    addAction(ui->exitAction);
    addAction(ui->preferencesAction);
#ifndef Q_OS_MACOS
    ui->menubar->hide();
#endif


    setWindowIcon(QIcon(QPixmap(":/resource/icon.svg").scaled(
        512, 512, Qt::KeepAspectRatio, Qt::SmoothTransformation
    )));

    ui->applicationNameLabel->setText(QApplication::applicationDisplayName());

    updateVersionInfo();
    updateConnectionState(connectionSession->state());

    connect(connectionSession, &ConnectionSession::stateChanged, this,
            &MainWindow::updateConnectionState);
    connect(connectionSession, &ConnectionSession::progressChanged, this, [this] { updateConnectionState(connectionSession->state()); });


    // 文件-退出
    connect(ui->exitAction, &QAction::triggered, this, &MainWindow::gracefullyQuit);

    connect(ui->preferencesAction,&QAction::triggered,this,&MainWindow::showApplicationPreferences);

    // 文件-设置
    connect(ui->settingAction, &QAction::triggered, this,
            [&]()
            {
                if (connectionSession->isActive()) {QMessageBox::warning(this,tr("Profile is in use"),tr("Disconnect before editing this profile."));return;}
                if (settingWindow) {settingWindow->raise();settingWindow->activateWindow();return;}
                if (guideWindow) {guideWindow->raise();guideWindow->activateWindow();return;}
                if (connectionUiController->isConfigurationSaving()) {QMessageBox::information(this,tr("Saving profile"),tr("Wait for the save to finish."));return;}
                connectionUiController->cancelPendingCredentials();
                settingWindow = new SettingWindow(this,coordinator->credentials(),coordinator->credentialSource(),true);
                settingWindow->setWindowTitle(tr("Edit profile · %1").arg(ui->profileMenuButton->text()));
                settingWindow->show();
            });

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

    // 文件-清除系统代理
    ui->disableProxyAction->setEnabled(false);
    connect(ui->disableProxyAction, &QAction::triggered,
            [&]()
            {
                QMessageBox messageBox(this);
                messageBox.setWindowTitle(tr("Clear system proxy"));
                messageBox.setText(tr("Clear the system proxy owned by JustConnect?"));

                messageBox.addButton(QMessageBox::Yes)->setText(tr("Yes"));
                messageBox.addButton(QMessageBox::No)->setText(tr("No"));
                messageBox.setDefaultButton(QMessageBox::Yes);

                if (messageBox.exec() == QMessageBox::No)
                {
                    return;
                }

                if (systemProxySession->isBusy() || !systemProxySession->needsCleanup()) return;
                connect(systemProxySession, &SystemProxySession::operationFinished, this,
                        [this](bool enabled, const PlatformOperationResult &result)
                        {
                            if (result.succeeded() && !enabled)
                            {
                                qInfo().noquote() << tr("System proxy cleared");
                            }
                        },
                        Qt::SingleShotConnection);
                systemProxySession->disable();
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
            tr("Delete this profile's legacy cache and its quarantined copy in secure storage? This unbound data is not used for login. Current account caches, passwords, TOTP and other profiles are preserved."),
            QMessageBox::Yes|QMessageBox::No,this);
        confirm.setDefaultButton(QMessageBox::No);
        if (confirm.exec()!=QMessageBox::Yes) return;
        coordinator->credentials()->clearLegacyCache(source).then(this,[this](const CredentialResult &result) {
            if (!result.succeeded()) QMessageBox::warning(this,tr("Legacy data cleanup incomplete"),PresentationHelpers::credentialOperationMessage(result.status));
            else qInfo().noquote()<<tr("Legacy data cleared for the current profile");
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
                PresentationHelpers::showAboutDialog(this);
            });

    // 复制日志
    connect(ui->copyLogPushButton, &QPushButton::clicked,
            [&]()
            {
                auto logText = ui->logPlainTextEdit->toPlainText();
                QApplication::clipboard()->setText(logText);
            }
    );

    // 清空日志
    connect(ui->clearLogPushButton, &QPushButton::clicked,
            [&]()
            {
                ui->logPlainTextEdit->clear();
            }
    );

    clearLog();
    connectionUiController = new ConnectionUiController(
        this,
        ui->connectButton,
        ui->proxyButton,
        trayConnectAction,
        connectionSession,
        systemProxySession,
        coordinator->networkPolicy(),
        authenticationDialogs,
        applicationLogger,
        coordinator->credentials(),
        [this]() { return profileService->settings(); },
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

    if (!profileService->silentStartEnabled() || !QSystemTrayIcon::isSystemTrayAvailable())
    {
        show();
        if (isFirstLaunch)
        {
            QTimer::singleShot(
                0,
                this,
                &MainWindow::promptFirstLaunchGuide
            );
        }
    }
}

void MainWindow::changeEvent(QEvent *event)
{
    QMainWindow::changeEvent(event);
    if (event->type()!=QEvent::LanguageChange || !viewsInitialized) return;
    ui->retranslateUi(this);
    newProfileAction->setText(tr("New profile"));renameProfileAction->setText(tr("Rename profile"));deleteProfileAction->setText(tr("Delete profile"));
    trayProfileMenu->setTitle(tr("Profiles"));trayShowAction->setText(tr("Show window"));
    trayCloseAction->setText(tr("Exit %1").arg(QApplication::applicationName()));
    connectionUiController->refreshActions();refreshProfileMenu();updateVersionInfo();updateConnectionState(connectionSession->state());updateDiagnostics();
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
    if (!ProfileManager().closeToTray()) { gracefullyQuit();return; }
    if (trayIcon && trayIcon->isVisible() && QSystemTrayIcon::isSystemTrayAvailable()) {
        hide();
        showNotification("JustConnect", tr("JustConnect is running in the system tray. Click its icon to restore the window; use Exit to quit."), QSystemTrayIcon::Information);
    } else {
        PresentationHelpers::activateWindow(this);
        setProperty("trayUnavailable",true);
        ui->statusHintLabel->setText(tr("System tray unavailable. Use Exit in Settings to quit."));
        ui->statusHintLabel->show();
    }
}


void MainWindow::showApplicationPreferences()
{
    if (auto *existing=findChild<ApplicationPreferencesDialog *>()) {existing->show();existing->raise();existing->activateWindow();return;}
    (new ApplicationPreferencesDialog(this))->show();
}

void MainWindow::clearLog()
{
    ui->logPlainTextEdit->clear();
    ui->logPlainTextEdit->appendPlainText(tr("Welcome to %1\nVersion: %2\nSystem: %3\nProfile: %4\nConfiguration: %5\n")
        .arg(QApplication::applicationDisplayName(),QApplication::applicationVersion(),QSysInfo::prettyProductName(),
            currentProfileId.isEmpty()?tr("Default"):currentProfileId,settings->fileName()));
}

void MainWindow::resetConnectionUi()
{
    if (connectionUiController) connectionUiController->cancelPendingCredentials();
    if (connectionUiController) connectionUiController->refreshActions();
    ui->proxyButton->hide();
    updateConnectionState(ConnectionState::Disconnected);
    updateProfileSummary();
}

void MainWindow::updateConnectionState(ConnectionState state)
{
    QString propertyValue;
    QString title;
    QString detail;

    switch (state)
    {
    case ConnectionState::Disconnected:
        propertyValue = "disconnected";
        title = tr("Not connected");
        detail = tr("Connect to access campus resources.");
        break;
    case ConnectionState::Starting:
        propertyValue = "starting";
        switch (connectionSession->phase()) {
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
        propertyValue = connectionSession->phase() == ConnectionPhase::CampusReady ? "connected" : "starting";
        title = connectionSession->phase() == ConnectionPhase::CampusReady ? tr("Connected")
            : connectionSession->phase() == ConnectionPhase::NetworkRestoring ? tr("Restoring network") : tr("Tunnel ready");
        detail = connectionSession->phase() == ConnectionPhase::CampusReady ? tr("Campus IPv4 access is ready.")
            : connectionSession->phase() == ConnectionPhase::NetworkRestoring ? tr("Campus access is paused until network recovery is confirmed.")
            : systemProxySession->needsCleanup() && !systemProxySession->isEnabled()
            ? tr("System proxy state is unconfirmed. Check remaining settings.")
            : systemProxySession->isEnabled()
            ? tr("Tunnel and system proxy are available; campus access is not ready yet.")
            : tr("Tunnel and local proxy are available; campus access is not ready yet.");
        break;
    case ConnectionState::Stopping:
        propertyValue = connectionSession->networkRecoveryFailed() ? "failed" : "stopping";
        title = connectionSession->networkRecoveryFailed() ? tr("Recovery incomplete") : tr("Disconnecting");
        detail = connectionSession->networkRecoveryFailed() ? tr("Select Retry recovery to finish restoring your network.") : tr("Safely closing this connection.");
        break;
    case ConnectionState::Reconnecting:
        propertyValue = "reconnecting";
        title = tr("Reconnecting");
        detail = tr("Reconnect %1/%2 is waiting for its next attempt.").arg(connectionSession->reconnectAttempt()).arg(ConnectionSessionState::MaxReconnectAttempts);
        break;
    case ConnectionState::Interrupted:
        propertyValue = "failed";
        title = tr("Connection interrupted");
        detail = tr("The core stopped unexpectedly. See Details for the log.");
        break;
    case ConnectionState::Failed:
        propertyValue = "failed";
        if(connectionSession->phase()==ConnectionPhase::NetworkRestoring){
            title=tr("Disconnected");
            detail=tr("Network recovery is confirmed. See Details for the earlier error.");
        }else{
            title = connectionSession->phase()==ConnectionPhase::ReauthenticationRequired ? tr("Sign in again") : tr("Connection failed");
            detail = tr("Check your network and account settings. See Details for the log.");
        }
        break;
    }

    const bool needsAttention=state==ConnectionState::Failed || state==ConnectionState::Interrupted || connectionSession->networkRecoveryFailed();
    const bool noTray=property("trayUnavailable").toBool();
    ui->statusHintLabel->setText(noTray ? tr("System tray unavailable. Use Exit in Settings to quit.") : needsAttention ? detail : QString());
    ui->statusHintLabel->setVisible(noTray || needsAttention);
    const QMap<QString,QString> results{{"running",tr("In progress")},{"succeeded",tr("Succeeded")},{"failed",tr("Failed")},{"required",tr("Sign in again")},{"disabled",tr("Disabled")},{"unavailable",tr("Unavailable")}};
    const auto traffic=connectionSession->observation("traffic");
    const auto mode=connectionSession->keepAliveOptions().mode;
    const QList<QPair<QString,QString>> maintenance{{"renewal",tr("Session renewal")},
        {"traffic",mode=="target" ? tr("Traffic keepalive (HTTP GET)") : mode=="off" ? tr("Traffic keepalive") : tr("Traffic keepalive (campus DNS)")},
        {"nodes",tr("Node maintenance")},{"tunnel",tr("Tunnel maintenance")}};
    for (const auto &[stage,label]:maintenance) {
        const auto observed=connectionSession->observation(stage);
        detail += tr("\nLast %1: %2").arg(label,results.value(observed.result,tr("Unknown")));
        if (observed.observedAt.isValid()) detail += " · "+observed.observedAt.toLocalTime().toString(Qt::ISODate);
    }
    if (traffic.result=="unavailable") detail += tr("\nNo authorized probe resource or campus DNS is available. Check the target and gateway authorization.");
    ui->statusTitleLabel->setText(title);
    if (trayIcon) {
        trayIcon->setToolTip(QApplication::applicationName()+" · "+title+"\n"+detail);
        trayIcon->setIcon(style()->standardIcon(connectionSession->phase()==ConnectionPhase::CampusReady && state==ConnectionState::Running ? QStyle::SP_MediaPlay : QStyle::SP_MediaStop));
    }
    ui->statusDetailLabel->setText(detail);

    const QList<QWidget *> styledWidgets{
        ui->statusIndicator,
        ui->connectButton
    };
    for (QWidget *widget : styledWidgets)
    {
        if (widget->property("connectionState").toString()==propertyValue) continue;
        widget->setProperty("connectionState", propertyValue);
        widget->style()->unpolish(widget);
        widget->style()->polish(widget);
        widget->update();
    }
}

void MainWindow::updateProfileSummary()
{
    const QString profileName = currentProfileId.isEmpty()
        ? tr("Default")
        : currentProfileId;
    const QString protocol = "aTrust · " + settings->value("JustConnect/ProfileKind","Custom").toString();
    const QString server = settings->value(
        "JustConnect/ServerAddress"
    ).toString().trimmed();

    QStringList details{protocol};
    details.append(server.isEmpty() ? tr("No server configured") : server);

    ui->profileMenuButton->setText(profileName);
    ui->profileMenuButton->setToolTip(profileName+"\n"+server);
    ui->profileDetailLabel->setText(details.join(QStringLiteral(" · ")));
}

void MainWindow::setupTrayIcon()
{
    // 系统托盘
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setIcon(
        QIcon(QPixmap(":/resource/icon.svg").scaled(512, 512, Qt::KeepAspectRatio, Qt::SmoothTransformation)));
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
    trayProfileMenu = new QMenu(tr("Profiles"), this);
    trayShowAction = new QAction(tr("Show window"), this);trayShowAction->setObjectName("trayShowAction");
    trayCloseAction = new QAction(tr("Exit ") + QApplication::applicationName(), this);
    trayMenu = new QMenu(this);
    trayMenu->addAction(trayConnectAction);
    trayMenu->addSeparator();
    trayMenu->addMenu(trayProfileMenu);
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

void MainWindow::setupProfileMenu()
{
    // 务必在 setupTrayIcon 之后调用，以确保 trayProfileMenu 已正确初始化
    switchGroup = new QActionGroup(ui->profileMenu);
    traySwitchGroup = new QActionGroup(trayProfileMenu);
    switchGroup->setExclusive(true);
    traySwitchGroup->setExclusive(true);
    ui->profileMenu->insertAction(ui->configurationGuideAction,ui->settingAction);
    ui->profileMenu->addSeparator();
    newProfileAction = ui->profileMenu->addAction(tr("New profile"));
    renameProfileAction = ui->profileMenu->addAction(tr("Rename profile"));
    deleteProfileAction = ui->profileMenu->addAction(tr("Delete profile"));
    ui->profileMenu->addSeparator();

    connect(
        ui->configurationGuideAction,
        &QAction::triggered,
        this,
        &MainWindow::openConfigurationGuide
    );
    connect(newProfileAction, &QAction::triggered, this, &MainWindow::createProfile);
    newProfileAction->setObjectName("newProfileAction");
    ui->profileMenuButton->setMenu(ui->profileMenu);
    connect(renameProfileAction, &QAction::triggered, this, &MainWindow::renameCurrentProfile);
    connect(deleteProfileAction, &QAction::triggered, this, &MainWindow::deleteCurrentProfile);

    refreshProfileMenu();
}

void MainWindow::refreshProfileMenu()
{
    qDeleteAll(switchGroup->actions());

    if (trayProfileMenu != nullptr)
    {
        trayProfileMenu->clear();
    }

    QAction *action = ui->profileMenu->addAction(tr("Default"));
    action->setCheckable(true);
    action->setChecked(currentProfileId.isEmpty());
    switchGroup->addAction(action);
    connect(action, &QAction::triggered, this, [this]()
    {
        switchProfile("");
    });
    if (trayProfileMenu != nullptr)
    {
        QAction *trayAction = trayProfileMenu->addAction(tr("Default"));
        trayAction->setCheckable(true);
        trayAction->setChecked(currentProfileId.isEmpty());
        traySwitchGroup->addAction(trayAction);
        connect(trayAction, &QAction::triggered, this, [this]()
        {
            switchProfile("");
        });
    }

    for (const QString &profileId : profileService->profiles())
    {
        QAction *action = ui->profileMenu->addAction(profileId);
        action->setCheckable(true);
        action->setChecked(
            !profileService->usesOverrideConfiguration()
            && profileId == currentProfileId
        );
        switchGroup->addAction(action);
        connect(action, &QAction::triggered, this, [this, profileId]()
        {
            switchProfile(profileId);
        });

        if (trayProfileMenu != nullptr)
        {
            QAction *trayAction = trayProfileMenu->addAction(profileId);
            trayAction->setCheckable(true);
            trayAction->setChecked(
                !profileService->usesOverrideConfiguration()
                && profileId == currentProfileId
            );
            traySwitchGroup->addAction(trayAction);
            connect(trayAction, &QAction::triggered, this, [this, profileId]()
            {
                switchProfile(profileId);
            });
        }
    }

    const bool currentProfileIsManaged =
        !currentProfileId.isEmpty()
        && !profileService->usesOverrideConfiguration();
    renameProfileAction->setEnabled(currentProfileIsManaged);
    deleteProfileAction->setEnabled(currentProfileIsManaged);
}

bool MainWindow::switchProfile(const QString &profileId)
{
    if (!profileService->usesOverrideConfiguration()
        && profileId == currentProfileId)
    {
        return true;
    }

    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, tr("Could not switch profile"), tr("Disconnect before switching profiles."));
        refreshProfileMenu();
        return false;
    }

    if (connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving()) || (guideWindow && guideWindow->isSaving())) {
        QMessageBox::information(this,tr("Saving profile"),tr("Wait for the save before switching profiles."));refreshProfileMenu();return false;
    }
    if (guideWindow) guideWindow->close();
    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    if (!profileService->switchTo(profileId))
    {
        QMessageBox::warning(this,tr("Could not switch profile"),tr("Could not save the current profile or read the selected profile. Check file permissions and contents. Your selection is unchanged."));
        refreshProfileMenu();
        return false;
    }
    settings = profileService->settings();
    currentProfileId = profileService->currentProfileId();

    upgradeSettings();
    updateVersionInfo();
    resetConnectionUi();
    clearLog();
    refreshProfileMenu();

    qInfo().noquote() << tr("Switched profile: ") + currentProfileId;
    return true;
}

void MainWindow::createProfile()
{
    if (connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving()) || (guideWindow && guideWindow->isSaving())) {
        QMessageBox::information(this,tr("Saving profile"),tr("Wait for the save before creating a profile."));return;
    }
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, tr("Could not create profile"), tr("Disconnect before creating a profile."));
        return;
    }

    bool ok = false;
    const QString name = QInputDialog::getText(
        this,
        tr("New profile"),
        tr("Profile name:\nUse letters, numbers, underscores or hyphens."),
        QLineEdit::Normal,
        "",
        &ok
    );
    if (!ok)
    {
        return;
    }

    if (guideWindow) guideWindow->close();
    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    const QString newProfileId = profileService->createAndSwitch(name);
    if (newProfileId.isEmpty())
    {
        QMessageBox::critical(this, tr("Could not create profile"), tr("The new profile could not be created."));
        return;
    }

    settings = profileService->settings();
    currentProfileId = profileService->currentProfileId();
    upgradeSettings();
    resetConnectionUi();
    updateVersionInfo();
    clearLog();
    refreshProfileMenu();

    openConfigurationGuide();
}

void MainWindow::openConfigurationGuide()
{
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(
            this,
            tr("Profile is in use"),
            tr("Disconnect before using the setup guide.")
        );
        return;
    }

    if (connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving())) {QMessageBox::information(this,tr("Saving profile"),tr("Wait for the save to finish."));return;}

    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    if (guideWindow && guideWindow->isVisible()) {guideWindow->raise();guideWindow->activateWindow();return;}
    connectionUiController->cancelPendingCredentials();
    const auto path=settings->fileName();
    guideWindow=new ConfigurationGuideDialog(this,coordinator->credentials(),coordinator->credentialSource());
    guideWindow->setAttribute(Qt::WA_DeleteOnClose);
    connect(guideWindow,&QDialog::accepted,this,[this,path] {
        if (settings->fileName()!=path) return;
        resetConnectionUi();clearLog();qInfo().noquote()<<tr("Current profile updated with the setup guide");
    });
    connect(guideWindow,&ConfigurationGuideDialog::connectRequested,this,[this,path] {
        if (profileService->settings()->fileName()==path) connectionUiController->enableCampusAccess();
    },Qt::QueuedConnection);
    guideWindow->show();
}

void MainWindow::promptFirstLaunchGuide()
{
    promptConfigurationGuide(
        tr("Welcome to JustConnect"),
        tr("Set up your VPN server now?")
    );
}

void MainWindow::promptConfigurationGuide(
    const QString &windowTitle,
    const QString &text
)
{
    QMessageBox messageBox(this);
    messageBox.setWindowTitle(windowTitle);
    messageBox.setText(text);
    messageBox.setInformativeText(
        tr("The guide helps you choose a server, sign-in method and credentials.")
    );

    QPushButton *startButton = messageBox.addButton(
        tr("Set up"),
        QMessageBox::AcceptRole
    );
    messageBox.addButton(tr("Later"), QMessageBox::RejectRole);
    messageBox.setDefaultButton(startButton);
    messageBox.exec();

    if (messageBox.clickedButton() == startButton)
    {
        openConfigurationGuide();
    }
}

void MainWindow::renameCurrentProfile()
{
    if (coordinator->credentials()->isBusy(settings->fileName()) || connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving()) || (guideWindow && guideWindow->isSaving())) {
        QMessageBox::information(this,tr("Secure storage is busy"),tr("Wait for the current operation before renaming."));return;
    }
    bool ok = false;
    QString name = QInputDialog::getText(this, tr("Rename profile"), tr("New profile name:\nUse letters, numbers or underscores."), QLineEdit::Normal, currentProfileId, &ok);
    if (!ok)
    {
        return;
    }

    const QString normalizedName = profileService->normalizeProfileId(name);
    if (normalizedName.isEmpty())
    {
        QMessageBox::warning(this, tr("Could not rename profile"), tr("The profile name cannot be empty."));
        return;
    }
    if (normalizedName == currentProfileId)
    {
        return;
    }
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, tr("Could not rename profile"), tr("Disconnect before renaming a profile."));
        return;
    }

    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }
    if (guideWindow) guideWindow->close();
    connectionUiController->cancelPendingCredentials();
    const auto source=coordinator->credentialSource();
    coordinator->credentials()->migrate(source).then(this,[this,source,normalizedName](const CredentialResult &result) {
        if (!CredentialAccess::matches(source,*settings)) return;
        if (!result.succeeded()) {QMessageBox::warning(this,tr("Rename incomplete"),PresentationHelpers::credentialOperationMessage(result.status)+tr("\nComplete the legacy credential migration first, or create a new profile."));return;}
        if (!profileService->renameCurrent(normalizedName)) {QMessageBox::warning(this,tr("Could not rename profile"),tr("The destination exists or this profile cannot be renamed."));return;}
        currentProfileId=profileService->currentProfileId();settings=profileService->settings();
        updateVersionInfo();refreshProfileMenu();clearLog();qInfo().noquote()<<tr("Profile renamed to: ")+currentProfileId;
    });
}

void MainWindow::deleteCurrentProfile()
{
    if (profileService->usesOverrideConfiguration()) {QMessageBox::warning(this,tr("Could not delete profile"),tr("External profiles cannot be deleted here."));return;}
    if (coordinator->credentials()->isBusy(settings->fileName()) || connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving()) || (guideWindow && guideWindow->isSaving())) {
        QMessageBox::information(this,tr("Secure storage is busy"),tr("Wait for the current operation before deleting a profile."));return;
    }
    if (currentProfileId.isEmpty())
    {
        QMessageBox::warning(this, tr("Could not delete profile"), tr("The default profile cannot be deleted."));
        return;
    }

    QMessageBox messageBox(this);
    messageBox.setWindowTitle(tr("Delete profile"));
    messageBox.setInformativeText(tr("The profile file and legacy cache will be deleted. Passwords, TOTP, account caches and quarantined copies in secure storage are preserved. To remove them, first clear passwords and TOTP in profile settings, then clear account and legacy caches from Settings."));
    messageBox.setText(tr("Delete profile \"%1\"?").arg(currentProfileId));
    messageBox.addButton(QMessageBox::Yes)->setText(tr("Yes"));
    messageBox.addButton(QMessageBox::No)->setText(tr("No"));
    messageBox.setDefaultButton(QMessageBox::No);
    if (messageBox.exec() != QMessageBox::Yes)
    {
        return;
    }

    const QString removedProfileId = currentProfileId;
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, tr("Could not delete profile"), tr("Disconnect before deleting a profile."));
        return;
    }
    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }
    if (guideWindow) guideWindow->close();
    connectionUiController->cancelPendingCredentials();
    const auto legacy=coordinator->credentialSource().legacyCachePath;
    if (!legacy.isEmpty() && QFileInfo::exists(legacy) && !QFile::remove(legacy)) {
        QMessageBox::warning(this,tr("Delete incomplete"),tr("The legacy cache could not be removed, so the profile was preserved. Check access permissions and retry."));return;
    }
    if (!profileService->removeCurrentAndSwitchToDefault())
    {
        QMessageBox::warning(this, tr("Could not delete profile"), tr("The profile file could not be deleted."));
        return;
    }

    currentProfileId = profileService->currentProfileId();
    settings = profileService->settings();
    upgradeSettings();
    updateVersionInfo();
    resetConnectionUi();
    clearLog();
    refreshProfileMenu();
    qInfo().noquote() << tr("Deleted profile: ") + removedProfileId;
}

void MainWindow::upgradeSettings()
{
    const SettingsMigrationAction action = SettingsMigrator::prepare(*settings);
    if (action == SettingsMigrationAction::MigrateAutoStart)
    {
        if (!profileService->migrateAutoStartSetting(settings->value("Common/AutoStart", false).toBool())) {
            QMessageBox::warning(this, tr("Startup preference migration failed"), tr("The previous startup preference could not be saved. The old configuration is preserved for retry."));
            return;
        }
    }
    if (action == SettingsMigrationAction::Failed || !SettingsMigrator::finish(*settings))
    {
        QMessageBox::warning(this, tr("Profile migration incomplete"), tr("The upgraded profile could not be saved. The old version is preserved for retry."));
    }
}

void MainWindow::updateVersionInfo()
{
    const VersionInfo &versionInfo = updateChecker->versionInfo();
    ui->versionLabel->setText(tr("Version %1").arg(versionInfo.uiVersion));
    QString latest;
    switch(versionInfo.updateState){
    case VersionInfo::UpdateState::Checking:latest=tr("Checking…");break;
    case VersionInfo::UpdateState::Disabled:latest=tr("Disabled");break;
    case VersionInfo::UpdateState::Failed:latest=tr("Check failed");break;
    case VersionInfo::UpdateState::Ready:latest=versionInfo.uiLatest;break;
    }
    ui->versionLabel->setToolTip(tr("Application: %1 (latest: %2)\nCore: %3")
        .arg(versionInfo.uiVersion,latest,versionInfo.coreVersion.isEmpty() ? tr("Unavailable") : versionInfo.coreVersion));
    updateProfileSummary();
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
    const auto report = coordinator->diagnostics()->report();
    if (ui->diagnosticReport->toPlainText() != report) ui->diagnosticReport->setPlainText(report);
    auto *policy = coordinator->networkPolicy();
    ui->refreshDiagnosticsButton->setEnabled(!policy->currentGeneration().isEmpty() && !policy->isBusy());
}
