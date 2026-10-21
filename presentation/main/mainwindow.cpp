#include <QMessageBox>
#include <QSysInfo>
#include <QNetworkInterface>
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
#include <QStyleHints>
#include <QTimer>

#include "mainwindow.h"

#include "application/applicationlogger.h"
#include "application/applicationconstants.h"
#include "application/commandlineoptions.h"
#include "application/settingsmigrator.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/update/updatechecker.h"
#include "presentation/coordinators/connectionuicontroller.h"
#include "presentation/dialogs/configurationguidedialog/configurationguidedialog.h"
#include "presentation/presentationhelpers.h"
#include "ui_mainwindow.h"

namespace
{
bool appendStyleSheet(const QString &path, QString &styleSheet)
{
    QFile styleFile(path);
    if (!styleFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qWarning().noquote() << "无法加载样式资源：" << path;
        return false;
    }

    styleSheet.append(QString::fromUtf8(styleFile.readAll()));
    styleSheet.append('\n');
    return true;
}
}

MainWindow::MainWindow(
    ApplicationLogger *logger,
    ApplicationLogFile *logFile,
    QWidget *parent
) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    applicationLogger(logger),
    applicationLogFile(logFile)
{
    const QString overrideConfigPath =
        CommandLineOptions::value(QCoreApplication::arguments(), "--config-path");
    coordinator = new MainWindowCoordinator(this, overrideConfigPath, this);
    profileService = coordinator->profiles();
    currentProfileId = profileService->currentProfileId();
    settings = profileService->settings();

    const bool isFirstLaunch =
        !settings->contains("Common/ConfigVersion");
    upgradeSettings();

    ui->setupUi(this);
#ifdef Q_OS_MACOS
    const QMargins centralMargins = ui->centralWidget->contentsMargins();
    ui->centralWidget->setContentsMargins(centralMargins.left(), 12, centralMargins.right(), centralMargins.bottom());
#endif
    ui->logPlainTextEdit->setFont(
        QFontDatabase::systemFont(QFontDatabase::FixedFont)
    );
    QStyleHints *styleHints = QGuiApplication::styleHints();
    applyColorScheme(styleHints->colorScheme());
    connect(styleHints, &QStyleHints::colorSchemeChanged,
            this, &MainWindow::applyColorScheme);
    authenticationDialogs = coordinator->authenticationDialogs();
    connectionSession = coordinator->connection();
    systemProxySession = coordinator->systemProxy();
    updateChecker = coordinator->updates();
    connect(coordinator->credentials(),&CredentialAccess::configurationSaved,this,[this](const QString &path) {
        if (settings && settings->fileName()==path) updateProfileSummary();
    });
    connect(updateChecker, &UpdateChecker::versionInfoChanged, this,
            [this](const VersionInfo &) { updateVersionInfo(); });
    connect(updateChecker, &UpdateChecker::checkFailed, this,
            [this](const QString &) {
                ui->versionLabel->setToolTip(ui->versionLabel->toolTip() + "\n检查更新失败");
            });
    connect(updateChecker, &UpdateChecker::uiUpdateAvailable, this,
            [this](const QString &latestVersion)
            {
                QMessageBox msgBox(this);
                msgBox.setText("UI 版本更新");
                msgBox.setInformativeText(
                    "存在 UI 版本更新：" + latestVersion + "\n是否前往 Github 发布页面查看？"
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
                ui->pushButton2->setEnabled(!busy);
                ui->disableProxyAction->setEnabled(!busy && systemProxySession->needsCleanup());
            });
    connect(systemProxySession, &SystemProxySession::enabledChanged, this,
            [this](bool enabled)
            {
                ui->disableProxyAction->setEnabled(!systemProxySession->isBusy() && systemProxySession->needsCleanup());
                ui->pushButton2->setText(systemProxySession->needsCleanup() ? "清除系统代理" : "设置系统代理");
                if (!systemProxySession->needsCleanup() && connectionSession != nullptr && !connectionSession->isActive())
                {
                    ui->pushButton2->hide();
                }
                updateProfileSummary();
                updateConnectionState(connectionSession->state());
            });
    connect(systemProxySession, &SystemProxySession::operationFinished, this,
        [this](bool, const PlatformOperationResult &result) {
            if (!result.succeeded()) QMessageBox::warning(this, "系统代理操作未完成",
                PresentationHelpers::platformOperationMessage(result));
        });
    setupTrayIcon();
    setupProfileMenu();

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

    // 文件-设置
    connect(ui->settingAction, &QAction::triggered, this,
            [&]()
            {
                if (connectionSession->isActive()) {QMessageBox::warning(this,"无法修改配置","请先断开连接，再修改学校配置。");return;}
                if (settingWindow) {settingWindow->raise();settingWindow->activateWindow();return;}
                if (guideWindow) {guideWindow->raise();guideWindow->activateWindow();return;}
                if (connectionUiController->isConfigurationSaving()) {QMessageBox::information(this,"正在保存配置","请等待保存完成。");return;}
                connectionUiController->cancelPendingCredentials();
                settingWindow = new SettingWindow(this,coordinator->credentials(),coordinator->credentialSource());
                settingWindow->show();
            });

    connect(ui->settingPushButton, &QPushButton::clicked,
            ui->settingAction, &QAction::trigger);
    connect(ui->guidePushButton, &QPushButton::clicked,
            ui->configurationGuideAction, &QAction::trigger);
    connect(ui->openLogPushButton, &QPushButton::clicked,
            ui->openLogAction, &QAction::trigger);

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
                    QMessageBox::warning(this, "日志文件", "日志文件创建失败。");
                }
            });

    // 文件-清除系统代理
    ui->disableProxyAction->setEnabled(false);
    connect(ui->disableProxyAction, &QAction::triggered,
            [&]()
            {
                QMessageBox messageBox(this);
                messageBox.setWindowTitle("清理系统代理");
                messageBox.setText("是否清理系统代理？");

                messageBox.addButton(QMessageBox::Yes)->setText("是");
                messageBox.addButton(QMessageBox::No)->setText("否");
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
                                qInfo().noquote() << "已清理系统代理设置";
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
            QMessageBox::information(this,"安全存储操作进行中","请等待操作完成后再清理旧版缓存。");return;
        }
        const auto source=coordinator->credentialSource();
        QMessageBox confirm(QMessageBox::Question,"清理旧版缓存",
            "删除当前配置的旧版缓存文件及其系统凭据库隔离副本？这些材料未绑定账户，不用于登录。当前账户认证缓存、密码、TOTP 和其他配置保持不变。",
            QMessageBox::Yes|QMessageBox::No,this);
        confirm.setDefaultButton(QMessageBox::No);
        if (confirm.exec()!=QMessageBox::Yes) return;
        coordinator->credentials()->clearLegacyCache(source).then(this,[this](const CredentialResult &result) {
            if (!result.succeeded()) QMessageBox::warning(this,"旧版缓存清理未完成",PresentationHelpers::credentialOperationMessage(result.status));
            else qInfo().noquote()<<"已清理当前配置的旧版缓存";
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
        ui->pushButton1,
        ui->pushButton2,
        trayConnectAction,
        connectionSession,
        systemProxySession,
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
        QApplication::quit();
    });
    connect(connectionUiController,&ConnectionUiController::quitFailed,this,[this](const QString &code) {
        qWarning() << code << "core_active" << connectionSession->isActive()
            << "proxy_busy" << systemProxySession->isBusy() << "proxy_unrestored" << systemProxySession->needsCleanup()
            << "credential_work" << coordinator->credentials()->isBusy();
        show();raise();activateWindow();
        auto *message=new QMessageBox(QMessageBox::Warning,"退出未完成",
            "清理失败或超时。已停止重连及新连接；请检查代理残留，完成清理后重试退出或重启系统。程序将保留事件循环，不强制销毁仍在运行的核心或存储线程。",
            QMessageBox::Retry|QMessageBox::Cancel,this);
        message->setAttribute(Qt::WA_DeleteOnClose);
        connect(message,&QMessageBox::finished,this,[this](int result){if(result==QMessageBox::Retry) gracefullyQuit();});
        message->open();
    });

    bool shouldConnect =
        settings->value("Common/ConnectAfterStart", false).toBool();
    if (qApp->arguments().contains("--connect"))
    {
        shouldConnect = true;
    }
    if (shouldConnect)
    {
        ui->pushButton1->click();
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
    if (trayIcon && trayIcon->isVisible() && QSystemTrayIcon::isSystemTrayAvailable()) {
        hide();
        showNotification("JustConnect", "程序继续在系统托盘运行，单击图标可恢复窗口；退出请使用菜单。", QSystemTrayIcon::Information);
    } else {
        show();
        ui->statusDetailLabel->setText("系统托盘不可用，已保留窗口。退出请使用文件菜单中的退出。");
    }
}


void MainWindow::clearLog()
{
    ui->logPlainTextEdit->clear();
    ui->logPlainTextEdit->appendPlainText(
        "欢迎使用 " + QApplication::applicationDisplayName() + "\n"
        "当前版本：" + QApplication::applicationVersion() + "\n"
        "系统版本：" + QSysInfo::prettyProductName() + "\n"
        "当前配置：" + (currentProfileId.isEmpty() ? "默认" : currentProfileId) + "\n"
        "配置路径：" + settings->fileName() + "\n");
}

void MainWindow::resetConnectionUi()
{
    if (connectionUiController) connectionUiController->cancelPendingCredentials();
    ui->pushButton1->setText("连接服务器");
    trayConnectAction->setText("连接服务器");
    ui->pushButton2->setText("设置系统代理");
    ui->pushButton2->hide();
    updateConnectionState(ConnectionState::Disconnected);
    updateProfileSummary();
}

void MainWindow::applyColorScheme(Qt::ColorScheme scheme)
{
    const QString themePath = scheme == Qt::ColorScheme::Dark
        ? QStringLiteral(":/resource/mainwindow-dark.qss")
        : QStringLiteral(":/resource/mainwindow-light.qss");

    QString styleSheet;
    if (!appendStyleSheet(QStringLiteral(":/resource/mainwindow.qss"), styleSheet)
        || !appendStyleSheet(themePath, styleSheet))
    {
        return;
    }

    setStyleSheet(styleSheet);
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
        title = "尚未连接";
        detail = "连接后即可访问网络资源。";
        break;
    case ConnectionState::Starting:
        propertyValue = "starting";
        switch (connectionSession->phase()) {
        case ConnectionPhase::Initializing: title="正在初始化核心库";break;
        case ConnectionPhase::Starting: title="正在启动会话";break;
        case ConnectionPhase::Restoring: title="正在恢复认证";break;
        case ConnectionPhase::Authenticating: title="等待认证";break;
        case ConnectionPhase::AuthenticationSucceeded: title="认证成功，正在建立通道";break;
        case ConnectionPhase::ReauthenticationRequired: title="需要重新认证";break;
        case ConnectionPhase::TransportReady: title="通道就绪";break;
        }
        detail = "校园访问接管尚未就绪。";
        break;
    case ConnectionState::Running:
        propertyValue = "starting";
        title = "通道就绪";
        detail = systemProxySession->needsCleanup() && !systemProxySession->isEnabled()
            ? "系统代理状态未确认，请检查残留设置。"
            : systemProxySession->isEnabled()
            ? "通道与系统代理已启用；校园访问接管尚未就绪。"
            : "通道与本地代理可用；校园访问接管尚未就绪。";
        break;
    case ConnectionState::Stopping:
        propertyValue = "stopping";
        title = "正在断开";
        detail = "正在安全关闭当前连接。";
        break;
    case ConnectionState::Reconnecting:
        propertyValue = "reconnecting";
        title = "正在重连";
        detail = QString("重连 %1/%2，等待下一次尝试。").arg(connectionSession->reconnectAttempt()).arg(ConnectionSessionState::MaxReconnectAttempts);
        break;
    case ConnectionState::Interrupted:
        propertyValue = "failed";
        title = "连接已断开";
        detail = "VPN 核心意外退出，请查看右侧日志。";
        break;
    case ConnectionState::Failed:
        propertyValue = "failed";
        title = connectionSession->phase()==ConnectionPhase::ReauthenticationRequired ? "需要重新认证" : "连接失败";
        detail = "请查看右侧日志，确认网络与账户配置。";
        break;
    }

    const auto renewal=connectionSession->observation("renewal");
    const QMap<QString,QString> results{{"running","进行中"},{"succeeded","成功"},{"failed","失败"},{"required","需要重新认证"},{"disabled","已关闭"},{"unavailable","不可用"}};
    detail += "\n最近会话续期：" + results.value(renewal.result,"未知");
    if (renewal.observedAt.isValid()) detail += " · " + renewal.observedAt.toLocalTime().toString(Qt::ISODate);
    ui->statusTitleLabel->setText(title);
    if (trayIcon) {
        trayIcon->setToolTip(QApplication::applicationName()+" · "+title+"\n"+detail);
        trayIcon->setIcon(style()->standardIcon(state==ConnectionState::Running ? QStyle::SP_MediaPlay : QStyle::SP_MediaStop));
    }
    ui->statusDetailLabel->setText(detail);

    const QList<QWidget *> styledWidgets{
        ui->statusIndicator,
        ui->pushButton1
    };
    for (QWidget *widget : styledWidgets)
    {
        widget->setProperty("connectionState", propertyValue);
        widget->style()->unpolish(widget);
        widget->style()->polish(widget);
        widget->update();
    }
}

void MainWindow::updateProfileSummary()
{
    const QString profileName = currentProfileId.isEmpty()
        ? QStringLiteral("默认")
        : currentProfileId;
    const QString protocol = "aTrust · " + settings->value("JustConnect/ProfileKind","Custom").toString();
    const QString server = settings->value(
        "JustConnect/ServerAddress"
    ).toString().trimmed();

    QStringList details{protocol};
    details.append(server.isEmpty() ? QStringLiteral("尚未配置服务器") : server);

    ui->profileNameLabel->setText(profileName);
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
            if (isHidden())
            {
                show();
            }
            setWindowState(Qt::WindowState::WindowActive);
            setFocus();
            break;
        }
    });

    trayConnectAction = new QAction("连接服务器", this);
    trayProfileMenu = new QMenu("配置选择", this);
    trayShowAction = new QAction("显示主界面", this);
    trayCloseAction = new QAction("退出 " + QApplication::applicationName(), this);
    trayMenu = new QMenu(this);
    trayMenu->addAction(trayConnectAction);
    trayMenu->addSeparator();
    trayMenu->addMenu(trayProfileMenu);
    trayMenu->addSeparator();
    trayMenu->addAction(trayShowAction);
    trayMenu->addAction(trayCloseAction);
    connect(trayConnectAction, &QAction::triggered, this, [&]() { ui->pushButton1->click(); });
    connect(trayShowAction, &QAction::triggered, this, [&]() {
        show();
        setWindowState(Qt::WindowState::WindowActive);
        setFocus();
    });
    connect(trayCloseAction, &QAction::triggered, this, &MainWindow::gracefullyQuit);
    trayIcon->setContextMenu(trayMenu);
    trayIcon->show();
}

void MainWindow::setupProfileMenu()
{
    // 务必在 setupTrayIcon 之后调用，以确保 trayProfileMenu 已正确初始化
    ui->profileMenu->addSeparator();
    newProfileAction = ui->profileMenu->addAction("新建配置");
    renameProfileAction = ui->profileMenu->addAction("重命名当前配置");
    deleteProfileAction = ui->profileMenu->addAction("删除当前配置");
    ui->profileMenu->addSeparator();

    connect(
        ui->configurationGuideAction,
        &QAction::triggered,
        this,
        &MainWindow::openConfigurationGuide
    );
    connect(newProfileAction, &QAction::triggered, this, &MainWindow::createProfile);
    connect(renameProfileAction, &QAction::triggered, this, &MainWindow::renameCurrentProfile);
    connect(deleteProfileAction, &QAction::triggered, this, &MainWindow::deleteCurrentProfile);

    refreshProfileMenu();
}

void MainWindow::refreshProfileMenu()
{
    const QList<QAction *> actions = ui->profileMenu->actions();
    bool remove = false;
    for (QAction *action : actions)
    {
        if (action == ui->configurationGuideAction
            || action == newProfileAction
            || action == renameProfileAction
            || action == deleteProfileAction)
        {
            continue;
        }
        if (action->isSeparator())
        {
            remove = true;
            continue;
        }
        if (remove)
        {
            ui->profileMenu->removeAction(action);
            delete action;
        }
    }

    QActionGroup *switchGroup = new QActionGroup(ui->profileMenu);
    QActionGroup *traySwitchGroup = nullptr;

    if (trayProfileMenu != nullptr)
    {
        trayProfileMenu->clear();
        traySwitchGroup = new QActionGroup(trayProfileMenu);
        traySwitchGroup->setExclusive(true);
    }

    switchGroup->setExclusive(true);
    QAction *action = ui->profileMenu->addAction("默认");
    action->setCheckable(true);
    action->setChecked(currentProfileId.isEmpty());
    switchGroup->addAction(action);
    connect(action, &QAction::triggered, this, [this]()
    {
        switchProfile("");
    });
    if (trayProfileMenu != nullptr)
    {
        QAction *trayAction = trayProfileMenu->addAction("默认");
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
        QMessageBox::warning(this, "切换失败", "请先断开 VPN 连接，再切换配置。");
        refreshProfileMenu();
        return false;
    }

    if (connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving()) || (guideWindow && guideWindow->isSaving())) {
        QMessageBox::information(this,"正在保存配置","请等待保存完成后再切换。");refreshProfileMenu();return false;
    }
    if (guideWindow) guideWindow->close();
    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    if (!profileService->switchTo(profileId))
    {
        QMessageBox::warning(this,"切换失败","无法保存当前配置或读取目标配置，请检查文件权限及内容后重试。当前选择未改变。");
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

    qInfo().noquote() << "已切换到配置：" + currentProfileId;
    return true;
}

void MainWindow::createProfile()
{
    if (connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving()) || (guideWindow && guideWindow->isSaving())) {
        QMessageBox::information(this,"正在保存配置","请等待保存完成后再创建配置。");return;
    }
    if (guideWindow) guideWindow->close();
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, "新建失败", "请先断开 VPN 连接，再新建配置。");
        return;
    }

    bool ok = false;
    const QString name = QInputDialog::getText(
        this,
        "新建配置",
        "请输入配置名称：\n（仅支持字母、数字、下划线和连字符）",
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

    const QString newProfileId = profileService->createAndSwitch(name);
    if (newProfileId.isEmpty())
    {
        QMessageBox::critical(this, "创建失败", "无法创建新配置。");
        return;
    }

    settings = profileService->settings();
    currentProfileId = profileService->currentProfileId();
    upgradeSettings();
    resetConnectionUi();
    updateVersionInfo();
    clearLog();
    refreshProfileMenu();

    promptConfigurationGuide(
        "配置已创建",
        "配置 \"" + newProfileId + "\" 已创建，是否现在使用配置引导完成设置？"
    );
}

void MainWindow::openConfigurationGuide()
{
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(
            this,
            "无法修改配置",
            "请先断开 VPN 连接，再使用配置引导。"
        );
        return;
    }

    if (connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving())) {QMessageBox::information(this,"正在保存配置","请等待保存完成。");return;}

    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    if (guideWindow) {guideWindow->raise();guideWindow->activateWindow();return;}
    connectionUiController->cancelPendingCredentials();
    const auto path=settings->fileName();
    guideWindow=new ConfigurationGuideDialog(this,coordinator->credentials(),coordinator->credentialSource());
    guideWindow->setAttribute(Qt::WA_DeleteOnClose);
    connect(guideWindow,&QDialog::accepted,this,[this,path] {
        if (settings->fileName()!=path) return;
        resetConnectionUi();clearLog();qInfo().noquote()<<"已通过配置引导更新当前配置";
    });
    guideWindow->show();
}

void MainWindow::promptFirstLaunchGuide()
{
    promptConfigurationGuide(
        "欢迎使用 JustConnect",
        "检测到这是首次启动，是否现在配置 VPN 服务器？"
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
        "配置引导将协助你选择 Fudan／Custom、认证方式和登录凭据。"
    );

    QPushButton *startButton = messageBox.addButton(
        "使用配置引导",
        QMessageBox::AcceptRole
    );
    messageBox.addButton("稍后配置", QMessageBox::RejectRole);
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
        QMessageBox::information(this,"安全存储操作进行中","请等待操作完成后再重命名。");return;
    }
    bool ok = false;
    QString name = QInputDialog::getText(this, "重命名配置", "请输入新配置名称：\n（仅支持字母、数字、下划线）", QLineEdit::Normal, currentProfileId, &ok);
    if (!ok)
    {
        return;
    }

    const QString normalizedName = profileService->normalizeProfileId(name);
    if (normalizedName.isEmpty())
    {
        QMessageBox::warning(this, "重命名失败", "配置名称不能为空。");
        return;
    }
    if (normalizedName == currentProfileId)
    {
        return;
    }
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, "重命名失败", "请先断开 VPN 连接，再重命名配置。");
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
        if (!result.succeeded()) {QMessageBox::warning(this,"重命名未完成",PresentationHelpers::credentialOperationMessage(result.status)+"\n请先完成旧凭据／缓存迁移，或创建新配置。");return;}
        if (!profileService->renameCurrent(normalizedName)) {QMessageBox::warning(this,"重命名失败","目标配置已存在，或当前配置不可重命名。");return;}
        currentProfileId=profileService->currentProfileId();settings=profileService->settings();
        updateVersionInfo();refreshProfileMenu();clearLog();qInfo().noquote()<<"当前配置已重命名为："+currentProfileId;
    });
}

void MainWindow::deleteCurrentProfile()
{
    if (profileService->usesOverrideConfiguration()) {QMessageBox::warning(this,"删除失败","外部配置不能在此删除。");return;}
    if (coordinator->credentials()->isBusy(settings->fileName()) || connectionUiController->isConfigurationSaving() || (settingWindow && settingWindow->isSaving()) || (guideWindow && guideWindow->isSaving())) {
        QMessageBox::information(this,"安全存储操作进行中","请等待操作完成后再删除配置。");return;
    }
    if (currentProfileId.isEmpty())
    {
        QMessageBox::warning(this, "删除失败", "默认配置不可删除。");
        return;
    }

    QMessageBox messageBox(this);
    messageBox.setWindowTitle("删除配置");
    messageBox.setInformativeText("将删除配置文件及其旧版缓存。系统凭据库中的密码、TOTP、认证缓存及隔离副本保留；如需清除，请先在设置中删除密码／TOTP，并用文件菜单清除当前账户认证缓存及旧版缓存。");
    messageBox.setText("确认删除当前配置 \"" + currentProfileId + "\" 吗？");
    messageBox.addButton(QMessageBox::Yes)->setText("是");
    messageBox.addButton(QMessageBox::No)->setText("否");
    messageBox.setDefaultButton(QMessageBox::No);
    if (messageBox.exec() != QMessageBox::Yes)
    {
        return;
    }

    const QString removedProfileId = currentProfileId;
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        QMessageBox::warning(this, "删除失败", "请先断开 VPN 连接，再删除配置。");
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
        QMessageBox::warning(this,"删除未完成","旧版缓存未能删除，配置文件已保留。请检查访问权限后重试。");return;
    }
    if (!profileService->removeCurrentAndSwitchToDefault())
    {
        QMessageBox::warning(this, "删除失败", "无法删除该配置文件。");
        return;
    }

    currentProfileId = profileService->currentProfileId();
    settings = profileService->settings();
    upgradeSettings();
    updateVersionInfo();
    resetConnectionUi();
    clearLog();
    refreshProfileMenu();
    qInfo().noquote() << "已删除配置：" + removedProfileId;
}

void MainWindow::upgradeSettings()
{
    const SettingsMigrationAction action = SettingsMigrator::prepare(*settings);
    if (action == SettingsMigrationAction::MigrateAutoStart)
    {
        if (!profileService->migrateAutoStartSetting(settings->value("Common/AutoStart", false).toBool())) {
            QMessageBox::warning(this, "自启动设置迁移失败", "未能保存原有自启动偏好，已保留旧配置以便重试。");
            return;
        }
    }
    if (action == SettingsMigrationAction::Failed || !SettingsMigrator::finish(*settings))
    {
        QMessageBox::warning(this, "配置迁移未完成", "未能保存升级后的配置，已保留旧版本以便重试。");
    }
}

void MainWindow::updateVersionInfo()
{
    const VersionInfo &versionInfo = updateChecker->versionInfo();
    ui->versionLabel->setText("版本 " + versionInfo.uiVersion);
    ui->versionLabel->setToolTip(
        "UI 版本：" + versionInfo.uiVersion + "（最新：" + versionInfo.uiLatest + "）\n"
        "内置核心：" + versionInfo.coreVersion
    );
    updateProfileSummary();
}

void MainWindow::showNotification(const QString &title, const QString &content, QSystemTrayIcon::MessageIcon icon)
{
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

        show();
        setWindowState(Qt::WindowState::WindowActive);
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
