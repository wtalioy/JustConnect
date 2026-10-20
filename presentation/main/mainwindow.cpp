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
#include "infrastructure/settings/settingsprofileloader.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/storage/applicationpaths.h"
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
                ui->disableProxyAction->setEnabled(!busy);
            });
    connect(systemProxySession, &SystemProxySession::enabledChanged, this,
            [this](bool enabled)
            {
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


    // 文件-退出
    connect(ui->exitAction, &QAction::triggered, this, &MainWindow::gracefullyQuit);

    // 文件-设置
    connect(ui->settingAction, &QAction::triggered, this,
            [&]()
            {
                settingWindow = new SettingWindow(this, settings, currentProfileId);
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

    // 文件-清理登录数据
    connect(ui->clearClientDataAction, &QAction::triggered, this,
            [&]()
            {
                QMessageBox messageBox(this);
                messageBox.setWindowTitle("清理登录缓存");
                messageBox.setText("是否清理登录缓存？");

                messageBox.addButton(QMessageBox::Yes)->setText("是");
                messageBox.addButton(QMessageBox::No)->setText("否");
                messageBox.setDefaultButton(QMessageBox::Yes);

                if (messageBox.exec() == QMessageBox::No)
                {
                    return;
                }

                ApplicationPaths::clearClientData(currentProfileId);
                qInfo().noquote() << "已清理登录缓存";
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
        [this]() { return settings; },
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

    if (!profileService->silentStartEnabled())
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

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        event->ignore();
        hide();
        showNotification("JustConnect", "程序已最小化到系统托盘，单击图标可恢复窗口。", QSystemTrayIcon::MessageIcon::Information);
    }
    else
    {
        event->accept();
    }
}

void MainWindow::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::WindowStateChange)
    {
        QWindowStateChangeEvent *stateChangeEvent = static_cast<QWindowStateChangeEvent *>(event);
        if (windowState().testFlag(Qt::WindowMinimized) == true && !(stateChangeEvent->oldState() & Qt::WindowMinimized))
        {
            event->ignore();
            hide();
            showNotification("JustConnect", "程序已最小化到系统托盘，单击图标可恢复窗口。", QSystemTrayIcon::MessageIcon::Information);
        }
    }
    else
    {
        event->accept();
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
        title = "正在连接";
        detail = "正在启动核心并建立安全通道。";
        break;
    case ConnectionState::Running:
        propertyValue = "running";
        title = "已连接";
        detail = systemProxySession->needsCleanup() && !systemProxySession->isEnabled()
            ? "系统代理状态未确认，请检查残留设置。"
            : systemProxySession->isEnabled()
            ? "VPN 通道与系统代理均已启用。"
            : "VPN 通道运行中，可按需启用系统代理。";
        break;
    case ConnectionState::Stopping:
        propertyValue = "stopping";
        title = "正在断开";
        detail = "正在安全关闭当前连接。";
        break;
    case ConnectionState::Reconnecting:
        propertyValue = "reconnecting";
        title = "正在重连";
        detail = "连接中断，正在按当前策略重新尝试。";
        break;
    case ConnectionState::Interrupted:
        propertyValue = "failed";
        title = "连接已断开";
        detail = "VPN 核心意外退出，请查看右侧日志。";
        break;
    case ConnectionState::Failed:
        propertyValue = "failed";
        title = "连接失败";
        detail = "请查看右侧日志，确认网络与账户配置。";
        break;
    }

    ui->statusTitleLabel->setText(title);
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

    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    if (!profileService->switchTo(profileId))
    {
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
    updateVersionInfo();
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

    if (settingWindow != nullptr)
    {
        settingWindow->close();
    }

    const auto before = SettingsProfileLoader::load(*settings);
    ConfigurationGuideDialog guide(this, settings);
    if (guide.exec() != QDialog::Accepted)
    {
        return;
    }

    if (!before.hasSameAuthentication(SettingsProfileLoader::load(*settings)))
    {
        ApplicationPaths::clearClientData(currentProfileId);
    }

    resetConnectionUi();
    clearLog();
    qInfo().noquote() << "已通过配置引导更新当前配置";
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
    if (!profileService->renameCurrent(normalizedName))
    {
        QMessageBox::warning(this, "重命名失败", "目标配置已存在，或当前配置不可重命名。");
        return;
    }

    currentProfileId = profileService->currentProfileId();
    settings = profileService->settings();
    updateVersionInfo();
    refreshProfileMenu();
    clearLog();
    qInfo().noquote() << "当前配置已重命名为：" + currentProfileId;
}

void MainWindow::deleteCurrentProfile()
{
    if (currentProfileId.isEmpty())
    {
        QMessageBox::warning(this, "删除失败", "默认配置不可删除。");
        return;
    }

    QMessageBox messageBox(this);
    messageBox.setWindowTitle("删除配置");
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

    // 清除系统代理
    coordinator->prepareForShutdown();
}

void MainWindow::gracefullyQuit()
{
    if (connectionSession != nullptr && connectionSession->isActive())
    {
        connect(connectionSession, &ConnectionSession::finished, qApp,
                [](ConnectionError) { QApplication::quit(); });
        ui->pushButton1->click();
    }
    else
    {
        qApp->quit();
    }
}

MainWindow::~MainWindow()
{
    delete coordinator;
    coordinator = nullptr;

    QObject::disconnect(applicationLogger, nullptr, this, nullptr);
    delete ui;
    ui = nullptr;
}
