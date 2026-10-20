#include "connectionuicontroller.h"
#include "presentation/presentationhelpers.h"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QDebug>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QWidget>

#include <utility>

#include "application/applicationlogger.h"
#include "application/connectionsession.h"
#include "application/systemproxysession.h"
#include "infrastructure/settings/settingsprofileloader.h"
#include "presentation/coordinators/authdialogcoordinator.h"

ConnectionUiController::ConnectionUiController(
    QWidget *parentWidget,
    QPushButton *connectButton,
    QPushButton *proxyButton,
    QAction *trayConnectAction,
    ConnectionSession *connectionSession,
    SystemProxySession *systemProxySession,
    AuthDialogCoordinator *authenticationDialogs,
    ApplicationLogger *applicationLogger,
    SettingsProvider settingsProvider,
    NotificationHandler notificationHandler,
    QObject *parent
)
    : QObject(parent),
      parentWidget(parentWidget),
      connectButton(connectButton),
      proxyButton(proxyButton),
      trayConnectAction(trayConnectAction),
      connectionSession(connectionSession),
      systemProxySession(systemProxySession),
      authenticationDialogs(authenticationDialogs),
      settingsProvider(std::move(settingsProvider)),
      notificationHandler(std::move(notificationHandler))
{
    connectButton->setText("连接服务器");
    trayConnectAction->setText("连接服务器");
    proxyButton->setText("设置系统代理");
    proxyButton->hide();

    connect(connectionSession, &ConnectionSession::diagnostic, applicationLogger,
        [applicationLogger](const QString &code) { applicationLogger->appendCoreOutput("[core] " + code + "\n"); });
    connect(
        authenticationDialogs,
        &AuthDialogCoordinator::loginSubmitted,
        this,
        [this](const QString &username, const QString &password, bool saveDetails)
        {
            if (saveDetails)
            {
                settings()->setValue("Credential/Username", username);
                settings()->setValue(
                    "Credential/Password",
                    QString(password.toUtf8().toBase64())
                );
                settings()->sync();
            }
            startConnection(username, password);
        }
    );
    connect(
        authenticationDialogs,
        &AuthDialogCoordinator::phoneNumberSubmitted,
        this,
        [this](
            const QString &countryCode,
            const QString &phoneNumber,
            bool saveDetails
        )
        {
            if (saveDetails)
            {
                settings()->setValue("JustConnect/PhoneCountryCode", countryCode);
                settings()->setValue("JustConnect/PhoneNumber", phoneNumber);
                settings()->sync();
            }

            const QString username =
                settings()->value("Credential/Username", "").toString();
            const QString password = QByteArray::fromBase64(
                settings()->value("Credential/Password", "").toString().toUtf8()
            );
            startConnection(
                username,
                password,
                countryCode + "-" + phoneNumber
            );
        }
    );
    connect(
        connectionSession,
        &ConnectionSession::reconnectScheduled,
        this,
        [](int) { qInfo().noquote() << "正在尝试重新连接..."; }
    );
    connect(
        connectionSession,
        &ConnectionSession::finished,
        this,
        [this](ConnectionError error)
        {
            qInfo().noquote() << "VPN 断开！";
            if (error != ConnectionError::NONE)
            {
                this->notificationHandler(
                    "VPN",
                    "VPN 意外断开！",
                    QSystemTrayIcon::MessageIcon::Warning
                );
            }
            this->connectButton->setText("连接服务器");
            this->trayConnectAction->setText("连接服务器");
            this->proxyButton->hide();
            if (this->connectionSession->state() != ConnectionState::Interrupted)
            {
                showConnectionError(error);
            }
        }
    );
    connect(connectionSession, &ConnectionSession::stateChanged, this, [this](ConnectionState state) {
        if (state == ConnectionState::Running) {
            this->proxyButton->show();
            if (settings()->value("Common/AutoSetProxy", false).toBool() && !this->systemProxySession->isEnabled())
                this->proxyButton->click();
        } else this->proxyButton->hide();
    });
    connect(
        connectButton,
        &QPushButton::clicked,
        this,
        &ConnectionUiController::handleConnectClicked
    );
    connect(
        proxyButton,
        &QPushButton::clicked,
        this,
        &ConnectionUiController::handleProxyClicked
    );

}

QSettings *ConnectionUiController::settings() const
{
    return settingsProvider();
}

void ConnectionUiController::handleConnectClicked()
{
    if (connectionSession->isActive())
    {
        connectionSession->stop();
        return;
    }

    if (settings()->contains("JustConnect/ServerAddress") &&
        settings()->value("JustConnect/ServerAddress").toString().isEmpty())
    {
        QMessageBox::critical(parentWidget, "错误", "服务器地址不能为空");
        return;
    }

    const QString username = settings()->value("Credential/Username", "").toString();
    const QString password = QByteArray::fromBase64(
        settings()->value("Credential/Password", "").toString().toUtf8()
    );
    const QString authType = settings()->value("JustConnect/AuthType","psw").toString();
    if (settings()->value("Common/NeedsConfiguration",false).toBool()) {
        QMessageBox::warning(parentWidget,"配置需要更新","请选择 Fudan 或确认 Custom 的 aTrust 服务器后保存配置。");
        return;
    }
    const bool passwordLogin = authType == "psw";
    if (authType == "smsCheckCode")
    {
        QString countryCode = settings()
            ->value("JustConnect/PhoneCountryCode", "86")
            .toString()
            .trimmed();
        const QString phoneNumber = settings()
            ->value("JustConnect/PhoneNumber", "")
            .toString()
            .trimmed();
        if (countryCode.isEmpty() || phoneNumber.isEmpty())
        {
            if (countryCode.isEmpty())
            {
                countryCode = "86";
            }
            authenticationDialogs->requestPhoneNumber(countryCode, phoneNumber);
            return;
        }
    }
    if (passwordLogin && (username.isEmpty() || password.isEmpty()))
    {
        authenticationDialogs->requestLogin(username, password);
        return;
    }
    startConnection(username, password);
}

void ConnectionUiController::handleProxyClicked()
{
    if (connectionSession->state() != ConnectionState::Running || systemProxySession->isBusy())
    {
        return;
    }
    if (systemProxySession->needsCleanup())
    {
        systemProxySession->disable();
        return;
    }

    const int httpPort = settings()->value("JustConnect/HTTPPort").toInt();
    const int socksPort = settings()->value("JustConnect/SOCKS5Port").toInt();
    const SystemProxyConfig proxyConfig{
        httpPort,
        socksPort,
        settings()->value("Common/SystemProxyBypass").toString()
    };
    connect(
        systemProxySession,
        &SystemProxySession::conflictCheckFinished,
        this,
        [this, proxyConfig, httpPort, socksPort](const SystemProxyCheck &check)
        {
            if (connectionSession->state() != ConnectionState::Running)
            {
                return;
            }

            if (!check.result.succeeded()) {
                QMessageBox::warning(parentWidget, "无法检查系统代理", PresentationHelpers::platformOperationMessage(check.result));
                return;
            }
            const bool conflict = check.conflict;
            if (conflict &&
                !settings()->value(
                    "Common/SuppressProxyOverrideWarning",
                    false
                ).toBool())
            {
                QMessageBox messageBox(
                    QMessageBox::Warning,
                    "警告",
                    "当前已存在系统代理配置（可能是 Clash 或其它代理软件）\n"
                    "是否覆盖当前系统代理配置？",
                    QMessageBox::Yes | QMessageBox::No,
                    parentWidget
                );
                auto *dontShowCheckBox = new QCheckBox("不再提示");
                messageBox.setCheckBox(dontShowCheckBox);
                if (messageBox.exec() == QMessageBox::No)
                {
                    return;
                }
                if (dontShowCheckBox->isChecked())
                {
                    settings()->setValue(
                        "Common/SuppressProxyOverrideWarning",
                        true
                    );
                    settings()->sync();
                }
            }
            else if (conflict)
            {
                qInfo().noquote() << "跳过系统代理覆盖警告，因为已设置了不再提示";
            }

            qInfo().noquote()
                << "设置系统代理：HTTP端口 " + QString::number(httpPort)
                       + "，SOCKS5 端口 " + QString::number(socksPort);
            systemProxySession->enable(proxyConfig);
        },
        Qt::SingleShotConnection
    );
    systemProxySession->checkConflict(proxyConfig);
}

void ConnectionUiController::startConnection(
    const QString &username,
    const QString &password,
    const QString &phone
)
{
    ConnectionProfile profile = SettingsProfileLoader::load(
        *settings(),
        username,
        password
    );
    if (!phone.isNull())
    {
        profile.endpoint.phone = phone;
    }
    const ReconnectPolicy reconnectPolicy{
        settings()->value("Common/AutoReconnect", false).toBool(),
        settings()->value("Common/ReconnectTime", 1).toInt() * 1000
    };
    if (!connectionSession->start(profile, reconnectPolicy)
        || !connectionSession->isActive())
    {
        return;
    }

    connectButton->setText("断开服务器");
    trayConnectAction->setText("断开服务器");

}

void ConnectionUiController::showConnectionError(ConnectionError error)
{
    QString message;
    switch (error)
    {
    case ConnectionError::CLIENT_FAILED:
        message = "连接失败！\n可能是响应超时，请检查本地网络配置是否正常，服务器设置是否正确。";
        break;
    case ConnectionError::CORE_UNAVAILABLE:
        message = "核心库不可用！\n请检查安装包是否完整及核心 ABI 是否匹配。";
        break;
    case ConnectionError::INVALID_CONFIGURATION:
        message = "配置无效或含有当前核心不支持的旧选项。\n请使用 aTrust 和回环 SOCKS/HTTP；TUN、额外 CLI 参数等功能尚不可用。";
        break;
    case ConnectionError::OTHER:
        message = "其它错误！\n未知原因，可将日志反馈给开发者以便调查。";
        break;
    case ConnectionError::NONE:
        return;
    }
    QMessageBox::critical(parentWidget, "错误", message);
}
