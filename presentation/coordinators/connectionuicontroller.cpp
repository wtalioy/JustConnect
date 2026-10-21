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
#include <QUrl>
#include <QTimer>

#include <utility>

#include "application/applicationlogger.h"
#include "application/connectionsession.h"
#include "application/systemproxysession.h"
#include "application/profileservice.h"
#include "application/settingsmigrator.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
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
    CredentialAccess *credentials,
    SettingsProvider settingsProvider,
    CredentialSourceProvider credentialSourceProvider,
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
      settingsProvider(std::move(settingsProvider)),credentials(credentials),credentialSourceProvider(std::move(credentialSourceProvider)),
      notificationHandler(std::move(notificationHandler))
{
    connectButton->setText("连接服务器");
    trayConnectAction->setText("连接服务器");
    proxyButton->setText("设置系统代理");
    proxyButton->hide();

    connect(connectionSession, &ConnectionSession::diagnostic, applicationLogger,
        [applicationLogger](const QString &code) { applicationLogger->appendCoreOutput("[core] " + code + "\n"); });
    connect(authenticationDialogs,&AuthDialogCoordinator::loginSubmitted,this,&ConnectionUiController::submitLogin);
    connect(authenticationDialogs,&AuthDialogCoordinator::phoneNumberSubmitted,this,&ConnectionUiController::submitPhone);
    connect(authenticationDialogs,&AuthDialogCoordinator::credentialInputCancelled,this,&ConnectionUiController::cancelPendingCredentials);
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
            autoProxyPending=settings()->value("Common/AutoSetProxy",false).toBool()
                && (!this->systemProxySession->isEnabled() || this->systemProxySession->isBusy());
            applyPendingAutomaticProxy();
        } else { ++proxyGeneration;autoProxyPending=false;this->proxyButton->hide(); }
    });
    connect(systemProxySession,&SystemProxySession::busyChanged,this,[this](bool busy) {
        // Deliver the old operation's result before starting the current session's request.
        if (!busy && autoProxyPending) QTimer::singleShot(0,this,&ConnectionUiController::applyPendingAutomaticProxy);
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

bool ConnectionUiController::sourceStillCurrent(const CredentialSource &source) const
{
    return settings()->fileName()==source.path
        && ProfileService::load(*settings()).authenticationIdentity()==source.profile.authenticationIdentity();
}

void ConnectionUiController::cancelPendingCredentials()
{
    ++credentialGeneration;credentialsPending=false;promptSource.reset();promptCredentials={};
    authenticationDialogs->closeCredentialPrompts();
    if (!connectionSession->isActive()) {connectButton->setText("连接服务器");trayConnectAction->setText("连接服务器");}
}
void ConnectionUiController::handleConnectClicked()
{
    if (connectionSession->isActive()) {cancelPendingCredentials();connectionSession->stop();return;}
    if (credentialsPending) {cancelPendingCredentials();return;}
    if (auto *modal=QApplication::activeModalWidget()) {modal->raise();modal->activateWindow();return;}
    if (credentials->isSaving(settings()->fileName())) {QMessageBox::information(parentWidget,"正在保存配置","请等待保存完成后再连接。");return;}
    cancelPendingCredentials();
    if (settings()->value("Common/NeedsConfiguration",false).toBool()) {
        QMessageBox::warning(parentWidget,"配置需要更新","请选择 Fudan 或确认 Custom 的 aTrust 服务器后保存配置。");return;
    }
    if (settings()->value("JustConnect/ServerAddress").toString().isEmpty()) {QMessageBox::critical(parentWidget,"错误","服务器地址不能为空");return;}
    if (ProfileService::load(*settings()).endpoint.authType.isEmpty()) {
        QMessageBox::warning(parentWidget,"请选择认证方式","请在设置中确认认证方式；可从当前服务器获取可用列表。");return;
    }
    const auto source=credentialSourceProvider();const auto generation=credentialGeneration;
    if (!SettingsMigrator::readableFile(source.path)) {
        QMessageBox::warning(parentWidget,"配置不可用","无法读取当前配置，请检查文件权限与内容后重新打开配置。");return;
    }
    credentialsPending=true;connectButton->setText("取消连接");trayConnectAction->setText("取消连接");
    credentials->load(source).then(this,[this,source,generation](const CredentialLoadResult &loaded) {
        if (generation!=credentialGeneration) return;
        credentialsPending=false;
        if (!sourceStillCurrent(source) || (loaded.result.succeeded() && !CredentialAccess::matches(source,*settings()))) {cancelPendingCredentials();return;}
        if (!loaded.result.succeeded() && loaded.result.status!=CredentialStatus::NotFound) {
            QMessageBox::warning(parentWidget,"无法读取已保存凭据",PresentationHelpers::credentialOperationMessage(loaded.result.status)+"\n本次仍可手动登录。");
        }
        if (generation!=credentialGeneration || !sourceStillCurrent(source)) return;
        auto profile=ProfileService::load(*settings());
        if (loaded.result.succeeded()) profile.credentials=loaded.credentials;
        connectButton->setText("连接服务器");trayConnectAction->setText("连接服务器");
        requestConnection(source,profile);
    });
}
void ConnectionUiController::requestConnection(const CredentialSource &source,ConnectionProfile profile)
{
    if (profile.endpoint.authType=="smsCheckCode" && profile.endpoint.phone.isEmpty()) {
        promptSource=source;promptCredentials=profile.credentials;
        auto country=settings()->value("JustConnect/PhoneCountryCode","86").toString().trimmed();
        if (country.isEmpty()) country="86";
        authenticationDialogs->requestPhoneNumber(country,settings()->value("JustConnect/PhoneNumber").toString());return;
    }
    if (profile.endpoint.authType=="psw" && (profile.credentials.username.isEmpty() || profile.credentials.password.isEmpty())) {
        promptSource=source;promptCredentials=profile.credentials;
        authenticationDialogs->requestLogin(profile.credentials.username,profile.credentials.password);return;
    }
    startConnection(profile);
}
void ConnectionUiController::submitLogin(const QString &username,const QString &password,bool save)
{
    if (!promptSource || !sourceStillCurrent(*promptSource)) return;
    const auto source=*promptSource;auto profile=ProfileService::load(*settings());
    const auto totp=username.trimmed()==source.profile.credentials.username && CredentialAccess::matches(source,*settings())
        ? promptCredentials.totpSecret : QString();
    profile.credentials={username.trimmed(),password,totp};promptSource.reset();promptCredentials={};
    submitManual(source,profile,save,{{"Credential/Username",profile.credentials.username}},
        !profile.credentials.password.isEmpty() || !profile.credentials.totpSecret.isEmpty());
}
void ConnectionUiController::submitPhone(const QString &country,const QString &phone,bool save)
{
    if (!promptSource || !sourceStillCurrent(*promptSource)) return;
    const auto source=*promptSource;auto profile=ProfileService::load(*settings());
    profile.endpoint.phone=country+"-"+phone;promptSource.reset();promptCredentials={};
    submitManual(source,profile,save,{{"JustConnect/PhoneCountryCode",country},{"JustConnect/PhoneNumber",phone}},false);
}
void ConnectionUiController::submitManual(const CredentialSource &source,const ConnectionProfile &profile,bool save,const QVariantMap &changes,bool updateCredentials)
{
    const auto validation=EmbeddedCoreEngine::validateConfiguration(profile);
    if (validation!=ConnectionError::NONE) {showConnectionError(validation);return;}
    if (!save) {startConnection(profile);return;}
    const auto generation=++credentialGeneration;
    credentialsPending=true;connectButton->setText("取消连接");trayConnectAction->setText("取消连接");
    credentials->save(source,profile,updateCredentials,changes).then(this,[this,source,profile,generation](const CredentialResult &result) {
        if (generation!=credentialGeneration) return;
        credentialsPending=false;
        const bool sameFile=settings()->fileName()==source.path;
        if (!sameFile) {cancelPendingCredentials();return;}
        if (!result.succeeded()) QMessageBox::warning(parentWidget,"未能记住登录信息",PresentationHelpers::credentialOperationMessage(result.status)+"\n本次仍可手动登录。");
        if (generation!=credentialGeneration) return;
        const auto current=ProfileService::load(*settings());
        const auto expected=result.succeeded() ? profile.authenticationIdentity() : source.profile.authenticationIdentity();
        if (current.authenticationIdentity()!=expected) {cancelPendingCredentials();return;}
        startConnection(profile);
    });
}

void ConnectionUiController::applyPendingAutomaticProxy()
{
    if (!autoProxyPending) return;
    if (connectionSession->state()!=ConnectionState::Running || !settings()->value("Common/AutoSetProxy",false).toBool()) {
        autoProxyPending=false;return;
    }
    if (systemProxySession->isBusy()) return;
    autoProxyPending=false;
    if (systemProxySession->needsCleanup()) return;
    handleProxyClicked();
}

void ConnectionUiController::handleProxyClicked()
{
    if (connectionSession->state() != ConnectionState::Running || systemProxySession->isBusy())
    {
        return;
    }
    autoProxyPending=false;
    if (systemProxySession->needsCleanup())
    {
        systemProxySession->disable();
        return;
    }

    const auto listeners = connectionSession->proxyOptions();
    const QUrl http("http://" + listeners.httpBind), socks("http://" + listeners.socksBind);
    const int httpPort = http.host() == "127.0.0.1" ? http.port(0) : 0;
    const int socksPort = socks.host() == "127.0.0.1" ? socks.port(0) : 0;
    if (httpPort < 1 || socksPort < 1) {
        QMessageBox::warning(parentWidget,"无法设置系统代理","设置系统代理需要同时启用本地 HTTP 和 SOCKS5 监听。请修改配置后重新连接。");
        return;
    }
    const auto generation = ++proxyGeneration;
    const SystemProxyConfig proxyConfig{
        httpPort,
        socksPort,
        settings()->value("Common/SystemProxyBypass").toString()
    };
    connect(
        systemProxySession,
        &SystemProxySession::conflictCheckFinished,
        this,
        [this, proxyConfig, httpPort, socksPort, generation](const SystemProxyCheck &check)
        {
            const auto current = [this,generation] {
                return generation == proxyGeneration && connectionSession->state() == ConnectionState::Running
                    && !systemProxySession->isBusy() && !systemProxySession->needsCleanup();
            };
            if (!current()) return;

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
                if (messageBox.exec() != QMessageBox::Yes || !current())
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

            if (!current()) return;
            qInfo().noquote()
                << "设置系统代理：HTTP端口 " + QString::number(httpPort)
                       + "，SOCKS5 端口 " + QString::number(socksPort);
            systemProxySession->enable(proxyConfig);
        },
        Qt::SingleShotConnection
    );
    systemProxySession->checkConflict(proxyConfig);
}

void ConnectionUiController::startConnection(const ConnectionProfile &profile)
{
    promptSource.reset();promptCredentials={};
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
    case ConnectionError::AUTHENTICATION_UNSUPPORTED:
        message="服务器要求的后续认证步骤暂不支持，请联系管理员确认认证策略。";
        break;
    case ConnectionError::AUTHENTICATION_CHANGED:
        message = "认证方式已变化或不唯一，请重新获取并选择认证方式。";
        break;
    case ConnectionError::TLS_TRUST:
        message="服务器证书不受信任或与地址不匹配。请检查服务器地址、系统时间和学校 CA。";
        break;
    case ConnectionError::TLS_PROTOCOL:
        message="TLS 协议协商失败。请检查服务器端口与 TLS 兼容性。";
        break;
    case ConnectionError::NETWORK_FAILED:
        message="网络连接失败。请检查 DNS、网络与服务器地址。";
        break;
    case ConnectionError::TIMED_OUT:
        message="连接或认证操作超时，请重试。";
        break;
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
