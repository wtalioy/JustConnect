#include "connectionuicontroller.h"
#include "application/networkpolicysession.h"
#include "authenticationcachecoordinator.h"
#include "controllerselectioncoordinator.h"
#include "presentation/presentationhelpers.h"
#include "presentation/widgets/applicationpreferenceswidget.h"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QDebug>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QWidget>
#include <QUrl>
#include <QtConcurrent>

#include <utility>

#include "application/applicationlogger.h"
#include "application/connectionsession.h"
#include "application/applicationshutdown.h"
#include "application/authmethodsquery.h"
#include "application/systemproxysession.h"
#include "application/profileservice.h"
#include "application/settingsmigrator.h"
#include "application/defaultsettings.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/process/running.h"
#include "presentation/coordinators/authdialogcoordinator.h"

ConnectionUiController::ConnectionUiController(
    QWidget *parentWidget,
    QPushButton *connectButton,
    QAction *trayConnectAction,
    ConnectionSession *connectionSession,
    SystemProxySession *systemProxySession,
    NetworkPolicySession *networkPolicy,
    AuthDialogCoordinator *authenticationDialogs,
    ApplicationLogger *applicationLogger,
    CredentialAccess *credentials,
    SettingsProvider settingsProvider,
    CredentialSourceProvider credentialSourceProvider,
    NotificationHandler notificationHandler,
    QObject *parent,
    OfficialClientProbe officialClientProbe
)
    : QObject(parent),
      parentWidget(parentWidget),
      connectButton(connectButton),
      trayConnectAction(trayConnectAction),
      connectionSession(connectionSession),
      networkPolicy(networkPolicy),
      authenticationDialogs(authenticationDialogs),
      settingsProvider(std::move(settingsProvider)),credentials(credentials),credentialSourceProvider(std::move(credentialSourceProvider)),
      notificationHandler(std::move(notificationHandler)),
      officialClientProbe(officialClientProbe?std::move(officialClientProbe):[] {return isProcessRunning(QStringLiteral("aTrustAgent"));})
{
    refreshActions();

    connect(connectionSession, &ConnectionSession::diagnostic, this,
        [this,applicationLogger](const QString &code) {
            applicationLogger->appendCoreOutput("[core] " + code);
            if (code == "browser_proxy_changed_externally")
                this->notificationHandler(tr("Browser proxy changed"),tr("New proxy settings were detected. JustConnect will preserve them."),QSystemTrayIcon::Information);
        });
    authenticationCache=new AuthenticationCacheCoordinator(connectionSession,credentials,this->credentialSourceProvider,this);
    controllerSelection=new ControllerSelectionCoordinator(parentWidget,this);
    shutdown=new ApplicationShutdown(connectionSession,systemProxySession, [this] {
        if (this->credentials->isBusy() || authenticationCache->isBinding() || controllerSelection->isReading()) return true;
        if (this->networkPolicy && this->networkPolicy->isBusy()) return true;
        for (auto *query:this->parentWidget->findChildren<AuthMethodsQuery *>()) if (query->isActive()) return true;
        for (auto *preferences : this->parentWidget->findChildren<ApplicationPreferencesWidget *>())
            if (preferences->isSavingStartup()) return true;
        return false;
    },this);
    connect(shutdown,&ApplicationShutdown::ready,this,&ConnectionUiController::readyToQuit);
    connect(shutdown,&ApplicationShutdown::failed,this,&ConnectionUiController::quitFailed);
    connect(authenticationCache,&AuthenticationCacheCoordinator::warning,this,[this](const QString &message) {
        this->notificationHandler(tr("Authentication cache was not saved"),message,QSystemTrayIcon::Warning);
    });
    connect(authenticationCache,&AuthenticationCacheCoordinator::forgotten,this,[this] { cacheCredentialsRequired=false; });
    connect(authenticationDialogs,&AuthDialogCoordinator::loginSubmitted,this,&ConnectionUiController::submitLogin);
    connect(authenticationDialogs,&AuthDialogCoordinator::phoneNumberSubmitted,this,&ConnectionUiController::submitPhone);
    connect(authenticationDialogs,&AuthDialogCoordinator::credentialInputCancelled,this,&ConnectionUiController::cancelPendingCredentials);
    connect(
        connectionSession,
        &ConnectionSession::reconnectScheduled,
        this,
        [this](int delayMs) {
            qInfo().noquote() << tr("Reconnect %1/%2 in %3 seconds")
                .arg(this->connectionSession->reconnectAttempt()).arg(ConnectionSessionState::MaxReconnectAttempts).arg(delayMs / 1000.0);
        }
    );
    connect(
        connectionSession,
        &ConnectionSession::finished,
        this,
        [this](ConnectionError error)
        {
            qInfo().noquote() << tr("VPN disconnected");
            if (quitting) return;
            if (error==ConnectionError::CREDENTIALS_REQUIRED && cacheCredentialsRequired && authenticationCache->source()
                && sourceStillCurrent(*authenticationCache->source()) && CredentialAccess::matches(*authenticationCache->source(),*settings())) {
                cacheCredentialsRequired=false;
                promptSource=this->credentialSourceProvider();
                refreshActions();
                this->authenticationDialogs->requestLogin(promptSource->profile.credentials.username,{});
                return;
            }
            promptCredentials={};cacheCredentialsRequired=false;
            if (error != ConnectionError::NONE)
            {
                this->notificationHandler(
                    "VPN",
                    tr("VPN disconnected unexpectedly"),
                    QSystemTrayIcon::MessageIcon::Warning
                );
            }
            refreshActions();
            if (this->connectionSession->state() != ConnectionState::Interrupted)
            {
                showConnectionError(error);
            }
        }
    );
    connect(connectionSession,&ConnectionSession::stateChanged,this,[this] { refreshActions(); });
    connect(connectionSession,&ConnectionSession::progressChanged,this,[this] { refreshActions(); });
    connect(
        connectButton,
        &QPushButton::clicked,
        this,
        &ConnectionUiController::toggleCampusAccess
    );
    connect(trayConnectAction,&QAction::triggered,this,&ConnectionUiController::toggleCampusAccess);

}

void ConnectionUiController::refreshActions()
{
    const auto action=connectionSession->networkRecoveryFailed()?tr("Retry recovery")
        : connectionSession->state()==ConnectionState::Stopping?tr("Disconnecting…")
        : connectionSession->state()==ConnectionState::Starting || connectionSession->state()==ConnectionState::Reconnecting?tr("Cancel")
        : connectionSession->isActive()?tr("Disconnect")
        : credentialsPending?tr("Cancel"):tr("Connect");
    connectButton->setText(action);trayConnectAction->setText(action);
    const bool enabled=!quitting && (connectionSession->state()!=ConnectionState::Stopping || connectionSession->networkRecoveryFailed());
    connectButton->setEnabled(enabled);trayConnectAction->setEnabled(enabled);
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

bool ConnectionUiController::isConfigurationSaving() const
{
    return credentials->isSaving(settings()->fileName())
        || authenticationCache->isBindingFor(settings()->fileName());
}

void ConnectionUiController::cancelPendingCredentials()
{
    ++credentialGeneration;credentialsPending=false;promptSource.reset();promptCredentials={};
    controllerSelection->cancel();
    authenticationDialogs->closeCredentialPrompts();
    if (!connectionSession->isActive()) {refreshActions();}
}
void ConnectionUiController::toggleCampusAccess()
{
    if (quitting) return;
    if (connectionSession->isActive()) {cancelPendingCredentials();connectionSession->stop();return;}
    if (credentialsPending) {cancelPendingCredentials();return;}
    enableCampusAccess();
}
void ConnectionUiController::enableCampusAccess()
{
    if (quitting || connectionSession->isActive() || credentialsPending) return;
    if (auto *modal=QApplication::activeModalWidget()) {modal->raise();modal->activateWindow();return;}
    if (isConfigurationSaving()) {QMessageBox::information(parentWidget,tr("Saving profile"),tr("Wait for the save before connecting."));return;}
    cancelPendingCredentials();
    const auto profile=ProfileService::load(*settings());
    if (settings()->value("Common/NeedsConfiguration",false).toBool() || profile.endpoint.server.isEmpty() || profile.endpoint.authType.isEmpty()) {
        emit configurationRequested();return;
    }
    const auto source=credentialSourceProvider();const auto generation=credentialGeneration;
    if (!SettingsMigrator::readableFile(source.path)) {
        QMessageBox::warning(parentWidget,tr("Profile unavailable"),tr("The current profile could not be read. Check file permissions and contents, then reopen it."));return;
    }
    credentialsPending=true;refreshActions();
    // The vendor's three desktop clients use aTrustAgent; this is advisory, never ownership or authentication evidence.
    QtConcurrent::run(officialClientProbe).then(this,[this,generation](std::optional<bool> running) {
        if(quitting || generation!=credentialGeneration)return;
        if(!running){qWarning()<<"Cannot inspect the official aTrust core process.";return;}
        if(*running)notificationHandler(tr("The official aTrust client is running"),
            tr("Its routes or DNS may conflict with JustConnect. Disconnect it manually first. JustConnect will not terminate its processes."),QSystemTrayIcon::Warning);
    });
    credentials->load(source).then(this,[this,source,generation](const CredentialLoadResult &loaded) {
        if (generation!=credentialGeneration) return;
        if (!sourceStillCurrent(source) || (loaded.result.succeeded() && !CredentialAccess::matches(source,*settings()))) {cancelPendingCredentials();return;}
        if (!loaded.result.succeeded() && loaded.result.status!=CredentialStatus::NotFound) {
            QMessageBox::warning(parentWidget,tr("Saved credentials unavailable"),PresentationHelpers::credentialOperationMessage(loaded.result.status)+tr("\nYou can sign in manually for this connection."));
        }
        if (generation!=credentialGeneration) return;
        const auto current=credentialSourceProvider();
        if (current.path!=source.path || current.profile.authenticationIdentity()!=source.profile.authenticationIdentity()
            || (loaded.result.succeeded() && current.scope!=source.scope)) {
            cancelPendingCredentials();
            return;
        }
        auto profile=current.profile;
        if (loaded.result.succeeded()) profile.credentials=loaded.credentials;
        if (profile.behavior.rememberAuthentication && !current.scope.isEmpty()) loadAuthenticationCache(current,profile,generation);
        else {
            credentialsPending=false;
            refreshActions();
            requestConnection(current,profile,credentials->authenticationCacheRevision(current));
        }
    });
}
void ConnectionUiController::loadAuthenticationCache(const CredentialSource &source,ConnectionProfile profile,quint64 generation)
{
    credentials->loadAuthenticationCache(source).then(this,[this,source,profile,generation](const AuthenticationCacheLoadResult &loaded) mutable {
        if (generation!=credentialGeneration) return;
        if (!sourceStillCurrent(source) || !CredentialAccess::matches(source,*settings())
            || source.publicValues!=DefaultSettings::publicValues(*settings())
            || loaded.revision!=credentials->authenticationCacheRevision(source)) {cancelPendingCredentials();return;}
        credentialsPending=false;
        if (loaded.result.succeeded()) profile.authenticationCache=loaded.cache;
        else if (loaded.result.status!=CredentialStatus::NotFound)
            notificationHandler(tr("Authentication cache was not restored"),PresentationHelpers::credentialOperationMessage(loaded.result.status)+tr("\nYou will sign in again for this connection."),QSystemTrayIcon::Warning);
        refreshActions();
        requestConnection(source,profile,loaded.revision);
    });
}
void ConnectionUiController::requestConnection(const CredentialSource &source,ConnectionProfile profile,quint64 revision)
{
    if (profile.endpoint.authType=="smsCheckCode" && profile.endpoint.phone.isEmpty()) {
        promptSource=source;promptCredentials=profile.credentials;
        auto country=settings()->value("JustConnect/PhoneCountryCode","86").toString().trimmed();
        if (country.isEmpty()) country="86";
        authenticationDialogs->requestPhoneNumber(country,settings()->value("JustConnect/PhoneNumber").toString());return;
    }
    if (profile.endpoint.authType=="psw" && (profile.credentials.username.isEmpty()
        || (profile.credentials.password.isEmpty() && profile.authenticationCache.data.isEmpty()))) {
        promptSource=source;promptCredentials=profile.credentials;
        authenticationDialogs->requestLogin(profile.credentials.username,profile.credentials.password);return;
    }
    startConnection(profile,source,revision);
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
    if (!save) {const auto current=credentialSourceProvider();startConnection(profile,current,credentials->authenticationCacheRevision(current));return;}
    const auto generation=++credentialGeneration;
    credentialsPending=true;refreshActions();
    credentials->save(source,profile,updateCredentials,changes).then(this,[this,source,profile,generation](const CredentialResult &result) {
        if (generation!=credentialGeneration) return;
        credentialsPending=false;
        const bool sameFile=settings()->fileName()==source.path;
        if (!sameFile) {cancelPendingCredentials();return;}
        if (!result.succeeded()) QMessageBox::warning(parentWidget,tr("Login details were not saved"),PresentationHelpers::credentialOperationMessage(result.status)+tr("\nYou can sign in manually for this connection."));
        if (generation!=credentialGeneration) return;
        const auto current=ProfileService::load(*settings());
        const auto expected=result.succeeded() ? profile.authenticationIdentity() : source.profile.authenticationIdentity();
        if (current.authenticationIdentity()!=expected) {cancelPendingCredentials();return;}
        const auto currentSource=credentialSourceProvider();
        startConnection(profile,currentSource,credentials->authenticationCacheRevision(currentSource));
    });
}

void ConnectionUiController::startConnection(ConnectionProfile profile,const CredentialSource &source,quint64 revision)
{
    const auto generation=credentialGeneration;
    credentialsPending=true;refreshActions();
    controllerSelection->choose([this,profile=std::move(profile),source,revision,generation](std::optional<QString> address) mutable {
        if (generation!=credentialGeneration || quitting) return;
        credentialsPending=false;
        if (!address || !sourceStillCurrent(source)) { cancelPendingCredentials();return; }
        profile.behavior.controllerAddress=*address;
        promptSource.reset();promptCredentials=profile.credentials;
        profile=authenticationCache->prepare(std::move(profile),source,revision);
        cacheCredentialsRequired=profile.endpoint.authType=="psw" && profile.credentials.password.isEmpty() && !profile.authenticationCache.data.isEmpty();
        const ReconnectPolicy reconnectPolicy{
            settings()->value("Common/AutoReconnect", false).toBool(),
            qBound(1, settings()->value("Common/ReconnectTime", 1).toInt(), ConnectionSessionState::MaxReconnectDelayMs / 1000) * 1000
        };
        if (!connectionSession->start(profile, reconnectPolicy)
            || !connectionSession->isActive())
        {
            return;
        }

        refreshActions();

    });
}

void ConnectionUiController::clearAuthenticationCache()
{
    if (quitting) return;
    const auto source=credentialSourceProvider();
    if (isConfigurationSaving()) {
        QMessageBox::information(parentWidget,tr("Saving profile"),tr("Wait for the save before clearing authentication caches."));return;
    }
    if (ProfileCredentials::authenticationCacheKey(source.scope,source.profile).isEmpty()) {
        QMessageBox::information(parentWidget,tr("Authentication cache"),tr("This profile has no bound account cache to clear."));return;
    }
    const auto account=source.profile.credentials.username.isEmpty() ? source.profile.endpoint.phone : source.profile.credentials.username;
    QMessageBox confirm(QMessageBox::Question,tr("Clear authentication cache"),source.profile.endpoint.server+tr("\nClear the authentication cache for ")+account+tr("? The next connection may require sign-in. Passwords, TOTP and other accounts are preserved."),QMessageBox::Yes|QMessageBox::No,parentWidget);
    confirm.setTextFormat(Qt::PlainText);confirm.setDefaultButton(QMessageBox::No);
    if (confirm.exec()!=QMessageBox::Yes) return;
    if (credentialsPending) cancelPendingCredentials();
    authenticationCache->clear(source).then(this,[this](const CredentialResult &result) {
        if (!result.succeeded()) QMessageBox::warning(parentWidget,tr("Authentication cache cleanup incomplete"),PresentationHelpers::credentialOperationMessage(result.status));
    });
}

void ConnectionUiController::prepareForQuit()
{
    if (!quitting) {
        quitting=true;
        if (networkPolicy) networkPolicy->clear();
        cancelPendingCredentials();
        for (auto *query:parentWidget->findChildren<AuthMethodsQuery *>()) query->stop();
        authenticationDialogs->closeAuthentication();
        authenticationDialogs->closeCredentialPrompts();
        connectButton->setEnabled(false);
        trayConnectAction->setEnabled(false);
    }
    shutdown->request();
}

void ConnectionUiController::showConnectionError(ConnectionError error)
{
    QString message;
    switch (error)
    {
    case ConnectionError::PERMISSION_DENIED:
        message=tr("Network permission was denied. Check interface access or authorization, then retry.");
        break;
    case ConnectionError::SESSION_INVALID:
        message=tr("The server ended the session. Select Connect to sign in again.");
        break;
    case ConnectionError::CREDENTIALS_REQUIRED:
        message=tr("Authentication expired or could not be restored. Enter your credentials and retry.");
        break;
    case ConnectionError::AUTHENTICATION_UNSUPPORTED:
        message=tr("The next sign-in step is not supported. Ask your administrator to confirm the authentication policy.");
        break;
    case ConnectionError::AUTHENTICATION_CHANGED:
        message = tr("Sign-in methods changed or are ambiguous. Query and select the method again.");
        break;
    case ConnectionError::TLS_TRUST:
        message=tr("The certificate is not trusted or does not match the server. Check the address, system time and campus CA.");
        break;
    case ConnectionError::TLS_PROTOCOL:
        message=tr("TLS negotiation failed. Check the server port and TLS compatibility.");
        break;
    case ConnectionError::NETWORK_FAILED:
        message=tr("The network connection failed. Check DNS, connectivity and the server address.");
        break;
    case ConnectionError::TIMED_OUT:
        message=tr("The connection or sign-in timed out. Please retry.");
        break;
    case ConnectionError::CLIENT_FAILED:
        message = tr("Connection failed. Check your network and server settings.");
        break;
    case ConnectionError::CORE_UNAVAILABLE:
        message = tr("The core library is unavailable. Check that the package is complete and its ABI matches.");
        break;
    case ConnectionError::INVALID_CONFIGURATION:
        message = tr("The profile is invalid or has unsupported legacy options. Use aTrust and supported network settings.");
        break;
    case ConnectionError::OTHER:
        message = tr("Unexpected error. Share the diagnostic log with the developer for investigation.");
        break;
    case ConnectionError::NONE:
        return;
    }
    QMessageBox::critical(parentWidget, tr("Error"), message);
}
