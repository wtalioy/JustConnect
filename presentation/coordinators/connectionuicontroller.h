#ifndef CONNECTIONUICONTROLLER_H
#define CONNECTIONUICONTROLLER_H

#include <QObject>
#include <QSystemTrayIcon>
#include <QPointer>

#include <functional>
#include <optional>
#include "infrastructure/settings/credentialaccess.h"

#include "core/connectionerror.h"

class ApplicationShutdown;
class ControllerSelectionCoordinator;
class QAction;
class ApplicationLogger;
class AuthDialogCoordinator;
class AuthenticationCacheCoordinator;
class ConnectionSession;
class NetworkPolicySession;
class QPushButton;
class QSettings;
class SystemProxySession;
class QWidget;

class ConnectionUiController : public QObject
{
    Q_OBJECT

public:
    using CredentialSourceProvider = std::function<CredentialSource()>;
    using SettingsProvider = std::function<QSettings *()>;
    using OfficialClientProbe = std::function<std::optional<bool>()>;
    using NotificationHandler = std::function<void(
        const QString &title,
        const QString &content,
        QSystemTrayIcon::MessageIcon icon
    )>;

    ConnectionUiController(
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
        QObject *parent = nullptr,
        OfficialClientProbe officialClientProbe = {}
    );

    bool isConfigurationSaving() const;
    void enableCampusAccess();
    void toggleCampusAccess();
    void refreshActions();
    void cancelPendingCredentials();
    void clearAuthenticationCache();
    void prepareForQuit();
signals:
    void configurationRequested();
    void readyToQuit();
    void quitFailed(const QString &code);
private:
    void startConnection(ConnectionOptions connectionOptions,const CredentialSource &source,quint64 cacheRevision);
    void requestConnection(const CredentialSource &source,ConnectionOptions connectionOptions,quint64 cacheRevision);
    void loadAuthenticationCache(const CredentialSource &source,ConnectionOptions connectionOptions,quint64 generation,bool authorize=false);
    void submitLogin(const QString &username,const QString &password,bool save);
    void submitPhone(const QString &country,const QString &phone,bool save);
    void submitManual(const CredentialSource &source,const ConnectionOptions &connectionOptions,bool save,const QVariantMap &changes,bool updateCredentials);
    void showConnectionError(ConnectionError error);
    QSettings *settings() const;
    bool sourceStillCurrent(const CredentialSource &source) const;

    QWidget *parentWidget;
    QPushButton *connectButton;
    QAction *trayConnectAction;
    ConnectionSession *connectionSession;
    QPointer<NetworkPolicySession> networkPolicy;
    AuthDialogCoordinator *authenticationDialogs;
    SettingsProvider settingsProvider;
    CredentialAccess *credentials;
    CredentialSourceProvider credentialSourceProvider;
    std::optional<CredentialSource> promptSource;
    ConnectionCredentials promptCredentials;
    AuthenticationCacheCoordinator *authenticationCache;
    bool cacheCredentialsRequired=false;
    bool quitting=false;
    ApplicationShutdown *shutdown;
    ControllerSelectionCoordinator *controllerSelection;
    quint64 credentialGeneration=0;
    bool credentialsPending=false;
    NotificationHandler notificationHandler;
    OfficialClientProbe officialClientProbe;
};

#endif // CONNECTIONUICONTROLLER_H
