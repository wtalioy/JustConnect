#ifndef CONNECTIONUICONTROLLER_H
#define CONNECTIONUICONTROLLER_H

#include <QObject>
#include <QSystemTrayIcon>

#include <functional>
#include <optional>
#include "infrastructure/settings/credentialaccess.h"

#include "core/connectionerror.h"

class QAction;
class ApplicationLogger;
class AuthDialogCoordinator;
class ConnectionSession;
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
    using NotificationHandler = std::function<void(
        const QString &title,
        const QString &content,
        QSystemTrayIcon::MessageIcon icon
    )>;

    ConnectionUiController(
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
        QObject *parent = nullptr
    );

    void cancelPendingCredentials();
private:
    void handleConnectClicked();
    void handleProxyClicked();
    void startConnection(const ConnectionProfile &profile);
    void requestConnection(const CredentialSource &source,ConnectionProfile profile);
    void submitLogin(const QString &username,const QString &password,bool save);
    void submitPhone(const QString &country,const QString &phone,bool save);
    void submitManual(const CredentialSource &source,const ConnectionProfile &profile,bool save,const QVariantMap &changes,bool updateCredentials);
    void showConnectionError(ConnectionError error);
    QSettings *settings() const;
    bool sourceStillCurrent(const CredentialSource &source) const;

    QWidget *parentWidget;
    QPushButton *connectButton;
    QPushButton *proxyButton;
    QAction *trayConnectAction;
    ConnectionSession *connectionSession;
    SystemProxySession *systemProxySession;
    AuthDialogCoordinator *authenticationDialogs;
    SettingsProvider settingsProvider;
    CredentialAccess *credentials;
    CredentialSourceProvider credentialSourceProvider;
    std::optional<CredentialSource> promptSource;
    ConnectionCredentials promptCredentials;
    quint64 credentialGeneration=0;
    bool credentialsPending=false;
    NotificationHandler notificationHandler;
};

#endif // CONNECTIONUICONTROLLER_H
