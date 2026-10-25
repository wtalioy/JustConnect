#ifndef MAINWINDOWCOORDINATOR_H
#define MAINWINDOWCOORDINATOR_H

#include <QObject>

class AuthDialogCoordinator;
class ConnectionSession;
class CoreEngine;
class NetworkAccess;
class NetworkPolicySession;
class CredentialAccess;
struct CredentialSource;
class ProfileService;
class SystemProxySession;
class UpdateChecker;
class QWidget;

class MainWindowCoordinator : public QObject
{
    Q_OBJECT

public:
    using NetworkFactory = NetworkAccess *(*)(CoreEngine *, NetworkPolicySession *);

    MainWindowCoordinator(
        QWidget *parentWidget,
        const QString &overrideConfigPath,
        QObject *parent = nullptr,
        NetworkFactory networkFactory = nullptr
    );

    ~MainWindowCoordinator() override;

    ProfileService *profiles() const;
    CredentialAccess *credentials() const;
    CredentialSource credentialSource();
    ConnectionSession *connection() const;
    NetworkPolicySession *networkPolicy() const;
    SystemProxySession *systemProxy() const;
    UpdateChecker *updates() const;
    AuthDialogCoordinator *authenticationDialogs() const;


private:
    ProfileService *profileService;
    CoreEngine *coreEngine; // Owned by ConnectionSession and shared with the collector.
    NetworkPolicySession *networkPolicySession;
    ConnectionSession *connectionSession;
    SystemProxySession *systemProxySession;
    UpdateChecker *updateChecker;
    AuthDialogCoordinator *authenticationCoordinator;
    CredentialAccess *credentialAccess;
};

#endif // MAINWINDOWCOORDINATOR_H
