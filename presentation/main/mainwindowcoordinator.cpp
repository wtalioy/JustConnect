#include "mainwindowcoordinator.h"

#include <memory>

#include "application/connectionsession.h"
#ifdef Q_OS_LINUX
#include "infrastructure/platform/linux/networkaccess.h"
#endif
#include "application/networkpolicysession.h"
#include "application/profileservice.h"
#include "application/systemproxysession.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/platform/proxyrecovery.h"
#include "infrastructure/platform/dnssnapshot.h"
#include "infrastructure/settings/profilemanager.h"
#include "infrastructure/settings/credentialaccess.h"
#include "infrastructure/platform/systemcredentialstore.h"
#include "infrastructure/storage/applicationpaths.h"
#include "infrastructure/update/updatechecker.h"
#include "presentation/coordinators/authdialogcoordinator.h"

MainWindowCoordinator::MainWindowCoordinator(
    QWidget *parentWidget,
    const QString &overrideConfigPath,
    QObject *parent
)
    : QObject(parent),
      profileService(new ProfileService(
          std::make_unique<ProfileManager>(),
          overrideConfigPath,
          this
      )),
      coreEngine(new EmbeddedCoreEngine()),
      networkPolicySession(new NetworkPolicySession(coreEngine, readSystemDnsSnapshot, this)),
      connectionSession(new ConnectionSession(coreEngine, this,
#ifdef Q_OS_LINUX
          new LinuxNetworkAccess(coreEngine, networkPolicySession,
              EmbeddedCoreEngine::buildInfo()["capabilities"].toObject()["tunnel_mtu"].toInt())
#else
          nullptr
#endif
      )),
      systemProxySession(new SystemProxySession(
          std::make_unique<ProxyRecoveryBackend>(),
          this
      )),
      updateChecker(new UpdateChecker(this)),
      authenticationCoordinator(new AuthDialogCoordinator(
          parentWidget,
          this
      )),
      credentialAccess(new CredentialAccess(createSystemCredentialStore(),this))
{
    connect(coreEngine, &CoreEngine::finished, systemProxySession, &SystemProxySession::disable);
    connect(connectionSession, &ConnectionSession::authenticationRequired,
        authenticationCoordinator, &AuthDialogCoordinator::requestAuthentication);
    connect(authenticationCoordinator, &AuthDialogCoordinator::responseSubmitted,
        connectionSession, &ConnectionSession::submitResponse);
    connect(connectionSession, &ConnectionSession::stateChanged, this, [this](ConnectionState state) {
        if (state == ConnectionState::Stopping) networkPolicySession->clear();
        if (state != ConnectionState::Starting) authenticationCoordinator->closeAuthentication();
    });

}

MainWindowCoordinator::~MainWindowCoordinator()
{
    // Finish worker writes before ProfileService synchronizes and destroys its settings.
    delete credentialAccess;
}

ProfileService *MainWindowCoordinator::profiles() const
{
    return profileService;
}

CredentialAccess *MainWindowCoordinator::credentials() const {return credentialAccess;}
CredentialSource MainWindowCoordinator::credentialSource() {
    const auto legacy=profileService->usesOverrideConfiguration() ? QString() : ApplicationPaths::clientDataFile(profileService->currentProfileId());
    return CredentialAccess::source(*profileService->settings(),legacy);
}

ConnectionSession *MainWindowCoordinator::connection() const
{
    return connectionSession;
}

NetworkPolicySession *MainWindowCoordinator::networkPolicy() const { return networkPolicySession; }

SystemProxySession *MainWindowCoordinator::systemProxy() const
{
    return systemProxySession;
}

UpdateChecker *MainWindowCoordinator::updates() const
{
    return updateChecker;
}

AuthDialogCoordinator *
MainWindowCoordinator::authenticationDialogs() const
{
    return authenticationCoordinator;
}
