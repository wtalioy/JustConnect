#include "mainwindowcoordinator.h"

#include <memory>

#include "application/connectionsession.h"
#include "application/profileservice.h"
#include "application/systemproxysession.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/platform/platformsystemproxybackend.h"
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
      connectionSession(new ConnectionSession(new EmbeddedCoreEngine(), this)),
      systemProxySession(new SystemProxySession(
          std::make_unique<PlatformSystemProxyBackend>(),
          this
      )),
      updateChecker(new UpdateChecker(this)),
      authenticationCoordinator(new AuthDialogCoordinator(
          parentWidget,
          this
      )),
      credentialAccess(new CredentialAccess(createSystemCredentialStore(),this))
{
    connect(connectionSession, &ConnectionSession::authenticationRequired,
        authenticationCoordinator, &AuthDialogCoordinator::requestAuthentication);
    connect(authenticationCoordinator, &AuthDialogCoordinator::responseSubmitted,
        connectionSession, &ConnectionSession::submitResponse);
    connect(connectionSession, &ConnectionSession::stateChanged, this, [this](ConnectionState state) {
        if (state != ConnectionState::Starting) authenticationCoordinator->closeAuthentication();
    });

    connect(
        systemProxySession,
        &SystemProxySession::operationFinished,
        this,
        [this](bool enabled, const PlatformOperationResult &result)
        {
            if (result.succeeded() && enabled && !connectionSession->isActive())
            {
                systemProxySession->disable();
            }
        }
    );
    connect(
        connectionSession,
        &ConnectionSession::finished,
        this,
        [this](ConnectionError)
        {
            if (systemProxySession->needsCleanup())
            {
                systemProxySession->disable();
            }
        }
    );
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

void MainWindowCoordinator::prepareForShutdown()
{
    authenticationCoordinator->closeAuthentication();
    authenticationCoordinator->closeCredentialPrompts();
    connectionSession->stop();
    const auto result = systemProxySession->clearBeforeShutdown();
    if (!result.succeeded()) qWarning() << "System proxy cleanup failed:" << result.detail << "partial:" << result.mayHaveChanged;
}
