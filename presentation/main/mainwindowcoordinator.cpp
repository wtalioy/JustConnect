#include "mainwindowcoordinator.h"

#include <memory>

#include "application/connectionsession.h"
#include "application/profileservice.h"
#include "application/systemproxysession.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/settings/profilemanager.h"
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
      ))
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
        [this](bool enabled)
        {
            if (enabled && !connectionSession->isActive())
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
            if (systemProxySession->isEnabled())
            {
                systemProxySession->disable();
            }
        }
    );
}

ProfileService *MainWindowCoordinator::profiles() const
{
    return profileService;
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
    connectionSession->stop();
    systemProxySession->clearBeforeShutdown();
}
