#include "mainwindowcoordinator.h"
#include "presentation/coordinators/connectiondiagnostics.h"

#include <memory>

#include "application/connectionsession.h"
#include "application/coexistencenetworkaccess.h"
#include "infrastructure/systemproxy/proxychanges.h"
#if defined(Q_OS_MACOS)
#include "infrastructure/networkaccess/macos/networkaccess.h"
#else
#include "infrastructure/networkaccess/windows/networkaccess.h"
#endif
#include "application/networkpolicysession.h"
#include "application/savedconnectionservice.h"
#include "application/systemproxysession.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/systemproxy/proxyrecovery.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/settings/savedconnectionstore.h"
#include "infrastructure/settings/credentialaccess.h"
#include "infrastructure/credentialstore/systemcredentialstore.h"
#include "infrastructure/storage/applicationpaths.h"
#include "infrastructure/update/updatechecker.h"
#include "presentation/coordinators/authdialogcoordinator.h"

namespace {
NetworkAccess *createNetworkAccess(CoreEngine *core, NetworkPolicySession *policy, SystemProxySession *&proxy,
    QObject *parent, MainWindowCoordinator::NetworkFactory factory)
{
    if (factory) {
        proxy = new SystemProxySession(std::make_unique<ProxyRecoveryBackend>(),parent);
        return factory(core,policy);
    }
#if defined(Q_OS_MACOS)
    auto *native = new MacNetworkAccess(core, policy);
    auto backend = native->makeProxyBackend();
#else
    auto *native = new WindowsNetworkAccess(core, policy);
    auto backend = std::make_unique<ProxyRecoveryBackend>();
#endif
    proxy = new SystemProxySession(std::move(backend),parent);
    auto *network = new CoexistenceNetworkAccess(native, core, policy, proxy);
    QObject::connect(network, &CoexistenceNetworkAccess::proxyObservationRequired, network,
        [network, changes = static_cast<ProxyChanges *>(nullptr)](bool enabled) mutable {
            if (enabled && !changes) {
                changes = new ProxyChanges(network);
                QObject::connect(changes, &ProxyChanges::changed, network, &CoexistenceNetworkAccess::systemProxyChanged);
            } else if (!enabled && changes) {
                delete changes;
                changes = nullptr;
            }
        });
    return network;
}
}

MainWindowCoordinator::MainWindowCoordinator(
    QWidget *parentWidget,
    const QString &overrideConfigPath,
    QObject *parent,
    NetworkFactory networkFactory
)
    : QObject(parent),
      savedConnections(new SavedConnectionService(
          std::make_unique<SavedConnectionStore>(),
          overrideConfigPath,
          this
      )),
      coreEngine(new EmbeddedCoreEngine()),
      networkPolicySession(new NetworkPolicySession(coreEngine, observeSystemDnsSnapshot(), this,
          [this] { return !connectionSession->usesLocalProxy(); })),
      systemProxySession(nullptr),
      connectionSession(new ConnectionSession(coreEngine, this,
          createNetworkAccess(coreEngine, networkPolicySession, systemProxySession, this, networkFactory))),
      updateChecker(new UpdateChecker(this)),
      authenticationCoordinator(new AuthDialogCoordinator(
          parentWidget,
          this
      )),
      credentialAccess(new CredentialAccess(createSystemCredentialStore(),this)),
      connectionDiagnostics(new ConnectionDiagnostics(coreEngine,connectionSession,networkPolicySession,systemProxySession,this))
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
    // Finish worker writes before SavedConnectionService synchronizes and destroys its settings.
    delete credentialAccess;
}

SavedConnectionService *MainWindowCoordinator::connectionSettingsService() const
{
    return savedConnections;
}

CredentialAccess *MainWindowCoordinator::credentials() const {return credentialAccess;}
CredentialSource MainWindowCoordinator::credentialSource() {
    const auto legacy=savedConnections->usesOverrideConfiguration() ? QString() : ApplicationPaths::clientDataFile(savedConnections->currentConnectionId());
    return CredentialAccess::source(*savedConnections->settings(),legacy);
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

ConnectionDiagnostics *MainWindowCoordinator::diagnostics() const { return connectionDiagnostics; }
