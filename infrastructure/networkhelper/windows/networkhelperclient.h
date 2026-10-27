#pragma once
#include "application/platformoperationresult.h"
#include <QObject>
#include <QProcess>
#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <QUuid>
#include <windows.h>
#include <functional>
#include <memory>
class QWinEventNotifier;

class WindowsNetworkHelperClient final : public QObject
{
    Q_OBJECT
public:
    enum class State {Idle,Authorizing,Inspecting,Ready,Applying,Active,Extending,Reconciling,Quiescing,Quiesced,Restoring,Recovering,Acknowledging,Closing,Cancelling};
    Q_ENUM(State)
    enum class Operation {Inspect,Apply,Extend,Routes,Quiesce,Restore,Recover,Acknowledge,Close};
    Q_ENUM(Operation)
    // Providers deliver on this object's thread and transfer ownership of the approved process handle.
    using AuthorizationProvider=std::function<void(const QUuid &,std::function<void(HANDLE,DWORD)>)>;
    explicit WindowsNetworkHelperClient(QObject *parent=nullptr,AuthorizationProvider authorization={});
    ~WindowsNetworkHelperClient() override;
    void inspect(const QUuid &session);
    void recover(const QUuid &owner);
    void cleanupRestored(const QUuid &owner);
    void apply(const QJsonObject &configuration);
    void extend(const QStringList &addresses);
    void reconcile(const QStringList &prefixes,bool refreshDNS=false);
    void quiesce();
    void restore();
    void close();
    void cancel();
    State state() const{return current;}
    QJsonArray pendingOwners() const{return owners;}
    QJsonObject ownedConfiguration() const{return configuration;}
    QJsonObject ownedDevice() const{return device;}
    quint64 packetPipeHandle() const;
    quint32 helperPID() const;
signals:
    void stateChanged(WindowsNetworkHelperClient::State state);
    void finished(WindowsNetworkHelperClient::Operation operation,PlatformOperationResult result);
    void ownershipLost(PlatformOperationResult result);
private:
    struct Native;
    struct Reply {PlatformOperationResult result;QJsonArray owners;QJsonObject device,configuration;};
    void setState(State state);
    void authorized(quint64 serial,HANDLE server,DWORD error);
    void request(Operation operation,const QUuid &owner={},const QJsonObject &payload={});
    void complete(PlatformOperationResult result);
    void launcherFinished();
    void stopMonitoring();
    std::shared_ptr<Native> native;
    AuthorizationProvider authorization;
    QProcess launcher;
    QFutureWatcher<Reply> worker;
    QByteArray launchOutput;
    QUuid session;
    QJsonArray owners;
    QJsonObject configuration,device;
    QWinEventNotifier *monitor=nullptr;
    bool quiet=false;
    quint64 serial=0;
    State current=State::Idle;
    Operation operation=Operation::Inspect;
};
