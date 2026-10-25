#pragma once
#include "application/platformoperationresult.h"
#include <QObject>
#include <QProcess>
#include <QFutureWatcher>
#include <QJsonArray>
#include <QUuid>
#include <windows.h>
#include <functional>
#include <memory>

class WindowsNetworkHelperClient final : public QObject
{
    Q_OBJECT
public:
    enum class State {Idle,Authorizing,Inspecting,Ready,Recovering,Acknowledging,Closing,Cancelling};
    Q_ENUM(State)
    enum class Operation {Inspect,Recover,Acknowledge,Close};
    Q_ENUM(Operation)
    // Providers deliver on this object's thread and transfer ownership of the approved process handle.
    using AuthorizationProvider=std::function<void(const QUuid &,std::function<void(HANDLE,DWORD)>)>;
    explicit WindowsNetworkHelperClient(QObject *parent=nullptr,AuthorizationProvider authorization={});
    ~WindowsNetworkHelperClient() override;
    void inspect(const QUuid &session);
    void recover(const QUuid &owner);
    void cleanupRestored(const QUuid &owner);
    void close();
    void cancel();
    State state() const{return current;}
    QJsonArray pendingOwners() const{return owners;}
signals:
    void stateChanged(WindowsNetworkHelperClient::State state);
    void finished(WindowsNetworkHelperClient::Operation operation,PlatformOperationResult result);
private:
    struct Native;
    struct Reply {PlatformOperationResult result;QJsonArray owners;};
    void setState(State state);
    void authorized(quint64 serial,HANDLE server,DWORD error);
    void request(Operation operation,const QUuid &owner={});
    void complete(PlatformOperationResult result);
    void launcherFinished();
    std::shared_ptr<Native> native;
    AuthorizationProvider authorization;
    QProcess launcher;
    QFutureWatcher<Reply> worker;
    QByteArray launchOutput;
    QUuid session;
    QJsonArray owners;
    quint64 serial=0;
    State current=State::Idle;
    Operation operation=Operation::Inspect;
};
