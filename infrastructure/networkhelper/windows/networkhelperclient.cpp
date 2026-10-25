#include "infrastructure/networkhelper/windows/networkhelperclient.h"
#include "infrastructure/networkhelper/windows/control.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "infrastructure/process/windows/identity.h"
#include "windowsnetworkcontract.h"
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QWinEventNotifier>
#include <QtConcurrent>
#include <objbase.h>
#include <mutex>
#include <system_error>
#include <climits>
#include <utility>

namespace {
using Result=PlatformOperationResult;
using Status=Result::Status;
QString text(const QUuid &id){return id.toString(QUuid::WithBraces).toUpper();}
GUID guid(const QUuid &id){GUID value{};const auto name=text(id);if(id.isNull() || FAILED(CLSIDFromString(reinterpret_cast<LPCOLESTR>(name.utf16()),&value)))throw std::runtime_error("Invalid control session");return value;}
Result failure(DWORD error){
    const auto status=error==ERROR_CANCELLED || error==ERROR_OPERATION_ABORTED?Status::Cancelled:error==ERROR_ACCESS_DENIED?Status::PermissionDenied:
        error==ERROR_NOT_SUPPORTED?Status::Unsupported:error==ERROR_TIMEOUT?Status::TimedOut:Status::Failed;
    return {status,QStringLiteral("Windows network permission operation failed (%1).").arg(error)};
}
const char *name(WindowsNetworkHelperClient::Operation operation){
    switch(operation){case WindowsNetworkHelperClient::Operation::Inspect:return "inspect";case WindowsNetworkHelperClient::Operation::Recover:return "recover";
        case WindowsNetworkHelperClient::Operation::Acknowledge:return "acknowledge";case WindowsNetworkHelperClient::Operation::Close:return "close";
        case WindowsNetworkHelperClient::Operation::Apply:return "apply";case WindowsNetworkHelperClient::Operation::Extend:
        case WindowsNetworkHelperClient::Operation::Routes:return "routes";case WindowsNetworkHelperClient::Operation::Quiesce:return "quiesce";case WindowsNetworkHelperClient::Operation::Restore:return "restore";}
    return "";
}
}

struct WindowsNetworkHelperClient::Native {
    HANDLE server=nullptr,cancelled=nullptr;
    std::mutex mutex;
    std::shared_ptr<WindowsPacketPipe> pipe;
    std::shared_ptr<WindowsPacketPipe> packets;
    explicit Native(HANDLE approved):server(approved){cancelled=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!cancelled){const auto error=GetLastError();CloseHandle(server);throw std::system_error(error,std::system_category());}}
    ~Native(){stop();CloseHandle(cancelled);CloseHandle(server);}
    void stop(){SetEvent(cancelled);std::shared_ptr<WindowsPacketPipe> connection,data;{std::lock_guard<std::mutex> guard(mutex);connection=pipe;data=packets;}if(connection)connection->close();if(data)data->close();}
    void connectPackets(const QUuid &session){
        auto connected=WindowsPacketPipe::connect(windowsPacketPipeName(guid(session)),server,WindowsNetworkContract::ControlTimeoutMs,cancelled);
        std::lock_guard<std::mutex> guard(mutex);
        if(WaitForSingleObject(cancelled,0)!=WAIT_TIMEOUT)throw std::system_error(ERROR_OPERATION_ABORTED,std::system_category());
        packets=std::move(connected);
    }
    void closePackets(){std::shared_ptr<WindowsPacketPipe> data;{std::lock_guard<std::mutex> guard(mutex);data=std::exchange(packets,{});}if(data)data->close();}
    std::shared_ptr<WindowsPacketPipe> connection(const QUuid &session){
        {std::lock_guard<std::mutex> guard(mutex);if(pipe)return pipe;}
        auto connected=WindowsPacketPipe::connect(windowsControlPipeName(guid(session)),server,WindowsNetworkContract::ControlTimeoutMs,cancelled);
        std::lock_guard<std::mutex> guard(mutex);
        if(WaitForSingleObject(cancelled,0)!=WAIT_TIMEOUT)throw std::system_error(ERROR_OPERATION_ABORTED,std::system_category());
        pipe=std::move(connected);return pipe;
    }
};

WindowsNetworkHelperClient::WindowsNetworkHelperClient(QObject *parent,AuthorizationProvider authorize)
    :QObject(parent),authorization(std::move(authorize))
{
    connect(&launcher,&QProcess::readyReadStandardOutput,this,[this]{
        launchOutput+=launcher.readAllStandardOutput();
        if(launchOutput.size()>WindowsNetworkContract::MaxMessageBytes){launcher.kill();complete({Status::Failed,"Invalid Windows authorization reply."});}
    });
    connect(&launcher,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this]{launcherFinished();});
    connect(&launcher,&QProcess::errorOccurred,this,[this](QProcess::ProcessError error){if(error==QProcess::FailedToStart && current==State::Authorizing)complete({Status::Unsupported,"Windows network helper is unavailable."});});
    connect(&worker,&QFutureWatcher<Reply>::finished,this,[this]{
        if(current==State::Cancelling){stopMonitoring();native.reset();owners={};device={};configuration={};complete({Status::Cancelled,"Network permission operation cancelled.",true});return;}
        const auto reply=worker.result();owners=reply.owners;device=reply.device;
        if(reply.result.succeeded() && (operation==Operation::Apply || operation==Operation::Extend || operation==Operation::Routes))configuration=reply.configuration;
        if(reply.result.succeeded() && operation==Operation::Quiesce)quiet=true;
        if(operation==Operation::Apply || operation==Operation::Restore || operation==Operation::Close || !reply.result.succeeded())quiet=false;
        if(operation==Operation::Restore || operation==Operation::Close || !reply.result.succeeded())configuration={};
        if(!reply.result.succeeded() || operation==Operation::Close){stopMonitoring();native.reset();}
        complete(reply.result);
    });
}
WindowsNetworkHelperClient::~WindowsNetworkHelperClient(){
    stopMonitoring();
    disconnect(&launcher,nullptr,this,nullptr);disconnect(&worker,nullptr,this,nullptr);
    if(native)native->stop();
    if(launcher.state()!=QProcess::NotRunning){launcher.kill();launcher.waitForFinished(1000);}
    worker.waitForFinished();native.reset();
}
void WindowsNetworkHelperClient::setState(State state){if(current!=state){current=state;emit stateChanged(state);}}
void WindowsNetworkHelperClient::complete(Result result){
    const auto state=native && result.succeeded()?(device.isEmpty()?State::Ready:quiet?State::Quiesced:State::Active):State::Idle;
    setState(state);
    emit finished(operation,result);
}
void WindowsNetworkHelperClient::inspect(const QUuid &id){
    if(id==session && (current==State::Ready || current==State::Active || current==State::Quiesced)){request(Operation::Inspect);return;}
    if(current!=State::Idle || id.isNull()){emit finished(Operation::Inspect,{Status::Failed,"Previous network permission operation is still active."});return;}
    session=id;owners={};operation=Operation::Inspect;launchOutput.clear();setState(State::Authorizing);const auto generation=++serial;
    if(authorization){
        QPointer<WindowsNetworkHelperClient> guarded(this);
        authorization(id,[guarded,generation](HANDLE server,DWORD error){if(guarded)guarded->authorized(generation,server,error);else if(server)CloseHandle(server);});
        return;
    }
    try{
        WindowsProcess caller(GetCurrentProcessId());
        launcher.start(QDir(QCoreApplication::applicationDirPath()).filePath(QString::fromWCharArray(WindowsNetworkContract::Executable)),
            {"--authorize",QString::number(caller.identity().pid),QString::number(caller.identity().created),text(session)});
    }catch(const std::system_error &error){complete(failure(error.code().value()));}
}
void WindowsNetworkHelperClient::launcherFinished(){
    if(current==State::Cancelling){native.reset();owners={};complete({Status::Cancelled,"Network permission operation cancelled."});return;}
    if(current!=State::Authorizing)return;
    launchOutput+=launcher.readAllStandardOutput();
    const auto object=QJsonDocument::fromJson(launchOutput).object();
    bool validHandle=false;
    const auto value=object["handle"].toString().toULongLong(&validHandle);
    if(launchOutput.size()>WindowsNetworkContract::MaxMessageBytes || object.size()!=4 || object["version"].toInteger(-1)!=WindowsNetworkContract::Protocol || object["session"].toString()!=text(session)
        || !validHandle || QString::number(value)!=object["handle"].toString() || !object["error"].isDouble()){
        complete({Status::Failed,"Invalid Windows authorization reply."});return;
    }
    const auto error=object["error"].toInteger(ERROR_INVALID_DATA);
    if(error<INT_MIN || error>MAXDWORD || launcher.exitStatus()!=QProcess::NormalExit || launcher.exitCode()!=(error?1:0)){
        complete({Status::Failed,"Invalid Windows authorization result."});return;
    }
    authorized(serial,reinterpret_cast<HANDLE>(static_cast<quintptr>(value)),static_cast<DWORD>(error));
}
void WindowsNetworkHelperClient::authorized(quint64 generation,HANDLE server,DWORD error){
    if(generation!=serial || current!=State::Authorizing){if(server)CloseHandle(server);return;}
    if(error || !server){if(server)CloseHandle(server);complete(failure(error?error:ERROR_INVALID_HANDLE));return;}
    try{
        native=std::make_shared<Native>(server);
        monitor=new QWinEventNotifier(server,this);
        connect(monitor,&QWinEventNotifier::activated,this,[this,generation](HANDLE){
            if(generation!=serial || !native || current==State::Closing || current==State::Cancelling)return;
            stopMonitoring();native->stop();
            if(!worker.isRunning()){native.reset();device={};configuration={};setState(State::Idle);}
            emit ownershipLost({Status::Failed,"Windows network helper exited before cleanup was confirmed.",true});
        });
        request(Operation::Inspect);
    }
    catch(const std::system_error &error){complete(failure(error.code().value()));}
}
void WindowsNetworkHelperClient::request(Operation next,const QUuid &owner,const QJsonObject &payload){
    if(!native || worker.isRunning() || (current!=State::Ready && current!=State::Authorizing && current!=State::Active && current!=State::Quiesced)){
        emit finished(next,{Status::Failed,"Windows network control is not ready."});return;
    }
    if((next==Operation::Recover || next==Operation::Acknowledge) && owner.isNull()){
        emit finished(next,{Status::Failed,"Invalid network ownership identity."});return;
    }
    operation=next;
    if(next==Operation::Close)stopMonitoring();
    setState(next==Operation::Inspect?State::Inspecting:next==Operation::Apply?State::Applying:next==Operation::Extend?State::Extending:
        next==Operation::Routes?State::Reconciling:next==Operation::Quiesce?State::Quiescing:next==Operation::Restore?State::Restoring:
        next==Operation::Recover?State::Recovering:next==Operation::Acknowledge?State::Acknowledging:State::Closing);
    const auto connection=native;const auto id=session;
    auto candidate=configuration;
    if(next==Operation::Apply)candidate=payload["configuration"].toObject();
    else if(next==Operation::Extend || next==Operation::Routes)candidate["capture_prefixes"]=payload["capture_prefixes"];
    worker.setFuture(QtConcurrent::run([connection,id,owner,next,payload,candidate]{
        Reply result;
        result.configuration=candidate;
        try{
            auto pipe=connection->connection(id);
            QJsonObject request{{"version",int(WindowsNetworkContract::Protocol)},{"session",text(id)},{"operation",name(next)},{"owner",owner.isNull()?QJsonValue(QJsonValue::Null):QJsonValue(text(owner))}};
            for(auto field=payload.begin();field!=payload.end();++field)request.insert(field.key(),field.value());
            sendWindowsControlMessage(*pipe,QJsonDocument(request).toJson(QJsonDocument::Compact).toStdString());
            const auto response=receiveWindowsControlMessage(*pipe,WindowsNetworkContract::ControlTimeoutMs);
            const auto reply=QJsonDocument::fromJson(QByteArray::fromStdString(response)).object();
            if(reply.size()!=7 || reply["version"].toInteger(-1)!=WindowsNetworkContract::Protocol || reply["session"].toString()!=text(id)
                || reply["operation"].toString()!=name(next) || !reply["ok"].isBool() || !reply["error"].isDouble() || !reply["owners"].isArray()
                || (!reply["device"].isNull() && !reply["device"].isObject()))
                throw std::runtime_error("Invalid Windows control response");
            if(!reply["ok"].toBool())result.result=failure(static_cast<DWORD>(reply["error"].toInteger(ERROR_INVALID_DATA)));
            else{
                if(reply["error"].toInteger(-1)!=0)throw std::runtime_error("Inconsistent Windows control response");
                for(const auto &item:reply["owners"].toArray()){
                    const auto record=item.toObject();const auto value=record["owner"].toString();const QUuid uuid(value);const auto phase=record["phase"].toString();
                    if(record.size()!=3 || uuid.isNull() || text(uuid)!=value || !record["live"].isBool() || (phase!="declared" && phase!="restoring" && phase!="restored"))throw std::runtime_error("Invalid Windows ownership receipt");
                    result.owners.append(record);
                }
                result.device=reply["device"].toObject();
                if(!result.device.isEmpty()){
                    const auto value=result.device["guid"].toString();const QUuid uuid(value);
                    bool valid=false;const auto luid=result.device["luid"].toString().toULongLong(&valid);
                    const auto index=result.device["index"].toInteger(0);
                    if(result.device.size()!=8 || uuid.isNull() || text(uuid)!=value || !valid || !luid || QString::number(luid)!=result.device["luid"].toString()
                        || index<=0 || index>MAXDWORD || result.device["name"].toString().isEmpty())throw std::runtime_error("Invalid owned device identity");
                    const auto dns=result.device["dns_id"];
                    if(!dns.isNull() && (QUuid(dns.toString()).isNull() || text(QUuid(dns.toString()))!=dns.toString()))throw std::runtime_error("Invalid owned DNS identity");
                }
                if(next==Operation::Apply){
                    const auto expected=payload["configuration"].toObject();
                    if(result.device["address"]!=expected["address"] || result.device["peer"]!=expected["peer"] || result.device["mtu"]!=expected["mtu"])throw std::runtime_error("Applied device configuration differs");
                    connection->connectPackets(id);
                }
                if(next==Operation::Restore)connection->closePackets();
                if(next==Operation::Close){
                    const unsigned char received=1;pipe->write(&received,1,WindowsNetworkContract::ControlTimeoutMs);
                    const HANDLE waits[]{connection->server,connection->cancelled};
                    const auto state=WaitForMultipleObjects(2,waits,FALSE,WindowsNetworkContract::ControlTimeoutMs);
                    if(state!=WAIT_OBJECT_0)throw std::system_error(state==WAIT_OBJECT_0+1?ERROR_OPERATION_ABORTED:state==WAIT_TIMEOUT?ERROR_TIMEOUT:GetLastError(),std::system_category());
                    DWORD code=1;if(!GetExitCodeProcess(connection->server,&code) || code!=0)throw std::runtime_error("Windows control close failed");
                }
            }
        }catch(const std::system_error &error){result.result=failure(error.code().value());}
        catch(const std::exception &){result.result={Status::Failed,"Invalid Windows network control response."};}
        if(!result.result.succeeded())result.result.mayHaveChanged=next!=Operation::Inspect;
        if(!result.result.succeeded() || next==Operation::Close)connection->stop();
        return result;
    }));
}
void WindowsNetworkHelperClient::recover(const QUuid &owner){request(Operation::Recover,owner);}
void WindowsNetworkHelperClient::cleanupRestored(const QUuid &owner){request(Operation::Acknowledge,owner);}
void WindowsNetworkHelperClient::apply(const QJsonObject &value){request(Operation::Apply,session,{{"configuration",value}});}
void WindowsNetworkHelperClient::reconcile(const QStringList &prefixes){request(Operation::Routes,session,{{"capture_prefixes",QJsonArray::fromStringList(prefixes)}});}
void WindowsNetworkHelperClient::extend(const QStringList &addresses){
    QStringList prefixes;for(const auto &item:configuration["capture_prefixes"].toArray())prefixes.append(item.toString());
    for(const auto &value:addresses)prefixes.append(value+"/32");prefixes.removeDuplicates();prefixes.sort();
    request(Operation::Extend,session,{{"capture_prefixes",QJsonArray::fromStringList(prefixes)}});
}
void WindowsNetworkHelperClient::quiesce(){request(Operation::Quiesce,session);}
void WindowsNetworkHelperClient::restore(){request(Operation::Restore,session);}
quint64 WindowsNetworkHelperClient::packetPipeHandle() const{if(!native)return 0;std::lock_guard<std::mutex> guard(native->mutex);return native->packets?quint64(reinterpret_cast<quintptr>(native->packets->handle())):0;}
quint32 WindowsNetworkHelperClient::helperPID() const{return native?GetProcessId(native->server):0;}
void WindowsNetworkHelperClient::close(){if(current==State::Ready || current==State::Active || current==State::Quiesced)request(Operation::Close);else cancel();}
void WindowsNetworkHelperClient::cancel(){
    if(current==State::Idle)return;
    ++serial;
    stopMonitoring();
    if(native)native->stop();
    if(worker.isRunning()){setState(State::Cancelling);return;}
    if(launcher.state()!=QProcess::NotRunning){setState(State::Cancelling);launcher.kill();return;}
    native.reset();owners={};device={};configuration={};complete({Status::Cancelled,"Network permission operation cancelled.",true});
}
void WindowsNetworkHelperClient::stopMonitoring(){if(monitor){monitor->setEnabled(false);monitor->deleteLater();monitor=nullptr;}}
