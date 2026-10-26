#include "infrastructure/networkhelper/windows/control.h"
#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/networkhelper/windows/service.h"
#include "infrastructure/networkhelper/windows/recovery.h"
#include "infrastructure/networkhelper/windows/session.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "windowsnetworkcontract.h"
#include <objbase.h>
#include <ws2tcpip.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <system_error>
#include <thread>
#include <iostream>

using namespace winrt::Windows::Data::Json;
namespace {
[[noreturn]] void fail(const char *stage,DWORD error=ERROR_INVALID_DATA)
{ throw std::system_error(static_cast<int>(error),std::system_category(),stage); }
std::wstring guid(const GUID &id)
{
    wchar_t value[39]{};
    if(id==GUID{} || !StringFromGUID2(id,value,39))fail("invalid control identity");
    return value;
}
GUID identifier(const winrt::hstring &value)
{
    GUID id{};
    if(FAILED(CLSIDFromString(value.c_str(),&id)) || guid(id)!=value.c_str())fail("noncanonical control identity");
    return id;
}
struct Request {std::wstring operation;GUID owner{};std::optional<WindowsNetworkConfiguration> configuration;std::vector<WindowsTunPrefix> captures;};
Request request(const std::string &message,const GUID &session) try
{
    const auto value=JsonObject::Parse(winrt::to_hstring(message));
    if(!value.HasKey(L"version") || !value.HasKey(L"session") || !value.HasKey(L"operation") || !value.HasKey(L"owner")
        || value.GetNamedNumber(L"version")!=WindowsNetworkContract::Protocol || identifier(value.GetNamedString(L"session"))!=session)
        fail("invalid control request envelope");
    const auto operation=value.GetNamedString(L"operation");
    Request result{{operation.data(),operation.size()}};
    const bool payload=result.operation==L"apply" || result.operation==L"routes";
    if(value.Size()!=(payload?5u:4u))fail("unknown control request fields");
    const auto owner=value.GetNamedValue(L"owner");
    if(result.operation==L"inspect" || result.operation==L"close"){
        if(owner.ValueType()!=JsonValueType::Null)fail("unexpected control owner");
    }else if(result.operation==L"recover" || result.operation==L"acknowledge" || result.operation==L"apply" || result.operation==L"routes" || result.operation==L"quiesce" || result.operation==L"restore")result.owner=identifier(owner.GetString());
    else fail("unknown control operation");
    if(result.operation==L"apply")result.configuration=decodeWindowsNetworkConfiguration(winrt::to_string(value.GetNamedObject(L"configuration").Stringify()));
    if(result.operation==L"routes")result.captures=decodeWindowsCapturePrefixes(winrt::to_string(value.GetNamedArray(L"capture_prefixes").Stringify()));
    return result;
}catch(const winrt::hresult_error &){fail("invalid native control JSON");}
JsonObject response(const GUID &session,const Request &request)
{
    JsonObject value;
    value.SetNamedValue(L"version",JsonValue::CreateNumberValue(WindowsNetworkContract::Protocol));
    value.SetNamedValue(L"session",JsonValue::CreateStringValue(guid(session)));
    value.SetNamedValue(L"operation",JsonValue::CreateStringValue(request.operation));
    value.SetNamedValue(L"ok",JsonValue::CreateBooleanValue(true));
    value.SetNamedValue(L"error",JsonValue::CreateNumberValue(0));
    value.SetNamedValue(L"owners",JsonArray{});
    value.SetNamedValue(L"device",JsonValue::CreateNullValue());
    return value;
}
JsonObject metadata(const WindowsNetworkSession &session,const WindowsNetworkConfiguration &configuration)
{
    const auto &identity=session.identity();JsonObject value;
    value.SetNamedValue(L"guid",JsonValue::CreateStringValue(guid(identity.guid)));
    value.SetNamedValue(L"name",JsonValue::CreateStringValue(identity.name));
    value.SetNamedValue(L"index",JsonValue::CreateNumberValue(identity.index));
    value.SetNamedValue(L"luid",JsonValue::CreateStringValue(std::to_wstring(identity.luid.Value)));
    const auto ip=[&](IN_ADDR address){wchar_t text[INET_ADDRSTRLEN]{};if(!InetNtopW(AF_INET,&address,text,INET_ADDRSTRLEN))fail("format owned address");return JsonValue::CreateStringValue(text);};
    value.SetNamedValue(L"address",ip(configuration.source));value.SetNamedValue(L"peer",ip(configuration.peer));
    value.SetNamedValue(L"mtu",JsonValue::CreateNumberValue(configuration.mtu));
    value.SetNamedValue(L"dns_id",configuration.dns?JsonValue::CreateStringValue(guid(configuration.dns->id)):JsonValue::CreateNullValue());
    return value;
}
}

int runWindowsNetworkControl(DWORD pid,std::uint64_t created,const GUID &session)
{
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    WindowsProcess caller(pid);
    if(caller.identity().created!=created || pid==GetCurrentProcessId())fail("control caller was replaced",ERROR_ACCESS_DENIED);
    HANDLE token=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))fail("read control elevation",GetLastError());
    TOKEN_ELEVATION elevation{};DWORD size=0;
    const auto queried=GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&size);
    CloseHandle(token);
    if(!queried || !elevation.TokenIsElevated)fail("control helper requires approved elevation",ERROR_ACCESS_DENIED);
    auto pipe=WindowsPacketPipe::listen(windowsControlPipeName(session),caller,WindowsNetworkContract::ControlTimeoutMs);
    const auto done=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if(!done)fail("create control peer lifetime",GetLastError());
    std::thread peer([&]{const HANDLE waits[]{done,caller.handle()};if(WaitForMultipleObjects(2,waits,FALSE,INFINITE)!=WAIT_OBJECT_0)pipe->close();});
    struct Join {HANDLE event;std::thread &thread;~Join(){SetEvent(event);thread.join();CloseHandle(event);}} join{done,peer};
    std::unique_ptr<WindowsHelperInstallation> installation;
    std::unique_ptr<WindowsNetworkSession> active;
    std::optional<WindowsNetworkConfiguration> configuration;
    bool first=true;
    for(;;){
        const auto command=request(receiveWindowsControlMessage(*pipe,first?WindowsNetworkContract::ControlTimeoutMs:INFINITE),session);
        first=false;
        auto reply=response(session,command);
        try{
            if(command.operation==L"close" && active && !active->isRestored())active->restore();
            if(!installation && command.operation!=L"close"){
                installation=WindowsHelperInstallation::prepare();
                ensureWindowsRecoveryService(*installation);
            }
            if(command.operation!=L"close"){
                WindowsNetworkRecovery recovery;
                if(command.operation==L"inspect"){
                    JsonArray owners;
                    for(const auto &id:recovery.owners()){
                        const auto record=recovery.read(id);
                        if(record.caller.sid!=caller.identity().sid)continue;
                        JsonObject owner;
                        owner.SetNamedValue(L"owner",JsonValue::CreateStringValue(guid(id)));
                        const auto phase=record.phase==WindowsRecoveryPhase::Restored?L"restored":record.phase==WindowsRecoveryPhase::Restoring?L"restoring":L"declared";
                        owner.SetNamedValue(L"phase",JsonValue::CreateStringValue(phase));
                        owner.SetNamedValue(L"live",JsonValue::CreateBooleanValue(record.helper.alive()));
                        owners.Append(owner);
                    }
                    reply.SetNamedValue(L"owners",owners);
                }else if(command.operation==L"recover"){
                    if(!recovery.restoreAbandoned(command.owner,caller.identity().sid))fail("network owner remains active",ERROR_BUSY);
                }else if(command.operation==L"acknowledge")recovery.acknowledge(command.owner,caller.identity().sid);
                else{
                    if(command.owner!=session)fail("network operation belongs to another session",ERROR_ACCESS_DENIED);
                    if(command.operation==L"apply"){
                        if(active)fail("network session cannot be reused",ERROR_ALREADY_EXISTS);
                        configuration=command.configuration;
                        active=WindowsNetworkSession::apply(installation->driver(),session,caller,*configuration,*pipe);
                    }else{
                        if(!active)fail("network session is not active",ERROR_NOT_FOUND);
                        if(command.operation==L"routes")active->reconcile(command.captures);
                        else if(command.operation==L"quiesce")active->quiesce();
                        else active->restore();
                    }
                }
                if(active && !active->isRestored())reply.SetNamedValue(L"device",metadata(*active,*configuration));
            }
        }catch(const std::system_error &error){
            std::cerr<<"native network "<<winrt::to_string(command.operation)<<": "<<error.what()<<'\n';
            reply.SetNamedValue(L"ok",JsonValue::CreateBooleanValue(false));
            reply.SetNamedValue(L"error",JsonValue::CreateNumberValue(error.code().value()));
        }
        sendWindowsControlMessage(*pipe,winrt::to_string(reply.Stringify()));
        if(command.operation==L"close"){
            unsigned char received=0;pipe->read(&received,1,WindowsNetworkContract::ControlTimeoutMs);
            if(received!=1)fail("unconfirmed control close");
            return 0;
        }
    }
}
