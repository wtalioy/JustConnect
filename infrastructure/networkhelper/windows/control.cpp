#include "infrastructure/networkhelper/windows/control.h"
#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/networkhelper/windows/service.h"
#include "infrastructure/networkhelper/windows/recovery.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "windowsnetworkcontract.h"
#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <system_error>
#include <thread>

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
struct Request {std::wstring operation;GUID owner{};};
Request request(const std::string &message,const GUID &session) try
{
    const auto value=JsonObject::Parse(winrt::to_hstring(message));
    if(value.Size()!=4 || !value.HasKey(L"version") || !value.HasKey(L"session") || !value.HasKey(L"operation") || !value.HasKey(L"owner")
        || value.GetNamedNumber(L"version")!=WindowsNetworkContract::Protocol || identifier(value.GetNamedString(L"session"))!=session)
        fail("invalid control request envelope");
    const auto operation=value.GetNamedString(L"operation");
    Request result{{operation.data(),operation.size()}};
    const auto owner=value.GetNamedValue(L"owner");
    if(result.operation==L"inspect" || result.operation==L"close"){
        if(owner.ValueType()!=JsonValueType::Null)fail("unexpected control owner");
    }else if(result.operation==L"recover" || result.operation==L"acknowledge")result.owner=identifier(owner.GetString());
    else fail("unknown control operation");
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
    return value;
}
}

std::wstring windowsControlPipeName(const GUID &session)
{return std::wstring(WindowsNetworkContract::ControlPipePrefix)+guid(session);}

std::string receiveWindowsControlMessage(WindowsPacketPipe &pipe,DWORD timeout)
{
    unsigned char length[4]{};
    pipe.read(length,1,timeout);
    pipe.read(length+1,3,WindowsNetworkContract::ControlTimeoutMs);
    const auto size=(std::uint32_t(length[0])<<24)|(std::uint32_t(length[1])<<16)|(std::uint32_t(length[2])<<8)|length[3];
    if(!size || size>WindowsNetworkContract::MaxMessageBytes)fail("invalid control message size");
    std::string message(size,'\0');pipe.read(message.data(),size,WindowsNetworkContract::ControlTimeoutMs);
    return message;
}
void sendWindowsControlMessage(WindowsPacketPipe &pipe,const std::string &message)
{
    if(message.empty() || message.size()>WindowsNetworkContract::MaxMessageBytes)fail("invalid control reply size");
    const auto size=static_cast<std::uint32_t>(message.size());
    unsigned char length[]{static_cast<unsigned char>(size>>24),static_cast<unsigned char>(size>>16),static_cast<unsigned char>(size>>8),static_cast<unsigned char>(size)};
    pipe.write(length,4,WindowsNetworkContract::ControlTimeoutMs);
    pipe.write(message.data(),size,WindowsNetworkContract::ControlTimeoutMs);
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
    bool first=true;
    for(;;){
        const auto command=request(receiveWindowsControlMessage(*pipe,first?WindowsNetworkContract::ControlTimeoutMs:INFINITE),session);
        first=false;
        auto reply=response(session,command);
        try{
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
                }else recovery.acknowledge(command.owner,caller.identity().sid);
            }
        }catch(const std::system_error &error){
            reply.SetNamedValue(L"ok",JsonValue::CreateBooleanValue(false));
            reply.SetNamedValue(L"error",JsonValue::CreateNumberValue(error.code().value()));
        }
        sendWindowsControlMessage(*pipe,winrt::to_string(reply.Stringify()));
        if(command.operation==L"close")return 0;
    }
}
