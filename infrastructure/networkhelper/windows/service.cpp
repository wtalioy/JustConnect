#include "infrastructure/networkhelper/windows/service.h"
#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/networkhelper/windows/recovery.h"
#include "windowsnetworkcontract.h"
#include <sddl.h>
#include <winrt/base.h>
#include <system_error>
#include <vector>

namespace {
constexpr DWORD RecoveryIntervalMs=1000,StartupTimeoutMs=30000,FailureResetSeconds=86400;
[[noreturn]] void fail(const char *stage,LONG error=GetLastError()){throw std::system_error(static_cast<int>(error),std::system_category(),stage);}
struct Service {SC_HANDLE value=nullptr;~Service(){if(value)CloseServiceHandle(value);}};
struct Security {PSECURITY_DESCRIPTOR value=nullptr;~Security(){if(value)LocalFree(value);}};
HANDLE stopEvent=nullptr;
SERVICE_STATUS_HANDLE statusHandle=nullptr;
bool trusted(PSID sid){return sid && (IsWellKnownSid(sid,WinLocalSystemSid)||IsWellKnownSid(sid,WinBuiltinAdministratorsSid));}
void validateSecurity(SC_HANDLE service)
{
    DWORD size=0;
    QueryServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,0,&size);
    if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER)fail("size recovery service security");
    std::vector<BYTE> data(size);
    const auto descriptor=reinterpret_cast<PSECURITY_DESCRIPTOR>(data.data());
    if(!QueryServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,descriptor,size,&size))fail("read recovery service security");
    PSID owner=nullptr;PACL acl=nullptr;BOOL defaulted=FALSE,present=FALSE;
    if(!GetSecurityDescriptorOwner(descriptor,&owner,&defaulted)||!trusted(owner)||!GetSecurityDescriptorDacl(descriptor,&present,&acl,&defaulted)||!present||!acl||!IsValidAcl(acl))fail("untrusted recovery service owner",ERROR_ACCESS_DENIED);
    constexpr DWORD controls=SERVICE_CHANGE_CONFIG|SERVICE_START|SERVICE_STOP|SERVICE_PAUSE_CONTINUE|SERVICE_USER_DEFINED_CONTROL|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
    for(DWORD i=0;i<acl->AceCount;++i){
        void *value=nullptr;if(!GetAce(acl,i,&value))fail("read recovery service ACE");
        const auto ace=static_cast<ACCESS_ALLOWED_ACE *>(value);
        if((ace->Header.AceFlags&INHERIT_ONLY_ACE)||ace->Header.AceType==ACCESS_DENIED_ACE_TYPE)continue;
        if(ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE||((ace->Mask&controls)&&!trusted(&ace->SidStart)))fail("untrusted recovery service control permission",ERROR_ACCESS_DENIED);
    }
}
std::vector<BYTE> configuration(SC_HANDLE service,DWORD level)
{
    DWORD size=0;QueryServiceConfig2W(service,level,nullptr,0,&size);
    if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER)fail("size recovery service settings");
    std::vector<BYTE> data(size);
    if(!QueryServiceConfig2W(service,level,data.data(),size,&size))fail("read recovery service settings");
    return data;
}
void validate(SC_HANDLE service,const std::wstring &command)
{
    validateSecurity(service);
    DWORD size=0;QueryServiceConfigW(service,nullptr,0,&size);
    if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER)fail("size recovery service configuration");
    std::vector<BYTE> data(size);
    const auto value=reinterpret_cast<QUERY_SERVICE_CONFIGW *>(data.data());
    if(!QueryServiceConfigW(service,value,size,&size))fail("read recovery service configuration");
    if(value->dwServiceType!=SERVICE_WIN32_OWN_PROCESS||value->dwStartType!=SERVICE_AUTO_START
        ||!value->lpBinaryPathName||command!=value->lpBinaryPathName||!value->lpServiceStartName||_wcsicmp(value->lpServiceStartName,L"LocalSystem")
        ||(value->lpDependencies&&*value->lpDependencies))fail("foreign recovery service configuration",ERROR_ACCESS_DENIED);
    const auto actions=configuration(service,SERVICE_CONFIG_FAILURE_ACTIONS);
    const auto recovery=reinterpret_cast<const SERVICE_FAILURE_ACTIONSW *>(actions.data());
    if((recovery->lpCommand&&*recovery->lpCommand)||(recovery->lpRebootMsg&&*recovery->lpRebootMsg)||recovery->cActions!=1||!recovery->lpsaActions
        ||recovery->lpsaActions[0].Type!=SC_ACTION_RESTART||recovery->lpsaActions[0].Delay!=RecoveryIntervalMs)
        fail("foreign recovery service failure command",ERROR_ACCESS_DENIED);
    const auto flags=configuration(service,SERVICE_CONFIG_FAILURE_ACTIONS_FLAG);
    if(!reinterpret_cast<const SERVICE_FAILURE_ACTIONS_FLAG *>(flags.data())->fFailureActionsOnNonCrashFailures)fail("disabled recovery service restart",ERROR_ACCESS_DENIED);
}
void status(DWORD state,DWORD error=NO_ERROR)
{
    SERVICE_STATUS value{};value.dwServiceType=SERVICE_WIN32_OWN_PROCESS;value.dwCurrentState=state;value.dwWin32ExitCode=error;
    if(state==SERVICE_RUNNING)value.dwControlsAccepted=SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
    if(state==SERVICE_START_PENDING||state==SERVICE_STOP_PENDING){value.dwCheckPoint=1;value.dwWaitHint=StartupTimeoutMs;}
    if(!SetServiceStatus(statusHandle,&value))fail("publish recovery service state");
}
DWORD WINAPI control(DWORD code,DWORD,void *,void *)
{
    if(code==SERVICE_CONTROL_STOP||code==SERVICE_CONTROL_SHUTDOWN){return SetEvent(stopEvent)?NO_ERROR:GetLastError();}
    return code==SERVICE_CONTROL_INTERROGATE?NO_ERROR:ERROR_CALL_NOT_IMPLEMENTED;
}
void WINAPI serviceMain(DWORD,wchar_t **)
{
    statusHandle=RegisterServiceCtrlHandlerExW(WindowsNetworkContract::Service,control,nullptr);
    if(!statusHandle)return;
    DWORD error=ERROR_GEN_FAILURE;
    try{
        status(SERVICE_START_PENDING);
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        WindowsProcess current(GetCurrentProcessId());
        Security sid;
        if(!ConvertStringSidToSidW(current.identity().sid.c_str(),reinterpret_cast<PSID *>(&sid.value))||!IsWellKnownSid(sid.value,WinLocalSystemSid))fail("recovery service requires LocalSystem",ERROR_ACCESS_DENIED);
        auto installation=WindowsHelperInstallation::openInstalled();
        WindowsNetworkRecovery recovery;
        status(SERVICE_RUNNING);
        for(;;){
            for(const auto &owner:recovery.owners()){
                try{recovery.restoreAbandoned(owner);}
                catch(const std::exception &failure){OutputDebugStringA(failure.what());}
            }
            const auto state=WaitForSingleObject(stopEvent,RecoveryIntervalMs);
            if(state==WAIT_OBJECT_0)break;
            if(state!=WAIT_TIMEOUT)fail("wait for native service cancellation");
        }
        status(SERVICE_STOP_PENDING);status(SERVICE_STOPPED);return;
    }catch(const std::system_error &failure){error=static_cast<DWORD>(failure.code().value());OutputDebugStringA(failure.what());}
    catch(...){OutputDebugStringA("native recovery service initialization failed");}
    SERVICE_STATUS stopped{};stopped.dwServiceType=SERVICE_WIN32_OWN_PROCESS;stopped.dwCurrentState=SERVICE_STOPPED;stopped.dwWin32ExitCode=error;
    SetServiceStatus(statusHandle,&stopped);
}
}

void ensureWindowsRecoveryService(const WindowsHelperInstallation &installation)
{
    const auto command=L"\""+installation.image()+L"\" --service";
    Service manager;manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE);
    if(!manager.value)fail("open native service manager");
    Service service;service.value=OpenServiceW(manager.value,WindowsNetworkContract::Service,SERVICE_ALL_ACCESS);
    struct Created {
        SC_HANDLE value=nullptr;
        ~Created(){if(value){SERVICE_STATUS state{};ControlService(value,SERVICE_CONTROL_STOP,&state);DeleteService(value);}}
    } created;
    if(!service.value){
        if(GetLastError()!=ERROR_SERVICE_DOES_NOT_EXIST)fail("open recovery service");
        service.value=CreateServiceW(manager.value,WindowsNetworkContract::Service,WindowsNetworkContract::Service,SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,command.c_str(),nullptr,nullptr,nullptr,nullptr,nullptr);
        if(!service.value)fail("install native recovery service");
        created.value=service.value;
        Security security;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCRC;;;BU)",SDDL_REVISION_1,&security.value,nullptr)
            ||!SetServiceObjectSecurity(service.value,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,security.value))fail("protect recovery service control");
        SC_ACTION action{SC_ACTION_RESTART,RecoveryIntervalMs};
        SERVICE_FAILURE_ACTIONSW actions{FailureResetSeconds,nullptr,nullptr,1,&action};
        SERVICE_FAILURE_ACTIONS_FLAG flags{TRUE};
        if(!ChangeServiceConfig2W(service.value,SERVICE_CONFIG_FAILURE_ACTIONS,&actions)||!ChangeServiceConfig2W(service.value,SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,&flags))fail("enable independent service restart");
    }
    // shortcut: a different installed image needs explicit replacement after recovery; add upgrade handling before a production updater.
    validate(service.value,command);
    if(!StartServiceW(service.value,0,nullptr)&&GetLastError()!=ERROR_SERVICE_ALREADY_RUNNING)fail("start independent recovery service");
    const auto deadline=GetTickCount64()+StartupTimeoutMs;
    for(;;){
        SERVICE_STATUS_PROCESS value{};DWORD size=0;
        if(!QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE *>(&value),sizeof(value),&size))fail("read recovery service readiness");
        if(value.dwCurrentState==SERVICE_RUNNING){created.value=nullptr;return;}
        if(value.dwCurrentState!=SERVICE_START_PENDING)fail("recovery service failed to initialize",value.dwWin32ExitCode?value.dwWin32ExitCode:ERROR_SERVICE_NOT_ACTIVE);
        if(GetTickCount64()>=deadline)fail("recovery service startup deadline",ERROR_TIMEOUT);
        Sleep(50);
    }
}
int runWindowsRecoveryService()
{
    stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if(!stopEvent)fail("create native service cancellation event");
    SERVICE_TABLE_ENTRYW table[]{{const_cast<wchar_t *>(WindowsNetworkContract::Service),serviceMain},{nullptr,nullptr}};
    const auto result=StartServiceCtrlDispatcherW(table);const auto error=GetLastError();
    CloseHandle(stopEvent);stopEvent=nullptr;
    if(!result)fail("enter native service dispatcher",error);
    return 0;
}
