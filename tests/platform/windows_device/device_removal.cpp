#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <iterator>
#include <string>
#include <system_error>
#include <iostream>
#include <cstring>
#include <cwchar>

namespace Fixture {
GUID owner{0x12345678,0x1234,0x5678,{1,2,3,4,5,6,7,8}};
ULONGLONG now=0,detachedAt=100,interfaceGoneAt=150;
bool node=true,veto=false,retainNode=false,foreign=false,abandoned=false;
CONFIGRET locateStatus=CR_SUCCESS;
int removals=0;
void check(bool value,const char *why){if(!value)throw std::runtime_error(why);}
std::wstring id(){wchar_t value[39]{};StringFromGUID2(owner,value,39);return std::wstring(L"SWD\\WINTUN\\")+value;}
HDEVINFO devices(){return reinterpret_cast<HDEVINFO>(1);}
BOOL enumerate(HDEVINFO,DWORD index,SP_DEVINFO_DATA *device){
    if(index>1 || (index==1 && !node)){SetLastError(ERROR_NO_MORE_ITEMS);return FALSE;}
    device->DevInst=index+1;return TRUE;
}
BOOL identity(HDEVINFO,SP_DEVINFO_DATA *device,PWSTR value,DWORD,DWORD *){
    const auto name=device->DevInst==1?L"SWD\\WINTUN\\{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}":id();
    std::wcscpy(value,name.c_str());return TRUE;
}
HKEY key(HDEVINFO,SP_DEVINFO_DATA *device,DWORD,DWORD,DWORD,REGSAM){
    check(device->DevInst==2,"foreign device registry was opened");return reinterpret_cast<HKEY>(1);
}
LSTATUS query(HKEY,LPCWSTR,LPDWORD,LPDWORD type,LPBYTE data,LPDWORD size){
    wchar_t value[39]{};auto actual=owner;if(foreign)++actual.Data1;StringFromGUID2(actual,value,39);
    *type=REG_SZ;*size=sizeof(value);std::memcpy(data,value,sizeof(value));return ERROR_SUCCESS;
}
DWORD interfaces(MIB_IF_TABLE2 **out){
    static MIB_IF_TABLE2 table{};table.NumEntries=now<interfaceGoneAt?1:0;table.Table[0].InterfaceGuid=owner;*out=&table;return NO_ERROR;
}
CONFIGRET locate(PDEVINST,PWSTR name,ULONG flags){
    check(name==id() && flags==CM_LOCATE_DEVNODE_NORMAL,"detach query changed device identity or cancelled removal");
    return locateStatus!=CR_SUCCESS?locateStatus:now<detachedAt?CR_SUCCESS:CR_NO_SUCH_DEVNODE;
}
BOOL parameters(HDEVINFO,SP_DEVINFO_DATA *device,SP_CLASSINSTALL_HEADER *header,DWORD){
    auto *value=reinterpret_cast<SP_REMOVEDEVICE_PARAMS *>(header);
    check(device->DevInst==2 && header->InstallFunction==DIF_REMOVE && value->Scope==DI_REMOVEDEVICE_GLOBAL,"uninstall crossed owned identity");return TRUE;
}
BOOL uninstall(DI_FUNCTION,HDEVINFO,SP_DEVINFO_DATA *){
    ++removals;
    // Matches the observed PNP_VetoAlreadyRemoved race: success can leave a pending-reboot node.
    if(!abandoned && (now<detachedAt || now<interfaceGoneAt))veto=true;
    if(abandoned)detachedAt=interfaceGoneAt=now;
    if(!veto && !retainNode)node=false;
    return TRUE;
}
void reset(){now=0;detachedAt=100;interfaceGoneAt=150;node=true;veto=retainNode=foreign=abandoned=false;locateStatus=CR_SUCCESS;removals=0;}
}

// Substitute native calls only in this test translation unit; no host device/registry mutation.
#define SetupDiGetClassDevsW(...) Fixture::devices()
#define SetupDiEnumDeviceInfo Fixture::enumerate
#define SetupDiGetDeviceInstanceIdW Fixture::identity
#define SetupDiOpenDevRegKey Fixture::key
#define SetupDiDestroyDeviceInfoList(...) TRUE
#define RegQueryValueExW Fixture::query
#define RegCloseKey(...) ERROR_SUCCESS
#define GetIfTable2Ex(level,table) Fixture::interfaces(table)
#define FreeMibTable(...) ((void)0)
#define CM_Locate_DevNodeW Fixture::locate
#define SetupDiSetClassInstallParamsW Fixture::parameters
#define SetupDiCallClassInstaller Fixture::uninstall
#define GetTickCount64() Fixture::now
#define Sleep(ms) (Fixture::now+=(ms))
#include "infrastructure/tundevice/windows/recovery.cpp"

int main() try
{
    using namespace Fixture;
    reset();finishWindowsAdapterClose(owner);
    check(!node && !veto && removals==1 && now==150,"uninstall raced asynchronous software-device unplug");
    reset();detachedAt=interfaceGoneAt=0;finishWindowsAdapterClose(owner);
    check(!node && removals==1 && now==0,"abandoned phantom device was not cleaned immediately");
    reset();node=false;finishWindowsAdapterClose(owner);
    check(removals==0 && now==150,"interface-only teardown was not confirmed");
    for(int scenario=0;scenario<4;++scenario){
        reset();
        if(scenario==0)detachedAt=10000;
        if(scenario==1)retainNode=true;
        if(scenario==2)foreign=true;
        if(scenario==3)locateStatus=CR_ACCESS_DENIED;
        bool failed=false;
        try{finishWindowsAdapterClose(owner);}catch(const std::system_error &error){
            failed=true;
            check(error.code().value()==(scenario<2?ERROR_TIMEOUT:scenario==2?ERROR_INVALID_DATA:ERROR_ACCESS_DENIED),"removal lost native failure classification");
        }
        check(failed && (scenario<2?now==5000:removals==0),"removal published success or renewed its deadline");
        if(scenario==0)check(removals==0,"unplug timeout still tried uninstalling a present device");
    }
    reset();abandoned=true;detachedAt=interfaceGoneAt=10000;restoreWindowsAdapter(owner);
    check(removals==1 && !node && now==0,"dead helper recovery waited for a missing SDK close");
    std::cout<<"PASS: live close waits for unplug, dead helper uninstalls directly; phantom/interface-only cleanup, one deadline, foreign identity and read failures preserved\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
