#include "infrastructure/tundevice/windows/recovery.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <iterator>
#include <algorithm>
#include <string>
#include <system_error>
#include <vector>

namespace {
constexpr ULONGLONG RemovalTimeoutMs=5000;
[[noreturn]] void fail(const char *stage,LONG error=GetLastError()) {throw std::system_error(static_cast<int>(error),std::system_category(),stage);}
std::wstring instance(const GUID &adapter)
{
    wchar_t text[39]{};
    if (adapter==GUID{} || !StringFromGUID2(adapter,text,39)) fail("empty recovery adapter",ERROR_INVALID_PARAMETER);
    // Wintun 0.14.1 uses the requested UUID for its software device instance.
    return std::wstring(L"SWD\\WINTUN\\")+text;
}
bool interfacePresent(const GUID &adapter)
{
    MIB_IF_TABLE2 *table=nullptr;
    const auto status=GetIfTable2Ex(MibIfTableNormalWithoutStatistics,&table);
    if (status!=NO_ERROR) fail("read recovery interface identities",status);
    bool present=false;std::vector<ULONGLONG> detached;
    for (ULONG i=0;i<table->NumEntries;++i) {
        const auto &row=table->Table[i];
        if(row.InterfaceGuid!=adapter)continue;
        if(row.OperStatus==IfOperStatusDown || row.OperStatus==IfOperStatusNotPresent)detached.push_back(row.InterfaceLuid.Value);
        else present=true;
    }
    FreeMibTable(table);
    if(present || detached.empty())return present;
    // NSI can retain an empty Down row after PnP removal; configured interfaces still block recovery.
    const auto owned=[&](NET_LUID luid){return std::find(detached.begin(),detached.end(),luid.Value)!=detached.end();};
    MIB_UNICASTIPADDRESS_TABLE *addresses=nullptr;
    const auto addressStatus=GetUnicastIpAddressTable(AF_UNSPEC,&addresses);
    if(addressStatus!=NO_ERROR)fail("read detached recovery addresses",addressStatus);
    for(ULONG i=0;i<addresses->NumEntries;++i)present=present || owned(addresses->Table[i].InterfaceLuid);
    FreeMibTable(addresses);
    if(present)return true;
    MIB_IPFORWARD_TABLE2 *routes=nullptr;
    const auto routeStatus=GetIpForwardTable2(AF_UNSPEC,&routes);
    if(routeStatus!=NO_ERROR)fail("read detached recovery routes",routeStatus);
    for(ULONG i=0;i<routes->NumEntries;++i)present=present || owned(routes->Table[i].InterfaceLuid);
    FreeMibTable(routes);return present;
}
struct Node {
    HDEVINFO devices=INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA device{sizeof(SP_DEVINFO_DATA)};
    bool found=false;
    explicit Node(const GUID &adapter)
    {
        const auto expected=instance(adapter);
        // Include phantom devices: a crash during Wintun allocation can leave a persistent node.
        devices=SetupDiGetClassDevsW(&GUID_DEVCLASS_NET,nullptr,nullptr,0);
        if (devices==INVALID_HANDLE_VALUE) fail("enumerate recovery PnP devices");
        try {
            for (DWORD i=0;;++i) {
                if (!SetupDiEnumDeviceInfo(devices,i,&device)) {if(GetLastError()==ERROR_NO_MORE_ITEMS)return;fail("read recovery PnP identity");}
                wchar_t identity[MAX_DEVICE_ID_LEN]{};
                if (!SetupDiGetDeviceInstanceIdW(devices,&device,identity,static_cast<DWORD>(std::size(identity)),nullptr)) fail("read recovery PnP instance");
                if (_wcsicmp(identity,expected.c_str())!=0) continue;
                const auto key=SetupDiOpenDevRegKey(devices,&device,DICS_FLAG_GLOBAL,0,DIREG_DRV,KEY_QUERY_VALUE);
                if (key==INVALID_HANDLE_VALUE) fail("open recovery adapter identity");
                wchar_t value[64]{};DWORD size=sizeof(value),type=0;
                const auto queried=RegQueryValueExW(key,L"NetCfgInstanceId",nullptr,&type,reinterpret_cast<BYTE *>(value),&size);RegCloseKey(key);
                GUID actual{};
                if (queried!=ERROR_SUCCESS || type!=REG_SZ || size>sizeof(value) || !size || size%sizeof(wchar_t) || value[size/sizeof(wchar_t)-1]!=0 || FAILED(CLSIDFromString(value,&actual)) || actual!=adapter)
                    fail("ambiguous recovery adapter identity",ERROR_INVALID_DATA);
                found=true;return;
            }
        } catch (...) {SetupDiDestroyDeviceInfoList(devices);devices=INVALID_HANDLE_VALUE;throw;}
    }
    ~Node(){if(devices!=INVALID_HANDLE_VALUE)SetupDiDestroyDeviceInfoList(devices);}
};
}

bool windowsAdapterPresent(const GUID &adapter)
{
    const Node node(adapter);
    return node.found || interfacePresent(adapter);
}
namespace {
void removeAdapter(const GUID &adapter,bool closed)
{
    const auto deadline=GetTickCount64()+RemovalTimeoutMs;
    const auto pending=[&]{
        if(GetTickCount64()>=deadline)fail("owned Wintun removal remains pending",ERROR_TIMEOUT);
        Sleep(50);
    };
    auto identity=instance(adapter);
    while(closed){
        DEVINST device=0;
        const auto status=CM_Locate_DevNodeW(&device,identity.data(),CM_LOCATE_DEVNODE_NORMAL);
        if(status!=CR_SUCCESS && status!=CR_NO_SUCH_DEVNODE)
            fail("read owned Wintun unplug state",CM_MapCrToWin32Err(status,ERROR_GEN_FAILURE));
        // SwDeviceClose unplugs asynchronously; uninstalling mid-unplug can set a pending-reboot veto.
        if(status==CR_NO_SUCH_DEVNODE && !interfacePresent(adapter))break;
        pending();
    }
    {
        Node node(adapter);
        if (node.found) {
            ULONG status=0,problem=0;
            const auto present=CM_Get_DevNode_Status(&status,&problem,node.device.DevInst,0);
            if(present==CR_NO_SUCH_DEVNODE){
                // Unplugged software nodes need persistent-state removal, without a second query/remove.
                const auto removed=CM_Uninstall_DevNode(node.device.DevInst,0);
                if(removed!=CR_SUCCESS)fail("remove owned Wintun persistent state",CM_MapCrToWin32Err(removed,ERROR_GEN_FAILURE));
            }else{
                if(present!=CR_SUCCESS)fail("read owned Wintun node status",CM_MapCrToWin32Err(present,ERROR_GEN_FAILURE));
                SP_REMOVEDEVICE_PARAMS removal{};
                removal.ClassInstallHeader.cbSize=sizeof(SP_CLASSINSTALL_HEADER);
                removal.ClassInstallHeader.InstallFunction=DIF_REMOVE;
                removal.Scope=DI_REMOVEDEVICE_GLOBAL;
                if (!SetupDiSetClassInstallParamsW(node.devices,&node.device,&removal.ClassInstallHeader,sizeof(removal))
                    || !SetupDiCallClassInstaller(DIF_REMOVE,node.devices,&node.device)) fail("remove abandoned owned Wintun node");
            }
        }
    }
    while(windowsAdapterPresent(adapter))pending();
}
}
void restoreWindowsAdapter(const GUID &adapter){removeAdapter(adapter,false);}
void finishWindowsAdapterClose(const GUID &adapter){removeAdapter(adapter,true);}
