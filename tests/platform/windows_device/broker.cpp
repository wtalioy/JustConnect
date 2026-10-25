#include "infrastructure/tundevice/windows/adapter.h"
#include <sddl.h>
#include <objbase.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <devguid.h>
#include <cstring>
#include <iostream>
#include <iterator>
#include <system_error>
#include <thread>
#include <vector>

namespace {
[[noreturn]] void fail(const char *stage, DWORD error = GetLastError())
{
    throw std::system_error(static_cast<int>(error),std::system_category(),stage);
}
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle() = default;
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
};

std::wstring instanceId(const GUID &owner)
{
    HDEVINFO devices = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET,nullptr,nullptr,DIGCF_PRESENT);
    if (devices == INVALID_HANDLE_VALUE) fail("enumerate network PnP");
    struct Cleanup { HDEVINFO value; ~Cleanup() { SetupDiDestroyDeviceInfoList(value); } } cleanup{devices};
    for (DWORD i=0;;++i) {
        SP_DEVINFO_DATA device{sizeof(SP_DEVINFO_DATA)};
        if (!SetupDiEnumDeviceInfo(devices,i,&device)) fail("locate owned PnP identity");
        HKEY key = SetupDiOpenDevRegKey(devices,&device,DICS_FLAG_GLOBAL,0,DIREG_DRV,KEY_QUERY_VALUE);
        if (key == INVALID_HANDLE_VALUE) continue;
        wchar_t value[64]{};
        DWORD size = sizeof(value), type = 0;
        const auto status = RegQueryValueExW(key,L"NetCfgInstanceId",nullptr,&type,reinterpret_cast<BYTE *>(value),&size);
        RegCloseKey(key);
        GUID id{};
        if (status != ERROR_SUCCESS || type != REG_SZ || size > sizeof(value) || value[std::size(value)-1] != 0
            || FAILED(CLSIDFromString(value,&id)) || id != owner) continue;
        wchar_t identity[MAX_DEVICE_ID_LEN]{};
        if (!SetupDiGetDeviceInstanceIdW(devices,&device,identity,static_cast<DWORD>(std::size(identity)),nullptr)) fail("read owned PnP identity");
        return identity;
    }
}

std::string json(const std::wstring &value)
{
    std::string result = "\"";
    for (const auto c:value) {
        if (c > 127 || c < 32) fail("unexpected fixture identity",ERROR_INVALID_DATA);
        if (c == '\\' || c == '"') result += '\\';
        result += static_cast<char>(c);
    }
    return result+'"';
}
void notice(const char *stage,const WindowsTunIdentity &device,const std::wstring &instance)
{
    std::cout << "{\"Stage\":\"" << stage << "\",\"Device\":{\"Name\":" << json(device.name)
        << ",\"Index\":" << device.index << ",\"LUID\":" << device.luid.Value
        << ",\"InstanceID\":" << json(instance) << "}}\n" << std::flush;
    if (!std::cout) fail("publish owned fixture identity",ERROR_WRITE_FAULT);
}

HANDLE ordinaryToken()
{
    Handle original, token;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_DEFAULT,&original.value)) fail("open fixture token");
    alignas(SID) unsigned char admin[SECURITY_MAX_SID_SIZE], medium[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(admin);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admin,&size)) fail("administrator SID");
    SID_AND_ATTRIBUTES denied{admin,0};
    if (!CreateRestrictedToken(original.value,DISABLE_MAX_PRIVILEGE|LUA_TOKEN,1,&denied,0,nullptr,0,nullptr,&token.value)) fail("restrict fixture token");
    size = sizeof(medium);
    if (!CreateWellKnownSid(WinMediumLabelSid,nullptr,medium,&size)) fail("medium SID");
    TOKEN_MANDATORY_LABEL label{{medium,SE_GROUP_INTEGRITY}};
    if (!SetTokenInformation(token.value,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(medium))) fail("set medium integrity");
    GetTokenInformation(token.value,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> data(size);
    if (!GetTokenInformation(token.value,TokenUser,data.data(),size,&size)) fail("read ordinary user SID");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid,&sid)) fail("format ordinary SID");
    const std::wstring sddl = std::wstring(L"D:P(A;;GA;;;SY)(A;;GA;;;")+sid+L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) fail("ordinary default DACL");
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    const bool read = GetSecurityDescriptorDacl(descriptor,&present,&acl,&defaulted) != FALSE;
    TOKEN_DEFAULT_DACL defaults{acl};
    const bool applied = read && present && SetTokenInformation(token.value,TokenDefaultDacl,&defaults,sizeof(defaults));
    const auto error = GetLastError();
    LocalFree(descriptor);
    if (!applied) fail("set ordinary process object DACL",error);
    HANDLE result = token.value;
    token.value = nullptr;
    return result;
}

void transfer(HANDLE pipe,void *data,DWORD size,bool write)
{
    auto *bytes = static_cast<unsigned char *>(data);
    while (size) {
        DWORD count = 0;
        const BOOL success = write ? WriteFile(pipe,bytes,size,&count,nullptr) : ReadFile(pipe,bytes,size,&count,nullptr);
        if (!success) fail("fixture pipe transfer");
        if (!count) fail("short fixture pipe",ERROR_BROKEN_PIPE);
        bytes += count;
        size -= count;
    }
}

bool validPacket(const std::vector<unsigned char> &packet,bool reply)
{
    if (packet.size()!=32 || packet[0]!=0x45 || packet[9]!=17 || packet[2]!=0 || packet[3]!=32
        || ((packet[6]<<8|packet[7])&0x3fff)!=0 || packet[24]!=0 || packet[25]!=12) return false;
    const unsigned char local[]{192,0,2,1}, peer[]{192,0,2,2};
    const auto port = reply ? 20 : 22;
    return std::memcmp(packet.data()+12,reply?peer:local,4)==0 && std::memcmp(packet.data()+16,reply?local:peer,4)==0
        && (packet[port]<<8|packet[port+1])==43877;
}

int exchange(WindowsTunDevice &device,const std::wstring &client,const std::wstring &mode)
{
    Handle token, childIn, childOut, input, output, error, process, thread, done;
    token.value = ordinaryToken();
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),nullptr,TRUE};
    if (!CreatePipe(&childIn.value,&input.value,&attributes,0) || !CreatePipe(&output.value,&childOut.value,&attributes,0)) fail("create fixture IPC");
    if (!SetHandleInformation(input.value,HANDLE_FLAG_INHERIT,0) || !SetHandleInformation(output.value,HANDLE_FLAG_INHERIT,0)) fail("limit fixture handle inheritance");
    if (!DuplicateHandle(GetCurrentProcess(),GetStdHandle(STD_ERROR_HANDLE),GetCurrentProcess(),&error.value,0,TRUE,DUPLICATE_SAME_ACCESS)) fail("retain fixture stderr");
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = childIn.value;
    startup.hStdOutput = childOut.value;
    startup.hStdError = error.value;
    std::wstring command = L"\""+client+L"\" --client "+(mode==L"connected"?L"roundtrip":mode);
    PROCESS_INFORMATION info{};
    if (!CreateProcessAsUserW(token.value,nullptr,command.data(),nullptr,nullptr,TRUE,0,nullptr,nullptr,&startup,&info)) fail("start ordinary packet consumer");
    process.value = info.hProcess;
    thread.value = info.hThread;
    CloseHandle(childIn.value); childIn.value=nullptr;
    CloseHandle(childOut.value); childOut.value=nullptr;
    struct ChildCleanup { HANDLE process; ~ChildCleanup() { if (WaitForSingleObject(process,0)==WAIT_TIMEOUT) { TerminateProcess(process,1); WaitForSingleObject(process,5000); } } } child{process.value};
    done.value = CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if (!done.value) fail("create fixture deadline");
    std::thread watchdog([&] { if (WaitForSingleObject(done.value,8000)==WAIT_TIMEOUT) device.close(); });
    struct Join { HANDLE done; std::thread &worker; ~Join() { SetEvent(done); worker.join(); } } join{done.value,watchdog};
    std::vector<unsigned char> packet(1400);
    do { packet.resize(1400); packet.resize(device.read(packet.data(),packet.size())); } while (!validPacket(packet,false));
    unsigned char length[]{0,0,0,static_cast<unsigned char>(packet.size())};
    transfer(input.value,length,4,true);
    transfer(input.value,packet.data(),static_cast<DWORD>(packet.size()),true);
    CloseHandle(input.value);input.value=nullptr;
    transfer(output.value,length,4,false);
    const auto size=(DWORD(length[0])<<24)|(DWORD(length[1])<<16)|(DWORD(length[2])<<8)|length[3];
    if (size<20 || size>65535) return 23;
    std::vector<unsigned char> response(size);
    transfer(output.value,response.data(),size,false);
    if (!validPacket(response,true) || std::memcmp(response.data()+28,"pong",4)!=0
        || response[22]!=packet[20] || response[23]!=packet[21]) return 23;
    device.write(response.data(),response.size());
    if (WaitForSingleObject(process.value,12000)!=WAIT_OBJECT_0) fail("ordinary consumer timeout",ERROR_TIMEOUT);
    DWORD code=1;
    if (!GetExitCodeProcess(process.value,&code)) fail("ordinary consumer exit");
    return static_cast<int>(code);
}
}

int wmain(int argc,wchar_t **argv) try
{
    wchar_t guarded[8]{};
    if (GetEnvironmentVariableW(L"GITHUB_ACTIONS",guarded,static_cast<DWORD>(std::size(guarded))) != 4
        || std::wstring(guarded) != L"true" || argc != 6 || std::wstring(argv[1]) != L"--broker")
        fail("device fixture requires the disposable runner",ERROR_ACCESS_DENIED);
    Handle ownToken;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&ownToken.value)) fail("read fixture elevation");
    TOKEN_ELEVATION elevation{};
    DWORD tokenSize=0;
    if (!GetTokenInformation(ownToken.value,TokenElevation,&elevation,sizeof(elevation),&tokenSize) || !elevation.TokenIsElevated)
        fail("device fixture requires an elevated disposable runner",ERROR_ACCESS_DENIED);
    const std::wstring name=argv[3],mode=argv[4];
    if (name.rfind(L"JustConnect ",0)!=0 || (mode!=L"connected" && mode!=L"roundtrip" && mode!=L"oversized" && mode!=L"crash" && mode!=L"setup-failure"))
        fail("invalid native fixture request",ERROR_INVALID_PARAMETER);
    GUID owner{};
    if (FAILED(CLSIDFromString(name.substr(12).c_str(),&owner))) fail("invalid fixture owner",ERROR_INVALID_PARAMETER);
    IN_ADDR source{},peer{};
    source.S_un.S_addr=htonl(0xc0000201);
    peer.S_un.S_addr=htonl(0xc0000202);
    std::wstring instance;
    auto device=WindowsTunDevice::create(argv[2],owner,source,peer,1400,{},[&](const auto &identity) {
        if (identity.name!=name) fail("owned fixture name changed",ERROR_INVALID_DATA);
        instance=instanceId(owner);
        notice("allocated",identity,instance);
    });
    if (instanceId(owner)!=instance) fail("configured PnP identity changed",ERROR_INVALID_DATA);
    if (mode==L"setup-failure") {
        MIB_IPFORWARD_TABLE2 *routes=nullptr;
        const auto status=GetIpForwardTable2(AF_INET,&routes);
        if (status!=NO_ERROR) fail("read configured fixture routes",status);
        bool present=false;
        for (ULONG i=0;i<routes->NumEntries;++i) present=present || routes->Table[i].InterfaceIndex==device->identity().index;
        FreeMibTable(routes);
        if (!present) fail("setup failure lacked actual owned routes",ERROR_INVALID_DATA);
        return 24;
    }
    notice("configured",device->identity(),instance);
    if (mode==L"crash") { Sleep(INFINITE);return 1; }
    return exchange(*device,argv[5],mode);
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
