#include "infrastructure/networkjournal/windows/registry.h"
#include "windowsnetworkcontract.h"
#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <iterator>
#include <system_error>

namespace {
[[noreturn]] void fail(const char *stage,LONG error = GetLastError())
{
    throw std::system_error(static_cast<int>(error),std::system_category(),stage);
}
void checked(LONG status,const char *stage) { if (status!=ERROR_SUCCESS) fail(stage,status); }
struct Local {
    PSECURITY_DESCRIPTOR value = nullptr;
    ~Local() { if (value) LocalFree(value); }
};
std::wstring name(const GUID &owner)
{
    if (owner==GUID{}) fail("empty journal owner",ERROR_INVALID_PARAMETER);
    wchar_t value[39]{};
    if (!StringFromGUID2(owner,value,static_cast<int>(std::size(value)))) fail("format journal owner",ERROR_INVALID_DATA);
    return value;
}
bool validJson(const std::string &data)
{
    if (data.empty() || data.size()>WindowsNetworkContract::MaxRecordBytes) return false;
    try {
        winrt::Windows::Data::Json::JsonValue::Parse(winrt::to_hstring(data));
        return true;
    } catch (const winrt::hresult_error &) { return false; }
}
}

void WindowsRegistryJournal::validateSecurity(PSECURITY_DESCRIPTOR descriptor)
{
    PSID owner = nullptr;
    BOOL defaulted = FALSE,present = FALSE;
    PACL acl = nullptr;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    if (!descriptor || !IsValidSecurityDescriptor(descriptor)
        || !GetSecurityDescriptorOwner(descriptor,&owner,&defaulted) || !owner
        || (!IsWellKnownSid(owner,WinBuiltinAdministratorsSid) && !IsWellKnownSid(owner,WinLocalSystemSid))
        || !GetSecurityDescriptorControl(descriptor,&control,&revision) || !(control&SE_DACL_PROTECTED)
        || !GetSecurityDescriptorDacl(descriptor,&present,&acl,&defaulted) || !present || !acl || !IsValidAcl(acl) || acl->AceCount!=2)
        fail("untrusted machine journal owner or DACL",ERROR_ACCESS_DENIED);
    bool system=false,admin=false;
    for (DWORD i=0;i<acl->AceCount;++i) {
        void *value = nullptr;
        if (!GetAce(acl,i,&value)) fail("read journal ACE");
        const auto ace=static_cast<const ACCESS_ALLOWED_ACE *>(value);
        if (ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE || (ace->Header.AceFlags&~(OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE)) || ace->Mask!=KEY_ALL_ACCESS)
            fail("untrusted machine journal ACE",ERROR_ACCESS_DENIED);
        const auto sid=const_cast<DWORD *>(&ace->SidStart);
        if (IsWellKnownSid(sid,WinLocalSystemSid) && !system) system=true;
        else if (IsWellKnownSid(sid,WinBuiltinAdministratorsSid) && !admin) admin=true;
        else fail("untrusted machine journal trustee",ERROR_ACCESS_DENIED);
    }
    if (!system || !admin) fail("incomplete machine journal DACL",ERROR_ACCESS_DENIED);
}

void WindowsRegistryJournal::protectedKey() const
{
    if (!key) fail("closed machine journal",ERROR_INVALID_HANDLE);
    Local security;
    checked(GetSecurityInfo(key,SE_REGISTRY_KEY,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        nullptr,nullptr,nullptr,nullptr,&security.value),"read machine journal security");
    validateSecurity(security.value);
}

WindowsRegistryJournal::WindowsRegistryJournal()
{
    constexpr auto access=KEY_ALL_ACCESS|KEY_WOW64_64KEY;
    auto status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,WindowsNetworkContract::StateRegistry,REG_OPTION_OPEN_LINK,access,&key);
    if (status==ERROR_FILE_NOT_FOUND) {
        Local security;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)",SDDL_REVISION_1,&security.value,nullptr)) fail("create journal security");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes),security.value,FALSE};
        status=RegCreateKeyExW(HKEY_LOCAL_MACHINE,WindowsNetworkContract::StateRegistry,0,nullptr,0,access,&attributes,&key,nullptr);
    }
    checked(status,"open protected machine journal");
    try {
        protectedKey();
        if (RegQueryValueExW(key,L"SymbolicLinkValue",nullptr,nullptr,nullptr,nullptr)!=ERROR_FILE_NOT_FOUND)
            fail("refuse linked machine journal",ERROR_ACCESS_DENIED);
    } catch (...) { RegCloseKey(key);key=nullptr;throw; }
}
WindowsRegistryJournal::~WindowsRegistryJournal() { if (key) RegCloseKey(key); }
void WindowsRegistryJournal::close()
{
    std::lock_guard<std::mutex> guard(lock);
    if (!key) return;
    const auto saved=key;
    key=nullptr;
    checked(RegCloseKey(saved),"close machine journal");
}

std::string WindowsRegistryJournal::read(const GUID &owner)
{
    const auto value=name(owner);
    std::lock_guard<std::mutex> guard(lock);
    protectedKey();
    DWORD size=0,type=0;
    checked(RegQueryValueExW(key,value.c_str(),nullptr,&type,nullptr,&size),"size machine checkpoint");
    if (type!=REG_BINARY || !size || size>WindowsNetworkContract::MaxRecordBytes) fail("invalid machine checkpoint",ERROR_INVALID_DATA);
    std::string result(size,'\0');
    const auto expected=size;
    checked(RegQueryValueExW(key,value.c_str(),nullptr,&type,reinterpret_cast<BYTE *>(result.data()),&size),"read machine checkpoint");
    if (type!=REG_BINARY || size!=expected || !validJson(result)) fail("damaged machine checkpoint",ERROR_INVALID_DATA);
    return result;
}
void WindowsRegistryJournal::write(const GUID &owner,const std::string &data)
{
    const auto value=name(owner);
    if (!validJson(data)) fail("invalid machine checkpoint",ERROR_INVALID_PARAMETER);
    std::lock_guard<std::mutex> guard(lock);
    protectedKey();
    checked(RegSetValueExW(key,value.c_str(),0,REG_BINARY,reinterpret_cast<const BYTE *>(data.data()),static_cast<DWORD>(data.size())),"store atomic machine checkpoint");
    checked(RegFlushKey(key),"flush machine checkpoint");
}
void WindowsRegistryJournal::remove(const GUID &owner)
{
    const auto value=name(owner);
    std::lock_guard<std::mutex> guard(lock);
    protectedKey();
    const auto status=RegDeleteValueW(key,value.c_str());
    if (status!=ERROR_FILE_NOT_FOUND) checked(status,"remove machine checkpoint");
    checked(RegFlushKey(key),"flush removed machine checkpoint");
}
std::vector<GUID> WindowsRegistryJournal::owners()
{
    std::lock_guard<std::mutex> guard(lock);
    protectedKey();
    std::vector<GUID> result;
    for (DWORD index=0;;++index) {
        wchar_t value[40]{};
        DWORD size=static_cast<DWORD>(std::size(value));
        const auto status=RegEnumValueW(key,index,value,&size,nullptr,nullptr,nullptr,nullptr);
        if (status==ERROR_NO_MORE_ITEMS) return result;
        checked(status,"enumerate machine checkpoints");
        GUID owner{};
        if (FAILED(CLSIDFromString(value,&owner)) || owner==GUID{} || name(owner)!=std::wstring(value,size))
            fail("invalid machine checkpoint identity",ERROR_INVALID_DATA);
        result.push_back(owner);
    }
}
