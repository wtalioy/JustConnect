#include "infrastructure/dns/windows/nrpt.h"
#include "infrastructure/dns/domainlimits.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <aclapi.h>
#include <sddl.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>
#include <iterator>
#include <set>
#include <system_error>

namespace {
[[noreturn]] void fail(const char *stage,LONG error=GetLastError())
{
    throw std::system_error(static_cast<int>(error),std::system_category(),stage);
}
void checked(LONG status,const char *stage) { if (status!=ERROR_SUCCESS) fail(stage,status); }
struct Key { HKEY value=nullptr; ~Key() { if(value) RegCloseKey(value); } };
struct Security { PSECURITY_DESCRIPTOR value=nullptr; ~Security() { if(value) LocalFree(value); } };
std::wstring guid(const GUID &value)
{
    wchar_t text[39]{};
    if (value==GUID{} || !StringFromGUID2(value,text,static_cast<int>(std::size(text)))) fail("invalid NRPT owner",ERROR_INVALID_PARAMETER);
    return text;
}
bool domain(const std::wstring &name)
{
    if (name.empty() || name.size()>253 || name==L"localhost" || (name.size()>10 && name.substr(name.size()-10)==L".localhost")) return false;
    IN_ADDR address{};
    if (InetPtonW(AF_INET,name.c_str(),&address)==1) return false;
    size_t start=0;
    for (size_t index=0;index<=name.size();++index) {
        if (index==name.size() || name[index]==L'.') {
            if (index==start || index-start>63 || name[start]==L'-' || name[index-1]==L'-') return false;
            start=index+1;
        } else {
            const auto c=name[index];
            if (!(c>=L'a' && c<=L'z') && !(c>=L'0' && c<=L'9') && c!=L'-' && c!=L'_') return false;
        }
    }
    return true;
}
bool trusted(PSID sid)
{
    return sid && (IsWellKnownSid(sid,WinBuiltinAdministratorsSid) || IsWellKnownSid(sid,WinLocalSystemSid));
}
void trustedKey(HKEY key,bool requireProtected)
{
    Security security;
    PSID owner=nullptr;
    PACL acl=nullptr;
    checked(GetSecurityInfo(key,SE_REGISTRY_KEY,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&security.value),"read NRPT security");
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision=0;
    if (!trusted(owner) || !GetSecurityDescriptorControl(security.value,&control,&revision) || (requireProtected && !(control&SE_DACL_PROTECTED)) || !acl || !IsValidAcl(acl))
        fail("untrusted NRPT owner or DACL",ERROR_ACCESS_DENIED);
    constexpr DWORD writes=KEY_SET_VALUE|KEY_CREATE_SUB_KEY|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
    for (DWORD i=0;i<acl->AceCount;++i) {
        void *value=nullptr;
        if (!GetAce(acl,i,&value)) fail("read NRPT ACE");
        const auto ace=static_cast<ACCESS_ALLOWED_ACE *>(value);
        if ((ace->Header.AceFlags&INHERIT_ONLY_ACE) || ace->Header.AceType==ACCESS_DENIED_ACE_TYPE) continue;
        if (ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE || ((ace->Mask&writes) && !trusted(&ace->SidStart)))
            fail("foreign NRPT write permission",ERROR_ACCESS_DENIED);
    }
}
void ownedKey(HKEY key,const WindowsDnsRule &rule)
{
    wchar_t name[64]{};
    DWORD size=static_cast<DWORD>(std::size(name));
    checked(RegQueryInfoKeyW(key,name,&size,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr),"read atomic NRPT class");
    if (std::wstring(name,size)!=L"JustConnect/"+guid(rule.marker)) fail("foreign NRPT ownership class",ERROR_ACCESS_DENIED);
    trustedKey(key,true);
}
// MS-GPNRPT local policy; managed policy remains owned by the domain administrator.
constexpr wchar_t LocalPolicy[]=L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";
constexpr wchar_t ManagedPolicy[]=L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig";
HKEY policyParent(bool create)
{
    Key key;
    auto status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,LocalPolicy,REG_OPTION_OPEN_LINK,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&key.value);
    if (status==ERROR_FILE_NOT_FOUND && create) {
        Security security;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:SYD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)",SDDL_REVISION_1,&security.value,nullptr)) fail("create local NRPT parent security");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes),security.value,FALSE};
        status=RegCreateKeyExW(HKEY_LOCAL_MACHINE,LocalPolicy,0,nullptr,0,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&attributes,&key.value,nullptr);
    }
    if (status==ERROR_FILE_NOT_FOUND) return nullptr;
    checked(status,"open native local DNS policy");
    trustedKey(key.value,false);
    if (RegQueryValueExW(key.value,L"SymbolicLinkValue",nullptr,nullptr,nullptr,nullptr)!=ERROR_FILE_NOT_FOUND)
        fail("refuse linked local DNS policy",ERROR_ACCESS_DENIED);
    const auto result=key.value;key.value=nullptr;return result;
}
void refresh()
{
    // Windows exports cache refresh without a public SDK declaration.
    const auto library=LoadLibraryExW(L"dnsapi.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) fail("load system DNS API");
    struct Free {HMODULE value;~Free(){FreeLibrary(value);}} free{library};
    const auto flush=reinterpret_cast<BOOL (WINAPI *)()>(GetProcAddress(library,"DnsFlushResolverCache"));
    if (!flush) fail("resolve native DNS cache refresh");
    if (!flush()) fail("refresh native DNS cache",ERROR_GEN_FAILURE);
}
struct Value { const wchar_t *name;DWORD type;std::vector<BYTE> data; };
std::vector<BYTE> bytes(const void *data,size_t size)
{
    const auto begin=static_cast<const BYTE *>(data);
    return {begin,begin+size};
}
std::vector<Value> expected(const WindowsDnsRule &rule)
{
    wchar_t address[INET_ADDRSTRLEN]{};
    if (!InetNtopW(AF_INET,&rule.server,address,static_cast<DWORD>(std::size(address)))) fail("format NRPT DNS server");
    std::vector<wchar_t> names;
    for (const auto &name:rule.domains) {
        names.push_back(L'.');names.insert(names.end(),name.begin(),name.end());names.push_back(0);
    }
    names.push_back(0);
    const DWORD version=1,options=0x8; // MS-GPNRPT: generic DNS servers enabled.
    return {{L"Version",REG_DWORD,bytes(&version,sizeof(version))},
        {L"GenericDNSServers",REG_SZ,bytes(address,(wcslen(address)+1)*sizeof(wchar_t))},
        {L"ConfigOptions",REG_DWORD,bytes(&options,sizeof(options))},
        {L"Name",REG_MULTI_SZ,bytes(names.data(),names.size()*sizeof(wchar_t))}};
}
void unchanged(HKEY key,const std::vector<Value> &values)
{
    DWORD children=0,count=0;
    checked(RegQueryInfoKeyW(key,nullptr,nullptr,nullptr,&children,nullptr,nullptr,&count,nullptr,nullptr,nullptr,nullptr),"inspect NRPT contents");
    if (children || count>values.size()) fail("unknown NRPT contents",ERROR_INVALID_DATA);
    for (DWORD i=0;i<count;++i) {
        wchar_t name[32]{};
        DWORD length=static_cast<DWORD>(std::size(name));
        checked(RegEnumValueW(key,i,name,&length,nullptr,nullptr,nullptr,nullptr),"enumerate NRPT values");
        const auto found=std::find_if(values.begin(),values.end(),[&](const auto &value) { return std::wstring(name,length)==value.name; });
        if (found==values.end()) fail("foreign NRPT value",ERROR_INVALID_DATA);
        std::vector<BYTE> data(found->data.size());
        DWORD size=static_cast<DWORD>(data.size()),type=0;
        checked(RegQueryValueExW(key,name,nullptr,&type,data.data(),&size),"read NRPT value");
        if (type!=found->type || size!=data.size() || data!=found->data) fail("externally changed NRPT value",ERROR_INVALID_DATA);
    }
}
}

bool WindowsDnsRule::valid() const
{
    const auto value=ntohl(server.S_un.S_addr);
    const auto first=value>>24;
    if (id==GUID{} || marker==GUID{} || domains.empty() || domains.size()>NetworkDnsDomainLimit
        || !value || value==0xffffffffu || first==127 || (first>=224 && first<=239) || (value>>16)==0xa9fe)
        return false;
    std::set<std::wstring> seen;
    for (const auto &name:domains) if (!domain(name) || !seen.insert(name).second) return false;
    return true;
}
WindowsDnsRule WindowsDnsRule::create(const std::vector<std::wstring> &names,IN_ADDR address)
{
    WindowsDnsRule rule;
    rule.domains=names;rule.server=address;
    if (FAILED(CoCreateGuid(&rule.id)) || FAILED(CoCreateGuid(&rule.marker))) fail("allocate NRPT ownership",ERROR_INVALID_DATA);
    if (!rule.valid()) fail("invalid NRPT namespace or server",ERROR_INVALID_PARAMETER);
    return rule;
}
void WindowsDnsRule::apply(HKEY parent) const
{
    if (!valid()) fail("invalid NRPT request",ERROR_INVALID_PARAMETER);
    Security security;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;WD)",SDDL_REVISION_1,&security.value,nullptr)) fail("create NRPT security");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),security.value,FALSE};
    auto className=L"JustConnect/"+guid(marker);
    Key key;
    checked(RegCreateKeyExW(parent,guid(id).c_str(),0,className.data(),0,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&attributes,&key.value,nullptr),"prepare owned NRPT key");
    ownedKey(key.value,*this);
    const auto values=expected(*this);
    unchanged(key.value,values);
    for (size_t i=0;i<values.size();++i) {
        const auto &value=values[i];
        if (i==values.size()-1) checked(RegFlushKey(key.value),"flush inactive NRPT preparation");
        checked(RegSetValueExW(key.value,value.name,0,value.type,value.data.data(),static_cast<DWORD>(value.data.size())),"write owned NRPT value");
    }
    checked(RegFlushKey(key.value),"flush activated NRPT rule");
    unchanged(key.value,values);
}
void WindowsDnsRule::restore(HKEY parent) const
{
    if (!valid()) fail("invalid NRPT restoration",ERROR_INVALID_PARAMETER);
    Key key;
    const auto status=RegOpenKeyExW(parent,guid(id).c_str(),REG_OPTION_OPEN_LINK,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&key.value);
    if (status==ERROR_FILE_NOT_FOUND) return;
    checked(status,"open owned NRPT restoration");
    ownedKey(key.value,*this);
    unchanged(key.value,expected(*this));
    const auto remove=reinterpret_cast<NTSTATUS (NTAPI *)(HANDLE)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtDeleteKey"));
    if (!remove) fail("resolve native NRPT deletion");
    const auto result=remove(key.value);
    if (result<0) fail("delete validated NRPT object",RtlNtStatusToDosError(result));
    checked(RegFlushKey(parent),"flush restored NRPT parent");
}

void WindowsDnsRule::applySystem() const
{
    Key managed;
    const auto status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,ManagedPolicy,REG_OPTION_OPEN_LINK,KEY_READ|KEY_WOW64_64KEY,&managed.value);
    if (status!=ERROR_FILE_NOT_FOUND) {
        checked(status,"inspect managed DNS policy");
        fail("managed DNS policy requires administrator coordination",ERROR_NOT_SUPPORTED);
    }
    Key parent;parent.value=policyParent(true);
    apply(parent.value);
    refresh();
}
void WindowsDnsRule::restoreSystem() const
{
    Key parent;parent.value=policyParent(false);
    if (parent.value) restore(parent.value);
    refresh();
}
