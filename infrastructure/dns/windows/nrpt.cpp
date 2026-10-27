#include "infrastructure/dns/windows/nrpt.h"
#include "infrastructure/dns/windows/dnscontract.h"
#include "infrastructure/dns/windows/dnsreader.h"
#include "infrastructure/dns/domainlimits.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <aclapi.h>
#include <sddl.h>
#include <winternl.h>
#include <iphlpapi.h>
#include <cwctype>
#include <algorithm>
#include <cstring>
#include <iterator>
#include <set>
#include <system_error>
#include <limits>

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
bool firewallService(PSID sid)
{
    static const auto service=[] {
        DWORD size=0,length=0;SID_NAME_USE use{};
        LookupAccountNameW(nullptr,L"NT SERVICE\\mpssvc",nullptr,&size,nullptr,&length,&use);
        if (GetLastError()!=ERROR_INSUFFICIENT_BUFFER) fail("locate native firewall policy owner");
        std::vector<BYTE> result(size);std::vector<wchar_t> domain(length);
        if (!LookupAccountNameW(nullptr,L"NT SERVICE\\mpssvc",result.data(),&size,domain.data(),&length,&use)) fail("read native firewall policy owner");
        return result;
    }();
    return EqualSid(sid,const_cast<BYTE *>(service.data()))!=FALSE;
}
void trustedKey(HKEY key,bool requireProtected,bool checkValues=false)
{
    Security security;
    PSID owner=nullptr;
    PACL acl=nullptr;
    checked(GetSecurityInfo(key,SE_REGISTRY_KEY,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&security.value),"read NRPT security");
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision=0;
    if (!trusted(owner) || !GetSecurityDescriptorControl(security.value,&control,&revision) || (requireProtected && !(control&SE_DACL_PROTECTED)) || !acl || !IsValidAcl(acl))
        fail("untrusted NRPT owner or DACL",ERROR_ACCESS_DENIED);
    // The system parent permits network operators to add namespaces; our UUID child never inherits those rights.
    const DWORD writes=DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL|((requireProtected||checkValues)?(KEY_SET_VALUE|KEY_CREATE_SUB_KEY):0);
    for (DWORD i=0;i<acl->AceCount;++i) {
        void *value=nullptr;
        if (!GetAce(acl,i,&value)) fail("read NRPT ACE");
        const auto ace=static_cast<ACCESS_ALLOWED_ACE *>(value);
        if ((ace->Header.AceFlags&INHERIT_ONLY_ACE) || ace->Header.AceType==ACCESS_DENIED_ACE_TYPE) continue;
        if (ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE || ((ace->Mask&writes) && !trusted(&ace->SidStart) && (requireProtected || !firewallService(&ace->SidStart))))
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
using WindowsDNS::LocalPolicy;
using WindowsDNS::ManagedPolicy;
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
void unmanagedPolicy()
{
    Key managed;
    const auto status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,ManagedPolicy,REG_OPTION_OPEN_LINK,KEY_READ|KEY_WOW64_64KEY,&managed.value);
    if(status!=ERROR_FILE_NOT_FOUND){checked(status,"inspect managed DNS policy");fail("managed DNS policy requires administrator coordination",ERROR_NOT_SUPPORTED);}
}
std::wstring stringValue(HKEY key,const wchar_t *name,bool optional=false)
{
    DWORD type=0,size=0;
    const auto status=RegQueryValueExW(key,name,nullptr,&type,nullptr,&size);
    if(optional && status==ERROR_FILE_NOT_FOUND)return {};
    checked(status,"inspect native DNS string");
    if(type!=REG_SZ || size<sizeof(wchar_t) || size>WindowsDNS::SnapshotBytes || size%sizeof(wchar_t))fail("invalid native DNS string",ERROR_INVALID_DATA);
    std::vector<wchar_t> text(size/sizeof(wchar_t));const auto expected=size;
    checked(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE *>(text.data()),&size),"read native DNS string");
    if(type!=REG_SZ || size!=expected || text.back()!=0 || wcsnlen(text.data(),text.size())!=text.size()-1)fail("changed native DNS string",ERROR_INVALID_DATA);
    return {text.data(),text.size()-1};
}
void setString(HKEY key,const wchar_t *name,const std::wstring &value)
{
    checked(RegSetValueExW(key,name,0,REG_SZ,reinterpret_cast<const BYTE *>(value.c_str()),DWORD((value.size()+1)*sizeof(wchar_t))),"write native DNS string");
    checked(RegFlushKey(key),"flush native DNS string");
}
std::wstring keyClass(HKEY key)
{
    std::vector<wchar_t> value(256);DWORD size=DWORD(value.size());
    checked(RegQueryInfoKeyW(key,value.data(),&size,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr),"read native DNS provider class");
    return {value.data(),size};
}
bool namespaceName(std::wstring value)
{
    for(auto &c:value)c=static_cast<wchar_t>(towlower(c));
    if(value==L".")return true;
    if(!value.empty() && value.front()==L'.')value.erase(0,1);
    if(!value.empty() && value.back()==L'*')value.pop_back();
    if(!value.empty() && value.back()==L'.')value.pop_back();
    return domain(value);
}
std::set<std::wstring> nameSet(const std::vector<std::wstring> &names)
{
    if(names.empty() || names.size()>NetworkDnsDomainLimit)fail("invalid native DNS namespaces",ERROR_INVALID_DATA);
    std::set<std::wstring> result;
    for(auto name:names){
        if(!namespaceName(name))fail("unsupported native DNS namespace",ERROR_NOT_SUPPORTED);
        for(auto &c:name)c=static_cast<wchar_t>(towlower(c));
        if(!result.insert(name).second)fail("duplicate native DNS namespace",ERROR_INVALID_DATA);
    }
    return result;
}
std::vector<std::wstring> namespaceValues(HKEY key)
{
    DWORD type=0,size=0;
    checked(RegQueryValueExW(key,L"Name",nullptr,&type,nullptr,&size),"inspect native DNS namespaces");
    if(type!=REG_MULTI_SZ || size<2*sizeof(wchar_t) || size>WindowsDNS::SnapshotBytes || size%sizeof(wchar_t))fail("invalid native DNS namespaces",ERROR_INVALID_DATA);
    std::vector<wchar_t> values(size/sizeof(wchar_t));const auto expected=size;
    checked(RegQueryValueExW(key,L"Name",nullptr,&type,reinterpret_cast<BYTE *>(values.data()),&size),"read native DNS namespaces");
    if(type!=REG_MULTI_SZ || size!=expected || values.back()!=0 || values[values.size()-2]!=0)fail("changed native DNS namespaces",ERROR_INVALID_DATA);
    std::vector<std::wstring> result;size_t at=0;
    while(at<values.size() && values[at]){const auto count=wcsnlen(values.data()+at,values.size()-at);result.emplace_back(values.data()+at,count);at+=count+1;}
    for(;at<values.size();++at)if(values[at])fail("malformed native DNS namespaces",ERROR_INVALID_DATA);
    nameSet(result);return result;
}
DWORD numberValue(HKEY key,const wchar_t *name)
{
    DWORD value=0,type=0,size=sizeof(value);
    checked(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE *>(&value),&size),"read native DNS policy");
    if(type!=REG_DWORD || size!=sizeof(value))fail("invalid native DNS policy",ERROR_INVALID_DATA);
    return value;
}
std::wstring canonicalIP(std::wstring value)
{
    if(value.find(L'\0')!=std::wstring::npos)fail("invalid original DNS server string",ERROR_INVALID_DATA);
    const auto first=value.find_first_not_of(L" \t"),last=value.find_last_not_of(L" \t");
    if(first==std::wstring::npos)fail("empty original DNS server",ERROR_INVALID_DATA);
    value=value.substr(first,last-first+1);
    const auto separator=value.find(L'%');std::wstring zone;
    if(separator!=std::wstring::npos){
        const auto index=value.substr(separator+1);
        if(index.empty() || index.size()>10 || index.find_first_not_of(L"0123456789")!=std::wstring::npos)fail("invalid original DNS scope",ERROR_INVALID_DATA);
        const auto number=std::stoull(index);
        if(number>std::numeric_limits<ULONG>::max())fail("invalid original DNS scope",ERROR_INVALID_DATA);
        if(number)zone=L"%"+std::to_wstring(number);
        value.resize(separator);
    }
    IN6_ADDR address{};wchar_t output[INET6_ADDRSTRLEN]{};
    auto family=value.find(L':')==std::wstring::npos?AF_INET:AF_INET6;
    if(InetPtonW(family,value.c_str(),&address)!=1)fail("original DNS requires literal servers",ERROR_NOT_SUPPORTED);
    if(family==AF_INET){
        const auto ip=ntohl(reinterpret_cast<IN_ADDR *>(&address)->S_un.S_addr);
        if(!ip || ip==0xffffffffu || (ip>>28)==14 || !zone.empty())fail("invalid original DNS server",ERROR_INVALID_DATA);
    }else{
        if(IN6_IS_ADDR_UNSPECIFIED(&address) || IN6_IS_ADDR_MULTICAST(&address))fail("invalid original DNS server",ERROR_INVALID_DATA);
        if(IN6_IS_ADDR_V4MAPPED(&address)){
            if(!zone.empty())fail("invalid mapped DNS scope",ERROR_INVALID_DATA);
            const auto mapped=*reinterpret_cast<const IN_ADDR *>(&address.u.Byte[12]);
            if(!InetNtopW(AF_INET,&mapped,output,INET6_ADDRSTRLEN))fail("format original DNS server");
            return canonicalIP(output);
        }
    }
    if(!InetNtopW(family,&address,output,INET6_ADDRSTRLEN))fail("format original DNS server");
    return std::wstring(output)+zone;
}
std::vector<std::wstring> serverList(const std::wstring &value)
{
    if(value.empty() || value.size()>WindowsDNS::SnapshotBytes/sizeof(wchar_t))fail("invalid original DNS server list",ERROR_INVALID_DATA);
    std::vector<std::wstring> result;size_t at=0;
    for(;;){
        const auto end=value.find(L';',at);result.push_back(canonicalIP(value.substr(at,end==std::wstring::npos?end:end-at)));
        if(result.size()>NetworkDnsDomainLimit)fail("too many original DNS servers",ERROR_INVALID_DATA);
        if(end==std::wstring::npos)break;
        at=end+1;
    }
    return result;
}
std::wstring redirectServer(IN_ADDR value)
{
    wchar_t text[INET_ADDRSTRLEN]{};
    if(!InetNtopW(AF_INET,&value,text,INET_ADDRSTRLEN))fail("format original DNS listener");
    return text;
}
void unchangedProvider(HKEY key,const WindowsNrptRedirect &value)
{
    trustedKey(key,false,true);
    if(keyClass(key)!=value.policyClass || nameSet(namespaceValues(key))!=nameSet(value.namespaces)
        || numberValue(key,L"Version")!=1 || numberValue(key,L"ConfigOptions")!=0x8)
        fail("original DNS provider changed",ERROR_NOT_SUPPORTED);
    if(RegQueryValueExW(key,L"SymbolicLinkValue",nullptr,nullptr,nullptr,nullptr)!=ERROR_FILE_NOT_FOUND)fail("linked original DNS provider",ERROR_ACCESS_DENIED);
}
bool plainPolicy(std::uint64_t value)
{
    constexpr auto policy=DNS_DOH_POLICY_NOT_CONFIGURED|DNS_DOH_POLICY_DISABLE;
    return !(value&~std::uint64_t(DNS_ENABLE_DOH|policy)) && (value&policy)!=policy;
}
std::uint64_t plainGlobalPolicy(const std::vector<std::wstring> &servers)
{
    DNS_SETTINGS2 settings{};settings.Version=DNS_SETTINGS_VERSION2;
    auto *base=reinterpret_cast<DNS_SETTINGS *>(&settings);
    checked(GetDnsSettings(base),"read global DNS security");
    const auto value=settings.SettingFlags;FreeDnsSettings(base);
    if(!plainPolicy(value))fail(("original DNS transport requires native encrypted policy (flags="+std::to_string(value)+")").c_str(),ERROR_NOT_SUPPORTED);
    if((value&DNS_ENABLE_DOH) && !(value&DNS_DOH_POLICY_DISABLE)){
        for(const auto &known:WindowsDNS::knownNrptDohServers()){
            const auto address=canonicalIP(known);
            if(std::find(servers.begin(),servers.end(),address)!=servers.end())fail("original NRPT server requires native DoH",ERROR_NOT_SUPPORTED);
        }
    }
    return value;
}
void localListener(IN_ADDR value)
{
    PMIB_UNICASTIPADDRESS_TABLE table=nullptr;
    checked(GetUnicastIpAddressTable(AF_INET,&table),"read original DNS listener addresses");
    struct Free {PMIB_UNICASTIPADDRESS_TABLE value;~Free(){FreeMibTable(value);}} free{table};
    for(ULONG i=0;i<table->NumEntries;++i){
        const auto &row=table->Table[i];
        if(row.Address.Ipv4.sin_addr.S_un.S_addr!=value.S_un.S_addr || row.DadState!=IpDadStatePreferred)continue;
        MIB_IF_ROW2 iface{};iface.InterfaceLuid=row.InterfaceLuid;
        if(GetIfEntry2(&iface)==NO_ERROR && iface.OperStatus==IfOperStatusUp)return;
    }
    fail("original DNS listener is not assigned to an active local interface",ERROR_INVALID_PARAMETER);
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
    unmanagedPolicy();
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

bool WindowsNrptRedirect::valid() const try
{
    if(id==GUID{} || marker==GUID{} || policyClass.size()>255 || policyClass.find(L'\0')!=std::wstring::npos
        || !plainPolicy(globalPolicy))return false;
    nameSet(namespaces);
    const auto listen=canonicalIP(redirectServer(server));
    const auto before=serverList(original);
    return std::find(before.begin(),before.end(),listen)==before.end();
}catch(const std::exception &){return false;}
std::vector<std::wstring> WindowsNrptRedirect::servers() const{return serverList(original);}

WindowsNrptRedirect WindowsNrptRedirect::prepare(HKEY parent,const std::vector<std::wstring> &names,
    const std::vector<std::wstring> &servers,IN_ADDR listen)
{
    const auto wanted=nameSet(names);std::vector<std::wstring> expectedServers;
    for(const auto &value:servers)expectedServers.push_back(canonicalIP(value));
    if(expectedServers.empty() || expectedServers.size()>NetworkDnsDomainLimit)fail("missing original DNS servers",ERROR_INVALID_PARAMETER);
    trustedKey(parent,false);
    DWORD count=0,longest=0;checked(RegQueryInfoKeyW(parent,nullptr,nullptr,nullptr,&count,&longest,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr),"inspect original DNS providers");
    if(count>NetworkDnsDomainLimit || longest>WindowsDNS::SnapshotBytes/sizeof(wchar_t))fail("too many original DNS providers",ERROR_INVALID_DATA);
    std::vector<wchar_t> keyName(size_t(longest)+1);WindowsNrptRedirect result;
    for(DWORD i=0;i<count;++i){
        DWORD length=DWORD(keyName.size());checked(RegEnumKeyExW(parent,i,keyName.data(),&length,nullptr,nullptr,nullptr,nullptr),"enumerate original DNS providers");
        Key key;checked(RegOpenKeyExW(parent,keyName.data(),REG_OPTION_OPEN_LINK,KEY_READ|KEY_WOW64_64KEY,&key.value),"inspect original DNS provider");
        if(RegQueryValueExW(key.value,L"Name",nullptr,nullptr,nullptr,nullptr)==ERROR_FILE_NOT_FOUND)continue;
        const auto current=namespaceValues(key.value);
        if(nameSet(current)!=wanted)continue;
        if(result.id!=GUID{})fail("ambiguous original DNS provider",ERROR_NOT_SUPPORTED);
        if(FAILED(CLSIDFromString(keyName.data(),&result.id)) || result.id==GUID{})fail("unsupported original DNS provider identity",ERROR_NOT_SUPPORTED);
        result.namespaces=current;result.policyClass=keyClass(key.value);result.original=stringValue(key.value,L"GenericDNSServers");result.server=listen;
        if(RegQueryValueExW(key.value,WindowsDNS::RedirectOwner,nullptr,nullptr,nullptr,nullptr)!=ERROR_FILE_NOT_FOUND)
            fail("original DNS already has an active owner",ERROR_ALREADY_EXISTS);
        unchangedProvider(key.value,result);
        if(serverList(result.original)!=expectedServers)fail("original DNS servers changed before preparation",ERROR_INVALID_DATA);
    }
    if(FAILED(CoCreateGuid(&result.marker)) || !result.valid())fail("cannot confirm original DNS provider",ERROR_INVALID_DATA);
    return result;
}
WindowsNrptRedirect WindowsNrptRedirect::prepareSystem(const std::vector<std::wstring> &names,
    const std::vector<std::wstring> &servers,IN_ADDR listen)
{
    unmanagedPolicy();localListener(listen);
    Key parent;parent.value=policyParent(false);
    if(!parent.value)fail("original DNS provider disappeared",ERROR_NOT_FOUND);
    auto result=prepare(parent.value,names,servers,listen);result.globalPolicy=plainGlobalPolicy(result.servers());return result;
}
void WindowsNrptRedirect::apply(HKEY parent) const
{
    if(!valid() || released)fail("invalid original DNS redirect",ERROR_INVALID_PARAMETER);
    Key key;checked(RegOpenKeyExW(parent,guid(id).c_str(),REG_OPTION_OPEN_LINK,KEY_QUERY_VALUE|KEY_SET_VALUE|READ_CONTROL|KEY_WOW64_64KEY,&key.value),"open original DNS redirect");
    unchangedProvider(key.value,*this);
    const auto owner=stringValue(key.value,WindowsDNS::RedirectOwner,true),current=stringValue(key.value,L"GenericDNSServers");
    if(owner.empty() && RegQueryValueExW(key.value,WindowsDNS::RedirectOwner,nullptr,nullptr,nullptr,nullptr)!=ERROR_FILE_NOT_FOUND)
        fail("invalid original DNS ownership marker",ERROR_ACCESS_DENIED);
    if((!owner.empty() && owner!=guid(marker)) || (current!=original && !(owner==guid(marker) && current==redirectServer(server))))
        fail("original DNS ownership changed",ERROR_ACCESS_DENIED);
    if(owner.empty())setString(key.value,WindowsDNS::RedirectOwner,guid(marker));
    setString(key.value,L"GenericDNSServers",redirectServer(server));
    unchangedProvider(key.value,*this);
    if(stringValue(key.value,WindowsDNS::RedirectOwner)!=guid(marker) || stringValue(key.value,L"GenericDNSServers")!=redirectServer(server))
        fail("original DNS redirect readback changed",ERROR_INVALID_DATA);
}
void WindowsNrptRedirect::restore(HKEY parent) const
{
    if(released)return;
    if(!valid())fail("invalid original DNS restoration",ERROR_INVALID_PARAMETER);
    Key key;const auto opened=RegOpenKeyExW(parent,guid(id).c_str(),REG_OPTION_OPEN_LINK,KEY_QUERY_VALUE|KEY_SET_VALUE|READ_CONTROL|KEY_WOW64_64KEY,&key.value);
    if(opened==ERROR_FILE_NOT_FOUND)return;
    checked(opened,"open original DNS restoration");trustedKey(key.value,false,true);
    const auto owner=stringValue(key.value,WindowsDNS::RedirectOwner,true);
    if(owner.empty()){
        if(RegQueryValueExW(key.value,WindowsDNS::RedirectOwner,nullptr,nullptr,nullptr,nullptr)!=ERROR_FILE_NOT_FOUND)
            fail("invalid original DNS ownership marker",ERROR_ACCESS_DENIED);
        if(stringValue(key.value,L"GenericDNSServers")==redirectServer(server))fail("original DNS listener lost its ownership marker",ERROR_ACCESS_DENIED);
        return;
    }
    if(owner!=guid(marker) || keyClass(key.value)!=policyClass)fail("original DNS provider was replaced",ERROR_ACCESS_DENIED);
    const auto current=stringValue(key.value,L"GenericDNSServers");
    if(current==redirectServer(server))setString(key.value,L"GenericDNSServers",original);
    // External endpoint and policy edits remain intact; release only this transaction's marker.
    checked(RegDeleteValueW(key.value,WindowsDNS::RedirectOwner),"release original DNS ownership");
    checked(RegFlushKey(key.value),"flush original DNS restoration");
}
void WindowsNrptRedirect::applySystem() const
{
    unmanagedPolicy();localListener(server);
    if(plainGlobalPolicy(servers())!=globalPolicy)fail("original DNS security changed before write",ERROR_NOT_SUPPORTED);
    Key parent;parent.value=policyParent(false);
    if(!parent.value)fail("original DNS provider disappeared",ERROR_NOT_FOUND);
    apply(parent.value);refresh();
    if(plainGlobalPolicy(servers())!=globalPolicy)fail("original DNS security changed during write",ERROR_NOT_SUPPORTED);
}
void WindowsNrptRedirect::restoreSystem() const
{
    Key parent;parent.value=policyParent(false);
    if(parent.value)restore(parent.value);
    refresh();
}
