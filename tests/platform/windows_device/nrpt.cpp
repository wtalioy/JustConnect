#include "infrastructure/dns/windows/nrpt.h"
#include "infrastructure/dns/domainlimits.h"
#include "infrastructure/dns/windows/dnscontract.h"
#include "infrastructure/networkjournal/windows/registry.h"
#include "windowsnetworkcontract.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <aclapi.h>
#include <sddl.h>
#include <iostream>
#include <system_error>

namespace {
void check(bool value,const char *stage) { if (!value) throw std::runtime_error(stage); }
struct Key { HKEY value=nullptr; ~Key() { if (value) RegCloseKey(value); } };
IN_ADDR address(const wchar_t *value)
{
    IN_ADDR result{};
    check(InetPtonW(AF_INET,value,&result)==1,"invalid test address");
    return result;
}
template<typename F> void refused(F operation,const char *message)
{
    bool denied=false;
    try { operation(); } catch (const std::system_error &) { denied=true; }
    check(denied,message);
}
void setString(HKEY key,const wchar_t *name,const std::wstring &value)
{
    check(RegSetValueExW(key,name,0,REG_SZ,reinterpret_cast<const BYTE *>(value.c_str()),DWORD((value.size()+1)*sizeof(wchar_t)))==ERROR_SUCCESS,"write provider fixture string");
}
std::wstring getString(HKEY key,const wchar_t *name)
{
    wchar_t text[256]{};DWORD type=0,size=sizeof(text);
    check(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE *>(text),&size)==ERROR_SUCCESS && type==REG_SZ,"read provider fixture string");
    return text;
}
void redirect(HKEY parent)
{
    auto provider=WindowsDnsRule::create({L"original.private.invalid"},address(L"192.0.2.53"));
    provider.apply(parent);
    wchar_t id[39]{};check(StringFromGUID2(provider.id,id,39)!=0,"format provider UUID");
    Key key;check(RegOpenKeyExW(parent,id,REG_OPTION_OPEN_LINK,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&key.value)==ERROR_SUCCESS,"open original provider");
    const std::wstring original=L" 192.0.2.53 ; 2001:db8::53 ";
    setString(key.value,L"GenericDNSServers",original);
    setString(key.value,L"Comment",L"provider-owned");
    const auto prepare=[&]{return WindowsNrptRedirect::prepare(parent,{L".original.private.invalid"},{L"192.0.2.53",L"2001:db8::53"},address(L"127.0.0.1"));};
    auto value=prepare();
    check(value.original==original,"preparation lost original formatting");
    value.restore(parent);
    check(getString(key.value,L"GenericDNSServers")==original,"unused intent changed original DNS");
    setString(key.value,L"GenericDNSServers",L"192.0.2.54");
    refused([&]{value.apply(parent);},"stale source snapshot was applied");
    setString(key.value,L"GenericDNSServers",original);
    value.apply(parent);value.apply(parent);
    check(getString(key.value,L"GenericDNSServers")==L"127.0.0.1","native provider was not redirected");
    refused([&]{prepare();},"another session adopted an active provider");
    auto foreign=value;check(SUCCEEDED(CoCreateGuid(&foreign.marker)),"allocate foreign redirect marker");
    refused([&]{foreign.apply(parent);},"foreign redirect adopted provider");
    refused([&]{foreign.restore(parent);},"foreign redirect restored provider");
    setString(key.value,L"Comment",L"externally changed");
    value.restore(parent);value.restore(parent);
    check(getString(key.value,L"GenericDNSServers")==original && getString(key.value,L"Comment")==L"externally changed","restoration lost original endpoint formatting or external fields");
    check(RegQueryValueExW(key.value,WindowsDNS::RedirectOwner,nullptr,nullptr,nullptr,nullptr)==ERROR_FILE_NOT_FOUND,"redirect ownership marker survived restoration");
    value=prepare();value.apply(parent);
    setString(key.value,L"GenericDNSServers",L"192.0.2.54");value.restore(parent);
    check(getString(key.value,L"GenericDNSServers")==L"192.0.2.54","external endpoint was overwritten");
    setString(key.value,L"GenericDNSServers",original);
    value=prepare();value.apply(parent);
    check(RegDeleteValueW(key.value,WindowsDNS::RedirectOwner)==ERROR_SUCCESS,"remove fixture redirect marker");
    refused([&]{value.restore(parent);},"unowned listener endpoint was silently released");
    setString(key.value,L"GenericDNSServers",original);
    value=prepare();value.released=true;
    refused([&]{value.apply(parent);},"released provider was reclaimed");
    const DWORD secure=0x18;
    check(RegSetValueExW(key.value,L"ConfigOptions",0,REG_DWORD,reinterpret_cast<const BYTE *>(&secure),sizeof(secure))==ERROR_SUCCESS,"set secure provider fixture");
    refused([&]{prepare();},"secured provider was redirected as plaintext");
    const DWORD plain=8;
    check(RegSetValueExW(key.value,L"ConfigOptions",0,REG_DWORD,reinterpret_cast<const BYTE *>(&plain),sizeof(plain))==ERROR_SUCCESS,"restore provider fixture policy");
    auto duplicate=WindowsDnsRule::create(provider.domains,provider.server);duplicate.apply(parent);
    refused([&]{prepare();},"ambiguous provider was selected");duplicate.restore(parent);
    check(RegDeleteValueW(key.value,L"Comment")==ERROR_SUCCESS,"remove provider fixture comment");
    setString(key.value,L"GenericDNSServers",L"192.0.2.53");provider.restore(parent);
    std::cout<<"PASS: original NRPT redirect, stale snapshot refusal, idempotent restore, external edit preservation, secure and ambiguous source rejection\n";
}
void boundaries()
{
    for (const auto &names:std::vector<std::vector<std::wstring>>{{},{L"."},{L"localhost"},{L"example.localhost"},
        {L"Mixed.example"},{L"trailing.example."},{L"duplicate.example",L"duplicate.example"},{L"valid.example",L"bad..example"},{L"192.0.2.1"}})
        refused([&] { WindowsDnsRule::create(names,address(L"192.0.2.53")); },"unsafe NRPT namespace accepted");
    for (const auto &server:{L"0.0.0.0",L"127.0.0.1",L"224.0.0.1",L"255.255.255.255",L"169.254.0.1"})
        refused([&] { WindowsDnsRule::create({L"safe.invalid"},address(server)); },"unsafe NRPT DNS server accepted");
    auto rule=WindowsDnsRule::create({L"safe.invalid"},address(L"192.0.2.53"));
    rule.marker=GUID{};
    refused([&] { rule.apply(nullptr); },"invalid owner reached the registry");
    check(WindowsDnsRule::create({L"_service.safe.invalid"},address(L"192.0.2.53")).valid(),"existing DNS service namespace refused");
    rule.marker=rule.id;
    rule.domains.clear();
    for (size_t i=0;i<=NetworkDnsDomainLimit;++i) rule.domains.push_back(L"d"+std::to_wstring(i)+L".invalid");
    check(!rule.valid(),"NRPT namespace count bypassed the shared bound");
    rule.domains.pop_back();
    check(rule.valid(),"maximum distinct namespace set refused");
}
}

int main() try
{
    wchar_t guarded[8]{};
    check(GetEnvironmentVariableW(L"GITHUB_ACTIONS",guarded,8)==4 && std::wstring(guarded)==L"true","protected registry test requires disposable runner");
    boundaries();
    WindowsRegistryJournal journal;
    Key parent;
    check(RegOpenKeyExW(HKEY_LOCAL_MACHINE,WindowsNetworkContract::StateRegistry,REG_OPTION_OPEN_LINK,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&parent.value)==ERROR_SUCCESS,"open private NRPT parent");
    redirect(parent.value);
    auto rule=WindowsDnsRule::create({L"private.safe.invalid"},address(L"192.0.2.53"));
    struct Cleanup { HKEY parent;WindowsDnsRule &rule;~Cleanup() { try { rule.restore(parent); } catch (...) {} } } cleanup{parent.value,rule};
    rule.apply(parent.value);rule.apply(parent.value);
    wchar_t name[39]{};
    check(StringFromGUID2(rule.id,name,39)!=0,"format owned rule");
    Key key;
    check(RegOpenKeyExW(parent.value,name,REG_OPTION_OPEN_LINK,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&key.value)==ERROR_SUCCESS,"open private owned NRPT rule");
    auto foreign=rule;
    check(SUCCEEDED(CoCreateGuid(&foreign.marker)),"new foreign marker");
    refused([&] { foreign.restore(parent.value); },"foreign class deleted an owned rule");
    for (const auto &permissions:{L"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KW;;;BU)",L"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;WD)"}) {
        PSECURITY_DESCRIPTOR descriptor=nullptr;
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(permissions,SDDL_REVISION_1,&descriptor,nullptr),"parse owned DNS ACL fixture");
        BOOL present=FALSE,defaulted=FALSE;PACL acl=nullptr;
        const bool parsed=GetSecurityDescriptorDacl(descriptor,&present,&acl,&defaulted);
        const auto status=parsed && present?SetSecurityInfo(key.value,SE_REGISTRY_KEY,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,acl,nullptr):ERROR_INVALID_DATA;
        LocalFree(descriptor);check(status==ERROR_SUCCESS,"set owned DNS ACL fixture");
        if (permissions==std::wstring(L"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KW;;;BU)")) {
            refused([&]{rule.apply(parent.value);},"user-writable owned DNS rule adopted");
            refused([&]{rule.restore(parent.value);},"user-writable owned DNS rule deleted");
        }
    }
    const wchar_t changed[]=L"192.0.2.54";
    check(RegSetValueExW(key.value,L"GenericDNSServers",0,REG_SZ,reinterpret_cast<const BYTE *>(changed),sizeof(changed))==ERROR_SUCCESS,"simulate external DNS edit");
    refused([&] { rule.restore(parent.value); },"external DNS value was deleted");
    wchar_t found[32]{};DWORD size=sizeof(found),type=0;
    check(RegQueryValueExW(key.value,L"GenericDNSServers",nullptr,&type,reinterpret_cast<BYTE *>(found),&size)==ERROR_SUCCESS && type==REG_SZ && std::wstring(found)==changed,"refused recovery changed external DNS");
    const wchar_t original[]=L"192.0.2.53";
    check(RegSetValueExW(key.value,L"GenericDNSServers",0,REG_SZ,reinterpret_cast<const BYTE *>(original),sizeof(original))==ERROR_SUCCESS,"restore test-owned DNS value");
    const DWORD extra=1;
    check(RegSetValueExW(key.value,L"Foreign",0,REG_DWORD,reinterpret_cast<const BYTE *>(&extra),sizeof(extra))==ERROR_SUCCESS,"add unknown rule value");
    refused([&] { rule.apply(parent.value); },"unknown rule value overwritten");
    refused([&] { rule.restore(parent.value); },"unknown rule value deleted");
    check(RegDeleteValueW(key.value,L"Foreign")==ERROR_SUCCESS,"remove test-owned unknown value");
    check(RegDeleteValueW(key.value,L"Name")==ERROR_SUCCESS,"simulate incomplete write-ahead activation");
    rule.apply(parent.value);
    rule.restore(parent.value);
    RegCloseKey(key.value);key.value=nullptr;
    rule.restore(parent.value);
    check(RegOpenKeyExW(parent.value,name,0,KEY_READ|KEY_WOW64_64KEY,&key.value)==ERROR_FILE_NOT_FOUND,"restored native NRPT rule remains present");
    std::cout << "PASS: atomic NRPT ownership class, partial activation, external-value preservation and validated-handle deletion\n";
    return 0;
} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
