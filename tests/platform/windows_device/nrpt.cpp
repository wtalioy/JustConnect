#include "infrastructure/dns/windows/nrpt.h"
#include "infrastructure/dns/domainlimits.h"
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
