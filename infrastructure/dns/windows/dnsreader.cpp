#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <initializer_list>
#include "dnscontract.h"
#include "dnsreader.h"
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <mi.h>
#include <cwchar>
#include <limits>
#include <map>
#include <set>
#include <vector>
#include "../domainlimits.h"
static_assert(WindowsDNS::PropertyVersion==DNS_SERVER_PROPERTY_VERSION1
    && WindowsDNS::DohProperty==DnsServerDohProperty && WindowsDNS::DotProperty==DnsServerDotProperty);
#endif

namespace {
constexpr size_t limit = WindowsDNS::SnapshotBytes;
void append(std::string &output, const std::string &text)
{
    if (text.size() > limit || output.size() > limit - text.size()) throw std::runtime_error("snapshot size");
    output += text;
}
std::string quote(const std::string &text)
{
    std::string output("\"");
    constexpr char hex[] = "0123456789abcdef";
    for (const auto byte : text) {
        const auto ch = static_cast<unsigned char>(byte);
        if (ch == '"' || ch == '\\') append(output, std::string("\\") + char(ch));
        else if (ch < 32) append(output, std::string("\\u00") + hex[ch >> 4] + hex[ch & 15]);
        else append(output, std::string(1, char(ch)));
    }
    append(output, "\"");
    return output;
}

#ifdef _WIN32
ULONGLONG started;
struct ProviderFailure { MI_Result code; };
void trace(const char *stage)
{
    std::fprintf(stderr, "JCDNS phase=%s elapsed_ms=%llu\n", stage,
                 static_cast<unsigned long long>(GetTickCount64() - started));
    std::fflush(stderr);
}
void require(MI_Result result)
{
    if (result != MI_RESULT_OK) throw ProviderFailure{result};
}
struct NamespaceLess {
    bool operator()(const std::wstring &left,const std::wstring &right) const {
        const auto order=CompareStringOrdinal(left.c_str(),int(left.size()),right.c_str(),int(right.size()),TRUE);
        if(!order)throw std::runtime_error("native namespace comparison");
        return order==CSTR_LESS_THAN;
    }
};
using Namespaces=std::set<std::wstring,NamespaceLess>;
struct RegistryKey {
    HKEY value=nullptr;
    ~RegistryKey(){if(value)RegCloseKey(value);}
};
void registryChecked(LSTATUS status)
{
    if(status!=ERROR_SUCCESS)throw std::runtime_error("native NRPT policy source");
}
bool absentPolicyObject(LSTATUS status)
{
    return status==ERROR_FILE_NOT_FOUND || status==ERROR_KEY_DELETED;
}
std::string utf8(const wchar_t *text)
{
    if (!text) return {};
    const auto length = wcsnlen(text, limit + 1);
    if (length > limit) throw std::runtime_error("native string size");
    if (!length) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, int(length), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0 || bytes > int(limit)) throw std::runtime_error("native Unicode");
    std::string output(size_t(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, int(length), output.data(), bytes, nullptr, nullptr) != bytes)
        throw std::runtime_error("native Unicode");
    return output;
}
std::string ip(const wchar_t *text)
{
    if (!text) throw std::runtime_error("native IP");
    const auto input = utf8(text);
    const auto separator = input.find('%');
    const auto host = input.substr(0, separator);
    IN6_ADDR address{};
    char canonical[INET6_ADDRSTRLEN]{};
    const int family = host.find(':') == std::string::npos ? AF_INET : AF_INET6;
    if (InetPtonA(family, host.c_str(), &address) != 1 || !InetNtopA(family, &address, canonical, sizeof(canonical)))
        throw std::runtime_error("native IP");
    std::string output(canonical);
    if (separator != std::string::npos) {
        const auto scope = input.substr(separator + 1);
        if (family != AF_INET6 || scope.empty() || scope.size() > 10 || scope.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("native IP scope");
        const auto number = std::stoull(scope);
        if (number > 0xffffffffu) throw std::runtime_error("native IP scope");
        if (number) output += "%" + std::to_string(number);
    }
    return output;
}
std::string optionalText(const wchar_t *text)
{
    return text ? quote(utf8(text)) : "null";
}
std::string dnsEndpoint(const SOCKET_ADDRESS &socket)
{
    if(!socket.lpSockaddr || socket.iSockaddrLength<int(sizeof(ADDRESS_FAMILY)))
        throw std::runtime_error("native DNS server socket");
    const auto family=socket.lpSockaddr->sa_family;
    char address[INET6_ADDRSTRLEN]{};
    unsigned port=0,scope=0;
    if(family==AF_INET && socket.iSockaddrLength>=int(sizeof(sockaddr_in))){
        const auto &value=*reinterpret_cast<const sockaddr_in *>(socket.lpSockaddr);
        if(!InetNtopA(AF_INET,&value.sin_addr,address,sizeof(address)))throw std::runtime_error("native DNS IPv4");
        port=ntohs(value.sin_port);
    }else if(family==AF_INET6 && socket.iSockaddrLength>=int(sizeof(sockaddr_in6))){
        const auto &value=*reinterpret_cast<const sockaddr_in6 *>(socket.lpSockaddr);
        if(!InetNtopA(AF_INET6,&value.sin6_addr,address,sizeof(address)))throw std::runtime_error("native DNS IPv6");
        port=ntohs(value.sin6_port);scope=value.sin6_scope_id;
    }else throw std::runtime_error("native DNS server family or size");
    auto host=std::string(address);
    if(scope)host+="%"+std::to_string(scope);
    return "{\"Address\":"+quote(host)+",\"Port\":"+std::to_string(port ? port : WindowsDNS::ServerPort)+"}";
}
std::string serverProperties(ULONG count,const DNS_SERVER_PROPERTY *properties)
{
    if(count>NetworkDnsDomainLimit || (count && !properties))throw std::runtime_error("native DNS security properties");
    std::string output("[");
    for(ULONG i=0;i<count;++i){
        const auto &value=properties[i];
        if(i)append(output,",");
        append(output,"{\"Version\":"+std::to_string(value.Version)+",\"ServerIndex\":"+std::to_string(value.ServerIndex)
            +",\"Type\":"+std::to_string(value.Type)+",\"Settings\":");
        if(value.Version==WindowsDNS::PropertyVersion && value.Type==DnsServerDohProperty){
            if(!value.Property.DohSettings)throw std::runtime_error("native DoH settings");
            const auto &settings=*value.Property.DohSettings;
            append(output,"{\"Template\":"+optionalText(settings.Template)+",\"Flags\":"+quote(std::to_string(settings.Flags))+"}");
        }else if(value.Version==WindowsDNS::PropertyVersion && value.Type==DnsServerDotProperty){
            if(!value.Property.DotSettings)throw std::runtime_error("native DoT settings");
            const auto &settings=*value.Property.DotSettings;
            append(output,"{\"Hostname\":"+optionalText(settings.Hostname)+",\"Port\":"+std::to_string(settings.Port)
                +",\"Flags\":"+quote(std::to_string(settings.Flags))+"}");
        }else append(output,"null"); // Unknown security properties remain explicit, never plain-DNS permission.
        append(output,"}");
    }
    append(output,"]");return output;
}
void checkSettingsStatus(ULONG status)
{
    // These statuses describe unavailable settings, not a confirmed unencrypted source.
    if(status!=NO_ERROR && !WindowsDNS::settingsUnavailable(status))throw std::runtime_error("native DNS settings read failed");
}
std::string interfaceSettings(const GUID &id)
{
    DNS_INTERFACE_SETTINGS4 settings{};
    settings.Version=DNS_INTERFACE_SETTINGS_VERSION4;
    auto *base=reinterpret_cast<DNS_INTERFACE_SETTINGS *>(&settings);
    const auto status=GetInterfaceDnsSettings(id,base);
    struct Release {DNS_INTERFACE_SETTINGS *value;~Release(){if(value)FreeInterfaceDnsSettings(value);}} release{status==NO_ERROR?base:nullptr};
    checkSettingsStatus(status);
    std::string output("{\"Status\":"+std::to_string(status)+",\"Value\":");
    if(status!=NO_ERROR)append(output,"null");
    else{
        append(output,"{\"Flags\":"+quote(std::to_string(settings.Flags))
            +",\"Domain\":"+optionalText(settings.Domain)+",\"NameServer\":"+optionalText(settings.NameServer)
            +",\"SearchList\":"+optionalText(settings.SearchList)+",\"ProfileNameServer\":"+optionalText(settings.ProfileNameServer)
            +",\"SupplementalSearchList\":"+optionalText(settings.SupplementalSearchList)
            +",\"DisableUnconstrainedQueries\":"+std::to_string(settings.DisableUnconstrainedQueries)
            +",\"EncryptedDnsAdapterFlags\":"+std::to_string(settings.EncryptedDnsAdapterFlags)+",\"ServerProperties\":");
        append(output,serverProperties(settings.cServerProperties,settings.ServerProperties));
        append(output,",\"ProfileServerProperties\":");append(output,serverProperties(settings.cProfileServerProperties,settings.ProfileServerProperties));
        append(output,"}");
    }
    append(output,"}");return output;
}
std::string globalSettings()
{
    trace("global_dns");
    DNS_SETTINGS2 settings{};settings.Version=DNS_SETTINGS_VERSION2;
    auto *base=reinterpret_cast<DNS_SETTINGS *>(&settings);
    const auto status=GetDnsSettings(base);
    struct Release {DNS_SETTINGS *value;~Release(){if(value)FreeDnsSettings(value);}} release{status==NO_ERROR?base:nullptr};
    checkSettingsStatus(status);
    std::string output("{\"Status\":"+std::to_string(status)+",\"Value\":");
    if(status!=NO_ERROR)append(output,"null");
    else append(output,"{\"Flags\":"+quote(std::to_string(settings.Flags))+",\"SettingFlags\":"+quote(std::to_string(settings.SettingFlags))
        +",\"Domain\":"+optionalText(settings.Domain)+",\"SearchList\":"+optionalText(settings.SearchList)+"}");
    append(output,"}");return output;
}
std::string adapterDns()
{
    trace("adapter_dns");
    // IP Helper recommends a 15 KB initial buffer; grow only to its actual required size.
    std::vector<unsigned char> buffer(15000);
    IP_ADAPTER_ADDRESSES *adapters=nullptr;
    for(;;){
        ULONG size=ULONG(buffer.size());adapters=reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
        const auto status=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_SKIP_UNICAST|GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST,
            nullptr,adapters,&size);
        if(status==ERROR_NO_DATA)return "[]";
        if(status==NO_ERROR)break;
        if(status!=ERROR_BUFFER_OVERFLOW || size<=buffer.size() || size>limit
            || GetTickCount64()-started>=WindowsDNS::SnapshotTimeoutMs)throw std::runtime_error("native DNS adapter read");
        buffer.resize(size);
    }
    std::string output("[");size_t count=0;
    for(auto *adapter=adapters;adapter;adapter=adapter->Next){
        if(++count>NetworkDnsDomainLimit)throw std::runtime_error("native DNS adapter count");
        GUID id{};wchar_t guid[40]{};
        if(ConvertInterfaceLuidToGuid(&adapter->Luid,&id)!=NO_ERROR || !StringFromGUID2(id,guid,40))
            throw std::runtime_error("native DNS adapter identity");
        if(count>1)append(output,",");
        append(output,"{\"InterfaceIndex\":"+std::to_string(adapter->IfIndex)+",\"Ipv6IfIndex\":"+std::to_string(adapter->Ipv6IfIndex)
            +",\"Guid\":"+quote(utf8(guid))+",\"Luid\":"+quote(std::to_string(adapter->Luid.Value))
            +",\"IfType\":"+std::to_string(adapter->IfType)+",\"OperStatus\":"+std::to_string(adapter->OperStatus)
            +",\"Ipv4Metric\":"+std::to_string(adapter->Ipv4Metric)+",\"Ipv6Metric\":"+std::to_string(adapter->Ipv6Metric)
            +",\"DnsSuffix\":"+optionalText(adapter->DnsSuffix)+",\"DnsServers\":[");
        size_t servers=0;
        for(auto *server=adapter->FirstDnsServerAddress;server;server=server->Next){
            if(++servers>NetworkDnsDomainLimit)throw std::runtime_error("native DNS server count");
            if(servers>1)append(output,",");append(output,dnsEndpoint(server->Address));
        }
        append(output,"],\"Settings\":");append(output,interfaceSettings(id));append(output,"}");
    }
    append(output,"]");return output;
}
void addNamespace(Namespaces &names,const wchar_t *name,size_t &bytes)
{
    if(!name || !*name)throw std::runtime_error("empty native namespace");
    const auto encoded=utf8(name);
    if(names.count(name))return;
    if(encoded.size()>limit-bytes)throw std::runtime_error("native namespace size");
    bytes+=encoded.size();
    names.insert(name);
    if(names.size()>NetworkDnsDomainLimit)throw std::runtime_error("native namespace count");
}
std::string registryScalar(HKEY key,const wchar_t *name,DWORD expectedType)
{
    DWORD type=0,size=0;
    const auto status=RegQueryValueExW(key,name,nullptr,&type,nullptr,&size);
    if(status==ERROR_FILE_NOT_FOUND)return "null";
    registryChecked(status);
    if(type!=expectedType)throw std::runtime_error("unsupported native NRPT scalar type");
    if(size>limit)throw std::runtime_error("native NRPT scalar size");
    if(type==REG_DWORD){
        if(size!=sizeof(DWORD))throw std::runtime_error("invalid native NRPT scalar size");
        DWORD value=0;
        registryChecked(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE *>(&value),&size));
        if(type!=REG_DWORD || size!=sizeof(value))throw std::runtime_error("changed native NRPT scalar");
        return std::to_string(value);
    }
    if(size<sizeof(wchar_t) || size%sizeof(wchar_t))throw std::runtime_error("invalid native NRPT string size");
    std::vector<wchar_t> value(size/sizeof(wchar_t));const auto before=size;
    registryChecked(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE *>(value.data()),&size));
    if(type!=REG_SZ || size!=before || value.back()!=0 || wcsnlen(value.data(),value.size())!=value.size()-1)
        throw std::runtime_error("changed native NRPT scalar");
    return quote(utf8(value.data()));
}
using PolicyRecords=std::map<std::string,std::string>;
Namespaces policyNamespaces(HKEY parent,PolicyRecords *records=nullptr,const char *store="local")
{
    DWORD count=0,longest=0;
    const auto inspected=RegQueryInfoKeyW(parent,nullptr,nullptr,nullptr,&count,&longest,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr);
    if(absentPolicyObject(inspected))return {};
    registryChecked(inspected);
    if(count>NetworkDnsDomainLimit || longest>limit/sizeof(wchar_t))throw std::runtime_error("native NRPT source count");
    std::vector<wchar_t> name(size_t(longest)+1);
    Namespaces names;
    size_t namespaceBytes=0,inputBytes=0,recordBytes=0;
    if(records)for(const auto &entry:*records)recordBytes+=entry.second.size();
    for(DWORD i=0;i<count;++i){
        DWORD length=DWORD(name.size());
        const auto enumerated=RegEnumKeyExW(parent,i,name.data(),&length,nullptr,nullptr,nullptr,nullptr);
        if(enumerated==ERROR_NO_MORE_ITEMS)break;
        if(absentPolicyObject(enumerated))return {};
        registryChecked(enumerated);
        RegistryKey key;
        const auto opened=RegOpenKeyExW(parent,name.data(),0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key.value);
        if(absentPolicyObject(opened))continue;
        registryChecked(opened);
        DWORD type=0,bytes=0;
        const auto status=RegQueryValueExW(key.value,L"Name",nullptr,&type,nullptr,&bytes);
        if(absentPolicyObject(status))continue; // A key without Name is not an active policy scope.
        registryChecked(status);
        if(type!=REG_MULTI_SZ || bytes<2*sizeof(wchar_t) || bytes>limit || bytes%sizeof(wchar_t))
            throw std::runtime_error("native NRPT namespace storage");
        if(bytes>limit-inputBytes)throw std::runtime_error("native namespace source size");
        inputBytes+=bytes;
        std::vector<wchar_t> data(bytes/sizeof(wchar_t));
        const auto expectedBytes=bytes;
        const auto read=RegQueryValueExW(key.value,L"Name",nullptr,&type,reinterpret_cast<BYTE *>(data.data()),&bytes);
        if(absentPolicyObject(read))continue;
        registryChecked(read);
        if(type!=REG_MULTI_SZ || bytes!=expectedBytes || data[data.size()-1] || data[data.size()-2])
            throw std::runtime_error("changed native NRPT namespace storage");
        size_t offset=0;std::string rawNames("[");
        while(offset<data.size() && data[offset]){
            const auto size=wcsnlen(data.data()+offset,data.size()-offset);
            addNamespace(names,data.data()+offset,namespaceBytes);
            if(rawNames.size()>1)append(rawNames,",");
            append(rawNames,quote(utf8(data.data()+offset)));
            offset+=size+1;
        }
        for(;offset<data.size();++offset)if(data[offset])throw std::runtime_error("malformed native NRPT namespace storage");
        if(records){
            append(rawNames,"]");
            wchar_t sourceClass[256]{};DWORD length=256;
            registryChecked(RegQueryInfoKeyW(key.value,sourceClass,&length,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr));
            std::string record="{\"store\":"+quote(store)+",\"id\":"+quote(utf8(name.data()))+",\"class\":"+quote(utf8(sourceClass))
                +",\"namespaces\":"+rawNames+",\"servers\":"+registryScalar(key.value,L"GenericDNSServers",REG_SZ)
                +",\"version\":"+registryScalar(key.value,L"Version",REG_DWORD)+",\"options\":"+registryScalar(key.value,L"ConfigOptions",REG_DWORD)
                +",\"owner\":"+registryScalar(key.value,WindowsDNS::RedirectOwner,REG_SZ)+"}";
            const auto identity=std::string(store)+"/"+utf8(name.data());
            if(recordBytes>limit || record.size()>limit-recordBytes)throw std::runtime_error("native NRPT record size");
            recordBytes+=record.size();
            if(!records->emplace(identity,std::move(record)).second)throw std::runtime_error("changed native NRPT identity");
        }
    }
    return names;
}
Namespaces policySources(PolicyRecords *records=nullptr)
{
    trace("nrpt_sources");
    Namespaces names;
    size_t namespaceBytes=0;
    const std::pair<const wchar_t *,const char *> paths[]{{WindowsDNS::LocalPolicy,"local"},{WindowsDNS::ManagedPolicy,"managed"}};
    for(const auto &[path,store]:paths){
        RegistryKey parent;
        const auto status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,path,0,KEY_READ|KEY_WOW64_64KEY,&parent.value);
        if(absentPolicyObject(status))continue;
        registryChecked(status);
        const auto part=policyNamespaces(parent.value,records,store);
        for(const auto &name:part)addNamespace(names,name.c_str(),namespaceBytes);
        if(names.size()>NetworkDnsDomainLimit)throw std::runtime_error("native namespace count");
    }
    return names;
}
bool backedBySources(const Namespaces &effective,const Namespaces &sources)
{
    for(const auto &name:effective)if(!sources.count(name))return false;
    return true;
}
std::vector<std::wstring> configuredEncryption()
{
    RegistryKey configured;std::vector<std::wstring> result;
    const auto opened=RegOpenKeyExW(HKEY_LOCAL_MACHINE,WindowsDNS::EncryptedServers,REG_OPTION_OPEN_LINK,KEY_READ|KEY_WOW64_64KEY,&configured.value);
    if(opened==ERROR_FILE_NOT_FOUND)return result;
    registryChecked(opened);
    if(RegQueryValueExW(configured.value,L"SymbolicLinkValue",nullptr,nullptr,nullptr,nullptr)!=ERROR_FILE_NOT_FOUND)
        throw std::runtime_error("linked native encrypted servers");
    DWORD count=0,longest=0;
    registryChecked(RegQueryInfoKeyW(configured.value,nullptr,nullptr,nullptr,&count,&longest,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr));
    if(count>NetworkDnsDomainLimit || longest>limit/sizeof(wchar_t))throw std::runtime_error("native encrypted server count");
    std::vector<wchar_t> name(size_t(longest)+1);
    for(DWORD i=0;i<count;++i){
        DWORD size=DWORD(name.size());
        registryChecked(RegEnumKeyExW(configured.value,i,name.data(),&size,nullptr,nullptr,nullptr,nullptr));
        ip(name.data());result.emplace_back(name.data(),size);
    }
    return result;
}
#ifdef JC_DNS_READER_TESTING
void verifyRegistryNamespaces()
{
    // Synthetic HKCU metadata only; the actual resolver policy stores are never changed.
    const auto path=L"Software\\JustConnectDnsReaderCheck-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
    RegistryKey parent;
    DWORD disposition=0;
    registryChecked(RegCreateKeyExW(HKEY_CURRENT_USER,path.c_str(),0,nullptr,REG_OPTION_VOLATILE,
        KEY_ALL_ACCESS|KEY_WOW64_64KEY,nullptr,&parent.value,&disposition));
    if(disposition!=REG_CREATED_NEW_KEY)throw std::runtime_error("existing namespace fixture preserved");
    struct Cleanup {
        RegistryKey &parent;const std::wstring &path;
        ~Cleanup(){
            if(parent.value){RegDeleteTreeW(parent.value,nullptr);RegCloseKey(parent.value);parent.value=nullptr;}
            RegDeleteKeyExW(HKEY_CURRENT_USER,path.c_str(),KEY_WOW64_64KEY,0);
        }
    } cleanup{parent,path};
    if(!policyNamespaces(parent.value).empty())throw std::runtime_error("empty namespace source");
    RegistryKey rule;
    registryChecked(RegCreateKeyExW(parent.value,L"rule",0,nullptr,REG_OPTION_VOLATILE,KEY_ALL_ACCESS|KEY_WOW64_64KEY,nullptr,&rule.value,nullptr));
    const wchar_t values[]=L".Campus.Test\0host.original.test\0";
    registryChecked(RegSetValueExW(rule.value,L"Name",0,REG_MULTI_SZ,reinterpret_cast<const BYTE *>(values),sizeof(values)));
    Namespaces effective;size_t namespaceBytes=0;
    addNamespace(effective,L".campus.test",namespaceBytes);addNamespace(effective,L"HOST.ORIGINAL.TEST",namespaceBytes);
    const auto active=policyNamespaces(parent.value);
    if(active.size()!=2 || !backedBySources(effective,active))throw std::runtime_error("native namespace case or array handling");
    const wchar_t originalServers[]=L" 192.0.2.53 ; 2001:db8::53 ",owner[]=L"{2717939F-2E6F-4F37-A293-8A4F3EDBC3E5}";
    registryChecked(RegSetValueExW(rule.value,L"GenericDNSServers",0,REG_SZ,reinterpret_cast<const BYTE *>(originalServers),sizeof(originalServers)));
    const DWORD version=1,options=8;
    registryChecked(RegSetValueExW(rule.value,L"Version",0,REG_DWORD,reinterpret_cast<const BYTE *>(&version),sizeof(version)));
    registryChecked(RegSetValueExW(rule.value,L"ConfigOptions",0,REG_DWORD,reinterpret_cast<const BYTE *>(&options),sizeof(options)));
    PolicyRecords before,after;
    if(policyNamespaces(parent.value,&before)!=active || before.size()!=1
        || before.at("local/rule").find("\"servers\":\" 192.0.2.53 ; 2001:db8::53 \"")==std::string::npos
        || before.at("local/rule").find("\"version\":1,\"options\":8,\"owner\":null")==std::string::npos)
        throw std::runtime_error("native NRPT source identity or original formatting lost");
    registryChecked(RegSetValueExW(rule.value,WindowsDNS::RedirectOwner,0,REG_SZ,reinterpret_cast<const BYTE *>(owner),sizeof(owner)));
    if(policyNamespaces(parent.value,&after)!=active || before==after
        || after.at("local/rule").find(quote(utf8(owner)))==std::string::npos)
        throw std::runtime_error("same-namespace ownership change lost");
    before=after;after.clear();
    const wchar_t listener[]=L"127.0.0.1";
    registryChecked(RegSetValueExW(rule.value,L"GenericDNSServers",0,REG_SZ,reinterpret_cast<const BYTE *>(listener),sizeof(listener)));
    if(policyNamespaces(parent.value,&after)!=active || before==after)throw std::runtime_error("same-namespace endpoint change lost");
    registryChecked(RegSetValueExW(rule.value,L"Version",0,REG_SZ,reinterpret_cast<const BYTE *>(listener),sizeof(listener)));
    after.clear();bool typeRefused=false;
    try{policyNamespaces(parent.value,&after);}catch(const std::runtime_error &){typeRefused=true;}
    if(!typeRefused)throw std::runtime_error("unsupported native policy type became a configured version");
    addNamespace(effective,L"deleted.original.test",namespaceBytes);
    if(backedBySources(effective,active))throw std::runtime_error("unbacked effective namespace accepted");
    registryChecked(RegDeleteValueW(rule.value,L"Name"));
    const auto inactive=policyNamespaces(parent.value);
    if(!inactive.empty() || backedBySources(effective,inactive))throw std::runtime_error("deleted namespace source remained active");
    const DWORD malformed=1;
    registryChecked(RegSetValueExW(rule.value,L"Name",0,REG_DWORD,reinterpret_cast<const BYTE *>(&malformed),sizeof(malformed)));
    bool rejected=false;
    try{policyNamespaces(parent.value);}catch(const std::runtime_error &){rejected=true;}
    if(!rejected)throw std::runtime_error("malformed namespace source accepted");
    registryChecked(RegSetValueExW(rule.value,L"Name",0,REG_MULTI_SZ,reinterpret_cast<const BYTE *>(values),sizeof(values)-sizeof(wchar_t)));
    rejected=false;
    try{policyNamespaces(parent.value);}catch(const std::runtime_error &){rejected=true;}
    if(!rejected)throw std::runtime_error("unterminated namespace source accepted");
    registryChecked(RegSetValueExW(rule.value,L"Name",0,REG_MULTI_SZ,reinterpret_cast<const BYTE *>(values),sizeof(values)));
    registryChecked(RegDeleteKeyExW(parent.value,L"rule",KEY_WOW64_64KEY,0));
    if(!policyNamespaces(parent.value).empty())throw std::runtime_error("delete-pending namespace source remained active");
    registryChecked(RegCloseKey(rule.value));rule.value=nullptr;
    registryChecked(RegDeleteTreeW(parent.value,nullptr));
    registryChecked(RegCloseKey(parent.value));parent.value=nullptr;
    registryChecked(RegDeleteKeyExW(HKEY_CURRENT_USER,path.c_str(),KEY_WOW64_64KEY,0));
}
#endif
struct Element {
    MI_Value value{};
    MI_Type type = MI_BOOLEAN;
    MI_Uint32 flags = MI_FLAG_NULL;
};
Element element(const MI_Instance *row, const wchar_t *name)
{
    Element item;
    const auto result = MI_Instance_GetElement(row, name, &item.value, &item.type, &item.flags, nullptr);
    if (result == MI_RESULT_NO_SUCH_PROPERTY || result == MI_RESULT_NOT_FOUND) return {};
    require(result);
    return item;
}
std::string value(const Element &item)
{
    if (item.flags & MI_FLAG_NULL) return "null";
    const auto &v = item.value;
    switch (item.type) {
    case MI_BOOLEAN: return v.boolean ? "true" : "false";
    case MI_UINT8: return std::to_string(v.uint8);
    case MI_SINT8: return std::to_string(v.sint8);
    case MI_UINT16: return std::to_string(v.uint16);
    case MI_SINT16: return std::to_string(v.sint16);
    case MI_UINT32: return std::to_string(v.uint32);
    case MI_SINT32: return std::to_string(v.sint32);
    case MI_SINT64: return std::to_string(v.sint64);
    case MI_UINT64:
        if (v.uint64 > static_cast<MI_Uint64>(std::numeric_limits<long long>::max())) throw std::runtime_error("native integer size");
        return std::to_string(v.uint64);
    case MI_STRING: return v.string ? quote(utf8(v.string)) : "null";
    case MI_STRINGA: {
        if (v.stringa.size > 4096) throw std::runtime_error("native array size");
        std::string output("[");
        for (MI_Uint32 i = 0; i < v.stringa.size; ++i) {
            if (i) append(output, ",");
            append(output, v.stringa.data[i] ? quote(utf8(v.stringa.data[i])) : "null");
        }
        append(output, "]");
        return output;
    }
    default: throw std::runtime_error("native property type");
    }
}
std::string strings(const Element &item, bool addresses)
{
    if (item.flags & MI_FLAG_NULL) return "[]";
    std::string output("[");
    bool first = true;
    const auto add = [&](const wchar_t *text) {
        if (!text) return;
        if (!first) append(output, ",");
        append(output, quote(addresses ? ip(text) : utf8(text)));
        first = false;
    };
    if (item.type == MI_STRING) add(item.value.string);
    else if (item.type == MI_STRINGA) {
        if (item.value.stringa.size > 4096) throw std::runtime_error("native array size");
        for (MI_Uint32 i = 0; i < item.value.stringa.size; ++i) add(item.value.stringa.data[i]);
    } else throw std::runtime_error("native string array");
    append(output, "]");
    return output;
}
std::string row(const MI_Instance *instance, std::initializer_list<const wchar_t *> fields)
{
    std::string output("{");
    bool first = true;
    for (const auto *name : fields) {
        if (!first) append(output, ",");
        first = false;
        append(output, quote(utf8(name)) + ":");
        const auto item = element(instance, name);
        const std::wstring field(name);
        if (field == L"Namespace" || field == L"NameServers" || field == L"DirectAccessDnsServers"
            || field == L"ServerAddresses" || field == L"ConnectionSpecificSuffixSearchList" || field == L"SuffixSearchList")
            append(output, strings(item, field == L"NameServers" || field == L"DirectAccessDnsServers"));
        else if (field == L"ConnectionSpecificSuffix" && (item.flags & MI_FLAG_NULL)) append(output, "\"\"");
        else append(output, value(item));
    }
    append(output, "}");
    return output;
}
struct Operation {
    MI_Operation handle = MI_OPERATION_NULL;
    ~Operation() { if (handle.ft) MI_Operation_Close(&handle); }
};
struct Session {
    HMODULE library = nullptr;
    MI_Application application = MI_APPLICATION_NULL;
    MI_Session handle = MI_SESSION_NULL;
    ~Session() {
        if (handle.ft) MI_Session_Close(&handle, nullptr, nullptr);
        if (application.ft) MI_Application_Close(&application);
        if (library) FreeLibrary(library);
    }
    void open() {
        trace("native");
        library = LoadLibraryExW(L"mi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) throw std::runtime_error("system MI library");
        const auto initialize = reinterpret_cast<decltype(&MI_Application_InitializeV1)>(GetProcAddress(library, "MI_Application_InitializeV1"));
        if (!initialize) throw std::runtime_error("system MI entry");
        require(initialize(0, nullptr, nullptr, &application));
        trace("local_session");
        require(MI_Application_NewSession(&application, L"WMIDCOM", nullptr, nullptr, nullptr, nullptr, &handle));
    }
};
template<typename Consume>
void consume(Operation &operation, Consume callback)
{
    MI_Boolean more = MI_TRUE;
    size_t count = 0;
    while (more) {
        const MI_Instance *instance = nullptr, *details = nullptr;
        const MI_Char *error = nullptr;
        MI_Result result = MI_RESULT_OK;
        require(MI_Operation_GetInstance(&operation.handle, &instance, &more, &result, &error, &details));
        require(result);
        if (instance) {
            if (++count > 4096) throw std::runtime_error("native result count");
            callback(instance);
        }
    }
}
std::string query(Session &session, const wchar_t *name, const char *stage, std::initializer_list<const wchar_t *> fields, bool singleton = false)
{
    trace(stage);
    Operation operation;
    const auto statement = std::wstring(L"SELECT * FROM ") + name;
    MI_Session_QueryInstances(&session.handle, 0, nullptr, L"ROOT\\StandardCimv2", L"WQL", statement.c_str(), nullptr, &operation.handle);
    std::string output("[");
    bool first = true;
    size_t count = 0;
    consume(operation, [&](const MI_Instance *instance) {
        ++count;
        if (!first) append(output, ",");
        first = false;
        append(output, row(instance, fields));
    });
    append(output, "]");
    if (singleton && count != 1) throw std::runtime_error("native global settings count");
    return singleton ? output.substr(1, output.size()-2) : output;
}
bool dohSupported(Session &session, const wchar_t *name)
{
    trace("doh_class");
    Operation operation;
    MI_Session_GetClass(&session.handle, 0, nullptr, L"ROOT\\StandardCimv2", name, nullptr, &operation.handle);
    const MI_Class *type = nullptr;
    const MI_Instance *details = nullptr;
    const MI_Char *error = nullptr;
    MI_Boolean more = MI_FALSE;
    MI_Result result = MI_RESULT_OK;
    const auto received = MI_Operation_GetClass(&operation.handle, &type, &more, &result, &error, &details);
    if (received == MI_RESULT_INVALID_CLASS || received == MI_RESULT_NOT_FOUND
        || result == MI_RESULT_INVALID_CLASS || result == MI_RESULT_NOT_FOUND) return false;
    require(received);
    require(result);
    if (!type || more) throw std::runtime_error("native DoH class");
    return true;
}
struct NrptResult {std::string json;Namespaces names;};
NrptResult nrpt(Session &session, const wchar_t *name, bool emptyFixture)
{
    trace("nrpt");
    MI_Instance *parameters = nullptr;
    require(MI_Application_NewInstance(&session.application, L"Parameters", nullptr, &parameters));
    struct Release { MI_Instance *instance; ~Release() { MI_Instance_Delete(instance); } } release{parameters};
    MI_Value effective{};
    effective.boolean = MI_TRUE;
    require(MI_Instance_AddElement(parameters, L"Effective", &effective, MI_BOOLEAN, MI_FLAG_IN));
    Operation operation;
    MI_Session_Invoke(&session.handle, 0, nullptr, L"ROOT\\Microsoft\\Windows\\DNS", name, L"Get", nullptr, parameters, nullptr, &operation.handle);
    std::string output("[");
    Namespaces namespaces;
    size_t namespaceBytes=0;
    bool first = true, found = false;
    consume(operation, [&](const MI_Instance *instance) {
        if (found) throw std::runtime_error("native NRPT result count");
        found = true;
        if (emptyFixture) return;
        const auto policies = element(instance, L"cmdletOutput"), code = element(instance, L"ReturnValue");
        if (!(code.flags & MI_FLAG_NULL) && (code.type != MI_UINT32 || code.value.uint32 != 0))
            throw std::runtime_error("native NRPT return code");
        if (policies.flags & MI_FLAG_NULL) return;
        if (policies.type != MI_INSTANCEA || policies.value.instancea.size > 4096
            || ((code.flags & MI_FLAG_NULL) && policies.value.instancea.size)) throw std::runtime_error("native NRPT output");
        trace("nrpt_rows");
        for (MI_Uint32 i = 0; i < policies.value.instancea.size; ++i) {
            if (!first) append(output, ",");
            first = false;
            const auto scope=element(policies.value.instancea.data[i],L"Namespace");
            if(scope.flags&MI_FLAG_NULL)throw std::runtime_error("missing native NRPT namespace");
            if(scope.type==MI_STRING)addNamespace(namespaces,scope.value.string,namespaceBytes);
            else if(scope.type==MI_STRINGA && scope.value.stringa.size<=NetworkDnsDomainLimit){
                for(MI_Uint32 n=0;n<scope.value.stringa.size;++n)addNamespace(namespaces,scope.value.stringa.data[n],namespaceBytes);
            }else throw std::runtime_error("native NRPT namespace type");
            append(output, row(policies.value.instancea.data[i], {L"Namespace",L"NameServers",L"DirectAccessEnabled",L"DirectAccessDnsServers",L"DirectAccessIPsecCARestriction",L"DirectAccessProxyName",L"DirectAccessProxyType",L"DirectAccessQueryIPsecEncryption",L"DirectAccessQueryIPsecRequired",L"DnsSecIPsecCARestriction",L"DnsSecQueryIPsecEncryption",L"DnsSecQueryIPsecRequired",L"DnsSecValidationRequired",L"NameEncoding",L"QueryPolicy",L"SecureNameQueryFallback"}));
        }
    });
    append(output, "]");
    return {output,namespaces};
}
std::string snapshot(const wchar_t *nrptClass, const wchar_t *dohClass, bool emptyFixture)
{
    Session session;
    session.open();
    NrptResult policies;PolicyRecords records;
    for(;;){
        if(GetTickCount64()-started>=WindowsDNS::SnapshotTimeoutMs)throw std::runtime_error("native NRPT source convergence timeout");
        PolicyRecords beforeRecords,afterRecords;
        const auto before=policySources(&beforeRecords);
        policies=nrpt(session,nrptClass,emptyFixture);
        const auto after=policySources(&afterRecords);
        // The effective provider can lag deletion; do not adopt an unbacked scope as original policy.
        if(before==after && beforeRecords==afterRecords && backedBySources(policies.names,after)){records=std::move(afterRecords);break;}
        trace("nrpt_consistency");Sleep(WindowsDNS::ConsistencyPollMs);
    }
    const bool supported = dohSupported(session, dohClass);
    const auto doh = supported ? query(session,dohClass,"MSFT_DNSClientDohServerAddress",{L"ServerAddress",L"DohTemplate",L"AllowFallbackToUdp",L"AutoUpgrade"}) : "[]";
    const auto interfaces = query(session,L"MSFT_DNSClientServerAddress","MSFT_DNSClientServerAddress",{L"InterfaceIndex",L"AddressFamily",L"ServerAddresses"});
    const auto clients = query(session,L"MSFT_DNSClient","MSFT_DNSClient",{L"InterfaceIndex",L"ConnectionSpecificSuffix",L"ConnectionSpecificSuffixSearchList",L"RegisterThisConnectionsAddress",L"UseSuffixWhenRegistering"});
    const auto globals = query(session,L"MSFT_DNSClientGlobalSetting","MSFT_DNSClientGlobalSetting",{L"SuffixSearchList",L"UseDevolution",L"DevolutionLevel",L"AppendParentSuffixes",L"AppendPrimarySuffixes"},true);
    const auto adapters=adapterDns(), nativeGlobal=globalSettings();
    std::string output("{\"interfaces\":");
    append(output,interfaces);append(output,",\"clients\":");append(output,clients);
    append(output,",\"global\":");append(output,globals);
    append(output,",\"nrpt\":");append(output,policies.json);
    append(output,",\"nrpt_sources\":[");
    bool firstSource=true;
    for(const auto &entry:records){if(!firstSource)append(output,",");firstSource=false;append(output,entry.second);}
    append(output,"]");
    append(output,",\"doh_supported\":");append(output,supported ? "true" : "false");
    append(output,",\"doh\":");append(output,doh);
    append(output,",\"configured_encryption\":[");bool firstEncrypted=true;
    for(const auto &server:configuredEncryption()){
        if(!firstEncrypted)append(output,",");firstEncrypted=false;append(output,quote(ip(server.c_str())));
    }
    append(output,"]");
    append(output,",\"adapters\":");append(output,adapters);
    append(output,",\"native_global\":");append(output,nativeGlobal);append(output,"}");
    trace("serialize");
    return output;
}
#endif
}

#ifdef JC_DNS_READER_LIBRARY
std::vector<std::wstring> WindowsDNS::knownNrptEncryptedServers() try
{
    started=GetTickCount64();
    Session session;session.open();
    if(!dohSupported(session,L"MSFT_DNSClientDohServerAddress"))throw std::runtime_error("native NRPT DoH table unavailable");
    Operation operation;
    MI_Session_QueryInstances(&session.handle,0,nullptr,L"ROOT\\StandardCimv2",L"WQL",L"SELECT * FROM MSFT_DNSClientDohServerAddress",nullptr,&operation.handle);
    std::vector<std::wstring> result;
    consume(operation,[&](const MI_Instance *instance){
        const auto server=element(instance,L"ServerAddress");
        if((server.flags&MI_FLAG_NULL) || server.type!=MI_STRING || !server.value.string)throw std::runtime_error("native NRPT DoH server missing");
        ip(server.value.string);
        result.emplace_back(server.value.string);
    });
    const auto configured=configuredEncryption();result.insert(result.end(),configured.begin(),configured.end());
    return result;
}catch(const ProviderFailure &failure){
    throw std::runtime_error("native NRPT DoH provider failed: "+std::to_string(unsigned(failure.code)));
}
#else
int main(int argc, char **argv) try
{
    const wchar_t *nrptClass = L"PS_DnsClientNrptPolicy", *dohClass = L"MSFT_DNSClientDohServerAddress";
    bool emptyFixture = false;
#ifdef JC_DNS_READER_TESTING
#ifdef _WIN32
    if (argc == 2 && std::strcmp(argv[1], "--stall") == 0) {
        started = GetTickCount64();
        trace("native");
        Sleep(INFINITE);
    }
#endif
    if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0) {
        if (quote(std::string("\0\n\t\"\\",5)) != "\"\\u0000\\u000a\\u0009\\\"\\\\\""
            || quote("\xc3\xa9") != "\"\xc3\xa9\"") throw std::runtime_error("JSON escaping");
#ifdef _WIN32
        if (ip(L"2001:0DB8:0000::1%0012") != "2001:db8::1%12") throw std::runtime_error("IP normalization");
        bool rejected = false;
        try { ip(L"2001:db8::1%4294967296"); } catch (const std::exception &) { rejected = true; }
        if (!rejected) throw std::runtime_error("IP scope limit");
        sockaddr_in6 server{};server.sin6_family=AF_INET6;server.sin6_scope_id=7;server.sin6_port=htons(5353);
        if(InetPtonW(AF_INET6,L"fe80::53",&server.sin6_addr)!=1)throw std::runtime_error("native DNS fixture address");
        SOCKET_ADDRESS endpoint{reinterpret_cast<sockaddr *>(&server),sizeof(server)};
        if(dnsEndpoint(endpoint)!="{\"Address\":\"fe80::53%7\",\"Port\":5353}")throw std::runtime_error("native DNS endpoint scope and port");
        server.sin6_port=0;
        if(dnsEndpoint(endpoint)!="{\"Address\":\"fe80::53%7\",\"Port\":53}")throw std::runtime_error("native DNS protocol port");
        endpoint.iSockaddrLength=sizeof(ADDRESS_FAMILY);
        rejected=false;try{dnsEndpoint(endpoint);}catch(const std::exception &){rejected=true;}
        if(!rejected)throw std::runtime_error("truncated native DNS socket");
        DNS_DOH_SERVER_SETTINGS encrypted{};encrypted.Flags=std::numeric_limits<ULONG64>::max();
        DNS_SERVER_PROPERTY security[2]{};
        security[0].Version=DNS_SERVER_PROPERTY_VERSION1;security[0].ServerIndex=1;
        security[0].Type=DnsServerDohProperty;security[0].Property.DohSettings=&encrypted;
        security[1].Version=2;security[1].Type=static_cast<DNS_SERVER_PROPERTY_TYPE>(99);
        const auto encoded=serverProperties(2,security);
        if(encoded.find("\"Template\":null,\"Flags\":\"18446744073709551615\"")==std::string::npos
            || encoded.find("\"Type\":99,\"Settings\":null")==std::string::npos)
            throw std::runtime_error("native security flags or unknown property lost");
        rejected=false;try{checkSettingsStatus(ERROR_ACCESS_DENIED);}catch(const std::exception &){rejected=true;}
        if(!rejected)throw std::runtime_error("DNS settings access failure downgraded to unavailable");
        const wchar_t invalid[] = {wchar_t(0xd800),0};
        rejected = false;
        try { utf8(invalid); } catch (const std::exception &) { rejected = true; }
        if (!rejected) throw std::runtime_error("Invalid Unicode");
        Element item;
        if (strings(item,false) != "[]" || value(item) != "null") throw std::runtime_error("Null property");
        wchar_t one[] = L"private.test";
        MI_Char *names[] = {one,nullptr};
        item.flags = 0; item.type = MI_STRINGA; item.value.stringa = {names,2};
        if (strings(item,false) != "[\"private.test\"]" || value(item) != "[\"private.test\",null]") throw std::runtime_error("String arrays");
        verifyRegistryNamespaces();
#endif
        std::string output(limit, 'x');
        try { append(output,"x"); } catch (const std::runtime_error &) { std::puts("PASS: bounded DNS JSON and control/Unicode escaping"); return 0; }
        throw std::runtime_error("JSON limit");
    }
    if (argc == 2 && std::strcmp(argv[1], "--missing-doh") == 0) dohClass = L"JustConnectMissingDnsClass";
    else if (argc == 2 && std::strcmp(argv[1], "--missing-nrpt") == 0) nrptClass = L"JustConnectMissingDnsClass";
    else if (argc == 2 && std::strcmp(argv[1], "--empty-nrpt") == 0) emptyFixture = true;
    else
#endif
    if (argc != 1) throw std::runtime_error("arguments");
#ifdef _WIN32
    started = GetTickCount64();
    const auto output = snapshot(nrptClass,dohClass,emptyFixture);
    if (std::fwrite(output.data(), 1, output.size(), stdout) != output.size() || std::fflush(stdout) != 0) return 1;
    return 0;
#else
    throw std::runtime_error("Windows only");
#endif
#ifdef _WIN32
} catch (const ProviderFailure &failure) {
    std::fprintf(stderr, "Native DNS provider failed with code %u%s; no partial snapshot published.\n",
                 unsigned(failure.code), failure.code == MI_RESULT_ACCESS_DENIED ? ": permission denied" : "");
    return 1;
#endif
} catch (const std::exception &) {
    std::fputs("Native DNS snapshot failed; no partial snapshot published.\n", stderr);
    return 1;
}
#endif
