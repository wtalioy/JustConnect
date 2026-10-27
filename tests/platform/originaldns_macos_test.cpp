#include "infrastructure/dns/macos/originaldns.h"
#include "infrastructure/dns/macos/propertylist.h"
#include "infrastructure/networkaddress/ipv4.h"
#include <QCoreApplication>
#include <QJsonObject>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *message)
{
    if(!value)throw std::runtime_error(std::string(message)+" (last SystemConfiguration status: "+std::to_string(SCError())+")");
}
static QString encoded(CFPropertyListRef value)
{
    const auto data=CFPropertyListCreateData(nullptr,value,kCFPropertyListBinaryFormat_v1_0,0,nullptr);check(data,"Encode native fixture");
    const auto result=QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(data)),CFDataGetLength(data)).toBase64();CFRelease(data);
    return QString::fromLatin1(result);
}
static int fixtureSource(const QString &address,int port)
{
    check(::geteuid()==0 && qgetenv("GITHUB_ACTIONS")=="true" && qgetenv("RUNNER_OS")=="macOS",
        "System DNS fixture requires the disposable macOS runner");
    check(canonicalUnicastIpv4(address) && port>0 && port<=65535,"Complete fixture DNS endpoint");
    ifaddrs *addresses=nullptr;check(::getifaddrs(&addresses)==0,"Read fixture interface addresses");
    const auto freeAddresses=qScopeGuard([&]{::freeifaddrs(addresses);});QString name,mask;
    for(auto *row=addresses;row;row=row->ifa_next){
        if(!row->ifa_addr || !row->ifa_netmask || row->ifa_addr->sa_family!=AF_INET || !(row->ifa_flags&IFF_UP))continue;
        char value[INET_ADDRSTRLEN]{},netmask[INET_ADDRSTRLEN]{};
        if(::inet_ntop(AF_INET,&reinterpret_cast<sockaddr_in *>(row->ifa_addr)->sin_addr,value,sizeof(value)) && address==QString::fromLatin1(value)
            && ::inet_ntop(AF_INET,&reinterpret_cast<sockaddr_in *>(row->ifa_netmask)->sin_addr,netmask,sizeof(netmask))){name=QString::fromLatin1(row->ifa_name);mask=QString::fromLatin1(netmask);break;}
    }
    check(!name.isEmpty(),"Fixture DNS endpoint must be assigned to a live interface");
    const auto interfaces=SCNetworkInterfaceCopyAll();check(interfaces,"Read fixture interface metadata");
    const auto freeInterfaces=qScopeGuard([&]{CFRelease(interfaces);});SCNetworkInterfaceRef interface=nullptr;
    for(CFIndex i=0;i<CFArrayGetCount(interfaces);++i){
        const auto candidate=static_cast<SCNetworkInterfaceRef>(CFArrayGetValueAtIndex(interfaces,i));const auto bsd=SCNetworkInterfaceGetBSDName(candidate);
        if(bsd && QString::fromCFString(bsd)==name){interface=candidate;break;}
    }
    check(interface,"Find actual fixture network interface metadata");
    const auto preferences=SCPreferencesCreate(nullptr,CFSTR("JustConnect owned DNS fixture"),nullptr);check(preferences,"Open fixture preferences");
    const auto releasePrefs=qScopeGuard([&]{CFRelease(preferences);});
    check(SCPreferencesLock(preferences,false),"Lock fixture creation");bool locked=true;
    const auto unlock=qScopeGuard([&]{if(locked)SCPreferencesUnlock(preferences);});
    const auto service=SCNetworkServiceCreate(preferences,interface);check(service,"Create owned DNS-only fixture service");
    const auto releaseService=qScopeGuard([&]{CFRelease(service);});
    const auto set=SCNetworkSetCopyCurrent(preferences);check(set,"Read current native network set");const auto freeSet=qScopeGuard([&]{CFRelease(set);});
    SCDynamicStoreRef store=nullptr;bool removed=false;
    const auto cleanup=[&]{
        if(removed)return true;
        if(store){CFRelease(store);store=nullptr;}
        if(!locked){SCPreferencesSynchronize(preferences);if(!SCPreferencesLock(preferences,false))return false;locked=true;}
        const auto present=SCNetworkServiceCopy(preferences,SCNetworkServiceGetServiceID(service));
        bool restored=true;
        if(present){
            restored=SCNetworkSetRemoveService(set,present) && SCNetworkServiceRemove(present)
                && SCPreferencesCommitChanges(preferences) && SCPreferencesApplyChanges(preferences);CFRelease(present);
        }
        SCPreferencesUnlock(preferences);locked=false;removed=restored;return restored;
    };
    const auto recover=qScopeGuard([&]{if(!cleanup())std::cerr<<"Owned DNS fixture cleanup remains incomplete\n";});
    check(SCNetworkServiceSetName(service,CFSTR("JustConnect original DNS fixture")) && SCNetworkServiceSetEnabled(service,true)
        && SCNetworkSetAddService(set,service),"Prepare owned DNS-only service");
    auto dns=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeDNS);
    if(!dns){check(SCNetworkServiceAddProtocolType(service,kSCNetworkProtocolTypeDNS),"Add fixture DNS protocol");dns=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeDNS);}
    check(dns,"Open fixture DNS protocol");const auto freeDNS=qScopeGuard([&]{CFRelease(dns);});
    const auto properties=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    const auto freeProperties=qScopeGuard([&]{CFRelease(properties);});const auto server=address.toCFString();const void *serverValue=server;
    const auto servers=CFArrayCreate(nullptr,&serverValue,1,&kCFTypeArrayCallBacks);CFRelease(server);
    CFDictionarySetValue(properties,kSCPropNetDNSServerAddresses,servers);CFRelease(servers);
    const auto number=CFNumberCreate(nullptr,kCFNumberIntType,&port);CFDictionarySetValue(properties,kSCPropNetDNSServerPort,number);CFRelease(number);
    const void *domain[]{CFSTR("campus.test")};const auto domains=CFArrayCreate(nullptr,domain,1,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(properties,kSCPropNetDNSSupplementalMatchDomains,domains);CFRelease(domains);
    const int noSearch=1;const auto flag=CFNumberCreate(nullptr,kCFNumberIntType,&noSearch);CFDictionarySetValue(properties,CFSTR("SupplementalMatchDomainsNoSearch"),flag);CFRelease(flag);
    check(SCNetworkProtocolSetConfiguration(dns,properties) && SCPreferencesCommitChanges(preferences) && SCPreferencesApplyChanges(preferences),"Commit owned fixture DNS service");
    SCPreferencesUnlock(preferences);locked=false;
    store=SCDynamicStoreCreate(nullptr,CFSTR("JustConnect owned DNS source IPv4"),nullptr,nullptr);check(store,"Open fixture service state");
    const auto key=SCDynamicStoreKeyCreateNetworkServiceEntity(nullptr,kSCDynamicStoreDomainState,SCNetworkServiceGetServiceID(service),kSCEntNetIPv4);
    const auto freeKey=qScopeGuard([&]{CFRelease(key);});
    const auto ipv4=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);const auto freeIPv4=qScopeGuard([&]{CFRelease(ipv4);});
    const auto bsd=name.toCFString();CFDictionarySetValue(ipv4,kSCPropInterfaceName,bsd);CFRelease(bsd);
    for(const auto &pair:{std::pair{kSCPropNetIPv4Addresses,address},std::pair{kSCPropNetIPv4SubnetMasks,mask}}){
        const auto text=pair.second.toCFString();const void *item=text;const auto values=CFArrayCreate(nullptr,&item,1,&kCFTypeArrayCallBacks);CFRelease(text);
        CFDictionarySetValue(ipv4,pair.first,values);CFRelease(values);
    }
    check(SCDynamicStoreAddTemporaryValue(store,key,ipv4),"Publish the actual fixture source interface without configuring its kernel addresses");
    std::cout<<"{\"service\":\""<<QString::fromCFString(SCNetworkServiceGetServiceID(service)).toStdString()<<"\"}"<<std::endl;
    std::string command;check(bool(std::getline(std::cin,command)) && command=="restore","Owned fixture shutdown command");
    check(cleanup(),"Remove only the owned fixture service and temporary state");
    std::cout<<"PASS: owned native original DNS fixture removed\n";return 0;
}
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv);
    if(argc==4 && app.arguments()[1]=="--fixture-source")return fixtureSource(app.arguments()[2],app.arguments()[3].toInt());
    check(argc==2 && app.arguments()[1]=="--isolated" && ::geteuid()==0
        && qgetenv("GITHUB_ACTIONS")=="true" && qgetenv("RUNNER_OS")=="macOS",
        "Private preferences writes require the disposable macOS root fixture");
    ::alarm(20);
    QTemporaryDir directory;check(directory.isValid(),"Create private preferences directory");
    const auto filename=directory.filePath("dns.plist").toCFString();
    const auto preferences=SCPreferencesCreate(nullptr,CFSTR("JustConnect DNS tests"),filename);CFRelease(filename);
    check(preferences,"Open private native preferences");const auto releasePrefs=qScopeGuard([&]{CFRelease(preferences);});
    const auto interfaces=SCNetworkInterfaceCopyAll();check(interfaces,"Read interface metadata");
    const auto releaseInterfaces=qScopeGuard([&]{CFRelease(interfaces);});SCNetworkInterfaceRef interface=nullptr;
    for(CFIndex i=0;i<CFArrayGetCount(interfaces);++i){
        const auto candidate=static_cast<SCNetworkInterfaceRef>(CFArrayGetValueAtIndex(interfaces,i));
        if(CFEqual(SCNetworkInterfaceGetInterfaceType(candidate),kSCNetworkInterfaceTypeEthernet)){interface=candidate;break;}
    }
    check(interface,"Find native Ethernet metadata");const auto service=SCNetworkServiceCreate(preferences,interface);
    check(service && SCNetworkServiceSetEnabled(service,true),"Create enabled private service");const auto releaseService=qScopeGuard([&]{CFRelease(service);});
    auto initial=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeDNS);
    if(!initial){check(SCNetworkServiceAddProtocolType(service,kSCNetworkProtocolTypeDNS),"Add private DNS protocol");initial=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeDNS);}
    check(initial,"Open private DNS protocol");const auto releaseInitial=qScopeGuard([&]{CFRelease(initial);});
    const auto original=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    const auto freeOriginal=qScopeGuard([&]{CFRelease(original);});
    const void *server[]{CFSTR("192.0.2.53"),CFSTR("2001:db8::53")};const auto servers=CFArrayCreate(nullptr,server,2,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(original,kSCPropNetDNSServerAddresses,servers);CFRelease(servers);
    int port=5353;const auto number=CFNumberCreate(nullptr,kCFNumberIntType,&port);CFDictionarySetValue(original,kSCPropNetDNSServerPort,number);CFRelease(number);
    const void *domain[]{CFSTR("original.test")};const auto domains=CFArrayCreate(nullptr,domain,1,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(original,kSCPropNetDNSSupplementalMatchDomains,domains);CFRelease(domains);
    const auto seed=[&]{
        check(SCNetworkProtocolSetConfiguration(initial,original),"Stage private DNS preferences");
        check(SCPreferencesCommitChanges(preferences),"Commit private DNS preferences");
    };
    seed();
    const auto id=QString::fromCFString(SCNetworkServiceGetServiceID(service));const auto owner=QUuid::createUuid();
    ifaddrs *addresses=nullptr;check(::getifaddrs(&addresses)==0,"Read actual local addresses");const auto freeAddresses=qScopeGuard([&]{::freeifaddrs(addresses);});QString local;
    for(auto *row=addresses;row;row=row->ifa_next){
        if(!row->ifa_addr || row->ifa_addr->sa_family!=AF_INET || !(row->ifa_flags&IFF_UP))continue;
        char text[INET_ADDRSTRLEN]{};const auto address=reinterpret_cast<sockaddr_in *>(row->ifa_addr)->sin_addr;
        if(::inet_ntop(AF_INET,&address,text,sizeof(text)) && canonicalUnicastIpv4(QString::fromLatin1(text))){local=QString::fromLatin1(text);break;}
    }
    check(!local.isEmpty(),"Find an assigned unicast IPv4 address");
    const QJsonArray sources{QJsonObject{{"service",id},{"original",encoded(original)},{"listen",local+":54321"}}};
    QJsonObject record;bool rejectActive=false;
    const auto checkpoint=[&](const QJsonObject &value){
        if(rejectActive && value["phase"]=="active")return PlatformOperationResult{PlatformOperationResult::Status::Failed,"checkpoint refused",true};
        record=value;return PlatformOperationResult{};
    };
    const PlatformCommandRunner inspect=[&](const QString &program,const QStringList &arguments){
        check(program=="/usr/sbin/scutil" && arguments==QStringList{"--dns"},"Unexpected native inspection target");
        return PlatformCommandResult{{},record["phase"]=="active"?"DNS configuration\nresolver #1\n domain : original.test\n nameserver[0] : "+local+"\n port : 54321\n flags : Supplemental\n":"No DNS configuration available",{}};
    };
    const auto read=[&]{SCPreferencesSynchronize(preferences);const auto value=SCNetworkProtocolGetConfiguration(initial);check(value,"Read private DNS configuration");return macDnsProperties(value)->toObject();};
    const auto before=read();
    {
        MacOriginalDns dns(preferences,inspect);
        const auto rejected=dns.apply(owner,sources,[](const QJsonObject &){return PlatformOperationResult{PlatformOperationResult::Status::Failed,"write ahead refused"};});
        check(!rejected.succeeded() && dns.snapshot().isEmpty() && read()==before,"Failed write-ahead changed DNS preferences");
        check(dns.apply(owner,sources,checkpoint).succeeded() && MacOriginalDns::valid(owner,record),"Apply durable private DNS source");
        const auto current=read();check(current["ServerAddresses"]==QJsonArray{local} && current["ServerPort"]==54321
            && current["SupplementalMatchDomains"]==before["SupplementalMatchDomains"],"DNS endpoint or original namespace was changed incorrectly");
        auto foreign=record;foreign["owner"]=QUuid::createUuid().toString(QUuid::WithoutBraces);
        check(!MacOriginalDns::valid(owner,foreign),"Foreign recovery owner was accepted");
    }
    // Destruction leaves the durable redirect in place; independent recovery runs after capture release.
    check(read()["ServerAddresses"].toArray()==QJsonArray{local} && !record.isEmpty(),"Redirect disappeared with its helper instance");
    {
        SCPreferencesSynchronize(preferences);const auto external=CFDictionaryCreateMutableCopy(nullptr,0,SCNetworkProtocolGetConfiguration(initial));
        const void *search[]{CFSTR("external.test")};const auto domains=CFArrayCreate(nullptr,search,1,&kCFTypeArrayCallBacks);
        CFDictionarySetValue(external,kSCPropNetDNSSearchDomains,domains);CFRelease(domains);
        check(SCNetworkProtocolSetConfiguration(initial,external) && SCPreferencesCommitChanges(preferences),"Change an unrelated DNS field externally");CFRelease(external);
        MacOriginalDns recovered(preferences,inspect);check(recovered.restore(owner,record,checkpoint).succeeded() && record.isEmpty(),"Recover from durable source ownership");
        const auto after=read();check(after["ServerAddresses"]==before["ServerAddresses"] && after["ServerPort"]==before["ServerPort"]
            && after["SearchDomains"]==QJsonArray{"external.test"},"Restoration overwrote external DNS fields or lost original endpoints");
    }
    seed();rejectActive=true;
    {
        MacOriginalDns dns(preferences,inspect);check(!dns.apply(owner,sources,checkpoint).succeeded() && record["phase"]=="applying",
            "Post-commit checkpoint failure discarded recovery intent");
    }
    rejectActive=false;
    {
        MacOriginalDns recovered(preferences,inspect);check(recovered.restore(owner,record,checkpoint).succeeded() && read()==before,
            "Unconfirmed committed DNS preferences were not restored exactly");
    }
    {
        MacOriginalDns dns(preferences,inspect);check(dns.apply(owner,sources,checkpoint).succeeded(),"Reapply private source");
        SCPreferencesSynchronize(preferences);const auto external=CFDictionaryCreateMutableCopy(nullptr,0,original);
        const void *server[]{CFSTR("192.0.2.99")};const auto servers=CFArrayCreate(nullptr,server,1,&kCFTypeArrayCallBacks);
        CFDictionarySetValue(external,kSCPropNetDNSServerAddresses,servers);CFRelease(servers);
        check(SCNetworkProtocolSetConfiguration(initial,external) && SCPreferencesCommitChanges(preferences),"Replace DNS endpoint externally");CFRelease(external);
        const auto changed=read();check(dns.restore(owner,record,checkpoint).succeeded() && read()==changed,"Restoration overwrote an externally replaced DNS endpoint");
    }
    seed();
    {
        MacOriginalDns dns(preferences,inspect);check(dns.apply(owner,sources,checkpoint).succeeded(),"Apply source before external disable");
        check(SCNetworkProtocolSetEnabled(initial,false) && SCPreferencesCommitChanges(preferences),"Disable the protocol externally");
        check(dns.restore(owner,record,checkpoint).succeeded() && !SCNetworkProtocolGetEnabled(initial)
            && read()["ServerAddresses"]==before["ServerAddresses"] && read()["ServerPort"]==before["ServerPort"],
            "Recovery re-enabled an external disable or left its own temporary endpoint behind");
    }
    std::cout<<"PASS: private native DNS write-ahead, helper loss, exact endpoint recovery, external values and checkpoint failure\n";return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
