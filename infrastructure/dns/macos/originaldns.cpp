#include "infrastructure/dns/macos/originaldns.h"
#include "infrastructure/dns/macos/propertylist.h"
#include "infrastructure/dns/macos/resolver.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/dns/domainlimits.h"
#include "infrastructure/networkaddress/ipv4.h"
#include <QJsonDocument>
#include <QDeadlineTimer>
#include <QScopeGuard>
#include <QSet>
#include <QThread>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
constexpr int RecordVersion=2;
Result failed(const char *message,bool changed=false) { return {Status::Failed,QString::fromLatin1(message),changed}; }
bool uuid(const QJsonValue &value) { const QUuid id(value.toString()); return !id.isNull() && id.toString(QUuid::WithoutBraces).compare(value.toString(),Qt::CaseInsensitive)==0; }
bool equal(CFTypeRef a,CFTypeRef b) { return a==b || (a && b && CFEqual(a,b)); }
QByteArray encoded(CFPropertyListRef value)
{
    const auto data=CFPropertyListCreateData(nullptr,value,kCFPropertyListBinaryFormat_v1_0,0,nullptr);
    if(!data)return {};
    const auto release=qScopeGuard([&]{CFRelease(data);});
    if(CFDataGetLength(data)>MacDnsSnapshotBytes)return {};
    return QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(data)),CFDataGetLength(data)).toBase64();
}
CFDictionaryRef decoded(const QJsonValue &value)
{
    if(!value.isString() || value.toString().toLatin1().size()>2*MacDnsSnapshotBytes)return nullptr;
    const auto bytes=value.toString().toLatin1();
    const auto decoded=QByteArray::fromBase64Encoding(bytes,QByteArray::AbortOnBase64DecodingErrors);
    if(!decoded || decoded.decoded.isEmpty() || decoded.decoded.size()>MacDnsSnapshotBytes || decoded.decoded.toBase64()!=bytes)return nullptr;
    const auto data=CFDataCreate(nullptr,reinterpret_cast<const UInt8 *>(decoded.decoded.constData()),decoded.decoded.size());
    if(!data)return nullptr;
    const auto result=CFPropertyListCreateWithData(nullptr,data,kCFPropertyListImmutable,nullptr,nullptr);CFRelease(data);
    if(!result)return nullptr;
    if(CFGetTypeID(result)!=CFDictionaryGetTypeID()){CFRelease(result);return nullptr;}
    return static_cast<CFDictionaryRef>(result);
}
SCNetworkProtocolRef protocol(SCPreferencesRef preferences,const QJsonValue &id,bool requireEnabled=true)
{
    if(!uuid(id))return nullptr;
    const auto name=id.toString().toCFString();
    const auto service=SCNetworkServiceCopy(preferences,name);CFRelease(name);
    if(!service)return nullptr;
    const auto result=(!requireEnabled || SCNetworkServiceGetEnabled(service))?SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeDNS):nullptr;
    CFRelease(service);
    if(result && requireEnabled && !SCNetworkProtocolGetEnabled(result)){CFRelease(result);return nullptr;}
    return result;
}
bool sameEndpoint(CFDictionaryRef a,CFDictionaryRef b)
{
    if(!a || !b)return a==b;
    for(const auto key:{kSCPropNetDNSServerAddresses,kSCPropNetDNSServerPort})
        if(!equal(CFDictionaryGetValue(a,key),CFDictionaryGetValue(b,key)))return false;
    return true;
}
bool localEndpoint(const QString &text,QString &address,int &port,const QJsonObject &context)
{
    const auto separator=text.lastIndexOf(':');
    address=text.first(separator);const auto number=text.mid(separator+1);bool valid=false;
    port=number.toInt(&valid);
    if(separator<=0 || !canonicalUnicastIpv4(address) || !valid || port<1 || port>65535 || QString::number(port)!=number)return false;
    ifaddrs *interfaces=nullptr;if(::getifaddrs(&interfaces)!=0)return false;
    const auto release=qScopeGuard([&]{::freeifaddrs(interfaces);});
    in_addr expected{};if(::inet_pton(AF_INET,address.toLatin1().constData(),&expected)!=1)return false;
    const auto name=context["interface"].toString().toLatin1();const auto index=context["interface_index"].toInteger();
    if(index>0 && ::if_nametoindex(name.constData())!=quint32(index))return false;
    for(auto *row=interfaces;row;row=row->ifa_next)
        if(row->ifa_addr && row->ifa_addr->sa_family==AF_INET && (row->ifa_flags&IFF_UP) && name==row->ifa_name
            && reinterpret_cast<sockaddr_in *>(row->ifa_addr)->sin_addr.s_addr==expected.s_addr)return true;
    return false;
}
std::optional<QJsonValue> dnsState(const QString &service)
{
    const auto store=SCDynamicStoreCreate(nullptr,CFSTR("JustConnect original DNS source validation"),nullptr,nullptr);
    if(!store)return {};
    const auto release=qScopeGuard([&]{CFRelease(store);});const auto id=service.toCFString();
    const auto key=SCDynamicStoreKeyCreateNetworkServiceEntity(nullptr,kSCDynamicStoreDomainState,id,kSCEntNetDNS);CFRelease(id);
    const auto value=SCDynamicStoreCopyValue(store,key);CFRelease(key);
    if(!value)return SCError()==kSCStatusNoKey?std::optional<QJsonValue>{QJsonValue(QJsonValue::Null)}:std::nullopt;
    const auto freeValue=qScopeGuard([&]{CFRelease(value);});const auto result=macDnsProperties(value);
    return result && result->isObject()?result:std::nullopt;
}
bool sameDnsState(const QJsonObject &entry,const MacOriginalDns::StateReader &read)
{
    const auto state=read(entry["service"].toString());return state && *state==entry["context"].toObject()["state"];
}
bool originalContext(const QJsonObject &entry)
{
    const auto context=entry["context"].toObject();const auto before=MacOriginalDns::properties(entry,true);
    if(!validMacOriginalDnsContext(context) || !before)return false;
    const auto state=context["state"].toObject();
    const auto source=(*before)["ServerAddresses"].toArray().isEmpty()?state:*before;
    const auto port=before->contains("ServerPort")?(*before)["ServerPort"]:state["ServerPort"];
    return macDnsServersBelongTo(context["servers"].toArray(),source["ServerAddresses"].toArray()) && (*before)["Options"].toString().isEmpty() && state["Options"].toString().isEmpty()
        && (port.isUndefined()?context["port"]==DnsServerPort:(port.isDouble() && port==context["port"]));
}
Result waitForOriginalDns(const QJsonArray &entries,bool activating,const PlatformCommandRunner &inspect)
{
    QDeadlineTimer deadline(5000);
    while(!deadline.hasExpired()){
        const auto current=inspect?inspect("/usr/sbin/scutil",{"--dns"}):runPlatformCommand("/usr/sbin/scutil",{"--dns"},int(deadline.remainingTime()));
        if(!current.result.succeeded())return current.result;
        const auto resolvers=parseMacDnsResolvers(current.output);
        if(!resolvers)return failed("Invalid effective DNS configuration while confirming original DNS.",true);
        bool ready=true;
        for(const auto &value:entries){
            const auto row=value.toObject();const auto applied=MacOriginalDns::properties(row,false);
            if(!applied)return failed("Invalid saved original DNS configuration.",true);
            const auto domains=row["context"].toObject()["domains"].toArray();
            QSet<QString> remaining;for(const auto &domain:domains)remaining.insert(domain.toString());
            for(const auto &value:*resolvers){
                const auto resolver=value.toObject();
                const auto servers=resolver["servers"].toArray(),owned=(*applied)["ServerAddresses"].toArray();
                const bool endpoint=activating?servers==owned:servers.contains(owned.first());
                if(!endpoint || resolver["port"].toInteger(DnsServerPort)!=(*applied)["ServerPort"].toInteger())continue;
                if(!activating){ready=false;break;}
                if(resolver["scope"]=="unscoped" && resolver["interface_index"].toInteger()==0 && resolver["options"].toString().isEmpty())
                    remaining.remove(resolver["domain"].toString());
            }
            if(activating && !remaining.isEmpty())ready=false;
        }
        if(ready)return {};
        QThread::msleep(50);
    }
    return {Status::TimedOut,activating?"Original DNS listeners did not become effective.":"Owned original DNS endpoints remain effective after restoration.",true};
}
}

DnsSnapshot readMacDnsPreferences(const QString &service)
{
    const auto preferences=SCPreferencesCreate(nullptr,CFSTR("JustConnect original DNS source"),nullptr);
    if(!preferences)return {failed("Cannot read native DNS preferences."),{}};
    const auto release=qScopeGuard([&]{CFRelease(preferences);});
    const auto source=protocol(preferences,service);
    if(!source)return {{Status::Unsupported,"The original DNS source is not an enabled preferences service."},{}};
    const auto releaseSource=qScopeGuard([&]{CFRelease(source);});
    const auto value=SCNetworkProtocolGetConfiguration(source);
    const auto properties=value?macDnsProperties(value):std::optional<QJsonValue>{QJsonObject{}};
    const auto original=value?encoded(value):QByteArray{};
    if(!properties || !properties->isObject() || (value && original.isEmpty()))return {{Status::Unsupported,"The original DNS preferences are unavailable."},{}};
    const auto name=service.toCFString();const auto native=SCNetworkServiceCopy(preferences,name);CFRelease(name);
    if(!native)return {failed("The original DNS service changed."),{}};
    const auto interface=SCNetworkServiceGetInterface(native);
    const auto bsd=interface?SCNetworkInterfaceGetBSDName(interface):nullptr;
    const auto interfaceName=bsd?QString::fromCFString(bsd):QString{};CFRelease(native);
    return {{},{{"original",value?QJsonValue(QString::fromLatin1(original)):QJsonValue(QJsonValue::Null)},{"properties",*properties},{"interface",interfaceName}}};
}

MacOriginalDns::MacOriginalDns(SCPreferencesRef value,PlatformCommandRunner inspect,StateReader read)
    :preferences(value?static_cast<SCPreferencesRef>(CFRetain(value)):SCPreferencesCreate(nullptr,CFSTR("JustConnect owned original DNS"),nullptr)),inspect(std::move(inspect)),readState(std::move(read)) { if(!readState)readState=dnsState; }
MacOriginalDns::~MacOriginalDns() { if(preferences)CFRelease(preferences); }
std::optional<QJsonObject> MacOriginalDns::properties(const QJsonObject &entry,bool original)
{
    if(original && entry["original"].isNull())return QJsonObject{};
    const auto value=decoded(entry[original?"original":"applied"]);
    if(!value)return {};
    const auto release=qScopeGuard([&]{CFRelease(value);});
    const auto converted=macDnsProperties(value);
    if(!converted || !converted->isObject())return {};
    return converted->toObject();
}
bool MacOriginalDns::valid(const QUuid &owner,const QJsonObject &record)
{
    if(owner.isNull() || record.size()!=4 || record["version"]!=RecordVersion || record["owner"]!=owner.toString(QUuid::WithoutBraces)
        || !record["entries"].isArray() || record["entries"].toArray().isEmpty()
        || record["entries"].toArray().size()>qsizetype(NetworkDnsDomainLimit)
        || QJsonDocument(record).toJson(QJsonDocument::Compact).size()>MacDnsSnapshotBytes)return false;
    const auto phase=record["phase"].toString();
    if(phase!="applying" && phase!="active" && phase!="restoring")return false;
    QSet<QString> seen;
    for(const auto &value:record["entries"].toArray()){
        const auto row=value.toObject();const auto id=row["service"].toString();
        if(row.size()!=4 || !uuid(row["service"]) || seen.contains(id.toLower()) || !originalContext(row) || !properties(row,false))return false;
        const auto original=decoded(row["original"]),applied=decoded(row["applied"]);
        const auto release=qScopeGuard([&]{if(original)CFRelease(original);CFRelease(applied);});
        const auto values=properties(row,false).value();const auto servers=values["ServerAddresses"].toArray();
        const auto port=values["ServerPort"].toInteger(-1);
        if(servers.size()!=1 || !canonicalUnicastIpv4(servers.first().toString()) || port<1 || port>65535
            || values["ServerPort"]!=QJsonValue(port))return false;
        const auto restored=CFDictionaryCreateMutableCopy(nullptr,0,applied);
        const auto freeRestored=qScopeGuard([&]{CFRelease(restored);});
        for(const auto key:{kSCPropNetDNSServerAddresses,kSCPropNetDNSServerPort}){
            const auto before=original?CFDictionaryGetValue(original,key):nullptr;
            if(before)CFDictionarySetValue(restored,key,before);else CFDictionaryRemoveValue(restored,key);
        }
        if(original?!equal(restored,original):CFDictionaryGetCount(restored)!=0)return false;
        seen.insert(id.toLower());
    }
    return true;
}
Result MacOriginalDns::apply(const QUuid &owner,const QJsonArray &sources,const Checkpoint &checkpoint)
{
    if(!preferences || owner.isNull() || sources.isEmpty() || sources.size()>qsizetype(NetworkDnsDomainLimit) || !installed.isEmpty() || !checkpoint)
        return failed("Invalid original DNS ownership.");
    SCPreferencesSynchronize(preferences);
    if(!SCPreferencesLock(preferences,false))return failed("Cannot lock original DNS preferences.");
    const auto unlock=qScopeGuard([&]{SCPreferencesUnlock(preferences);});
    QJsonArray entries;QSet<QString> seen;
    for(const auto &value:sources){
        const auto row=value.toObject();QString address;int port=0;const auto id=row["service"].toString();
        if(row.size()!=4 || !uuid(row["service"]) || seen.contains(id.toLower()) || !originalContext(row) || !sameDnsState(row,readState)
            || !localEndpoint(row["listen"].toString(),address,port,row["context"].toObject()))
            return failed("Invalid original DNS endpoint or source.");
        seen.insert(id.toLower());
        const auto original=decoded(row["original"]);
        const auto release=qScopeGuard([&]{if(original)CFRelease(original);});
        const auto current=protocol(preferences,row["service"]);if(!current)return failed("The original DNS service is unavailable.");
        const auto releaseProtocol=qScopeGuard([&]{CFRelease(current);});
        if(!equal(SCNetworkProtocolGetConfiguration(current),original))return failed("The original DNS source changed before application.");
        const auto applied=original?CFDictionaryCreateMutableCopy(nullptr,0,original):CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        const auto freeApplied=qScopeGuard([&]{CFRelease(applied);});
        const auto server=address.toCFString();const void *pointer=server;
        const auto servers=CFArrayCreate(nullptr,&pointer,1,&kCFTypeArrayCallBacks);CFRelease(server);
        const auto number=CFNumberCreate(nullptr,kCFNumberIntType,&port);
        CFDictionarySetValue(applied,kSCPropNetDNSServerAddresses,servers);CFDictionarySetValue(applied,kSCPropNetDNSServerPort,number);
        CFRelease(servers);CFRelease(number);
        const auto bytes=encoded(applied);if(bytes.isEmpty())return failed("Original DNS ownership exceeds its bound.");
        entries.append(QJsonObject{{"service",row["service"]},{"original",row["original"]},{"applied",QString::fromLatin1(bytes)},{"context",row["context"]}});
    }
    const QJsonObject record{{"version",RecordVersion},{"owner",owner.toString(QUuid::WithoutBraces)},{"phase","applying"},{"entries",entries}};
    if(!valid(owner,record))return failed("Invalid original DNS write-ahead record.");
    auto result=checkpoint(record);if(!result.succeeded())return result;installed=record;
    SCPreferencesSynchronize(preferences);
    for(const auto &value:entries){
        const auto row=value.toObject();const auto current=protocol(preferences,row["service"]);
        if(!current)return failed("The original DNS service changed while recording ownership.",true);
        const auto release=qScopeGuard([&]{CFRelease(current);});
        const auto original=decoded(row["original"]),applied=decoded(row["applied"]);
        const auto freeValues=qScopeGuard([&]{if(original)CFRelease(original);CFRelease(applied);});
        if(!sameDnsState(row,readState) || !equal(SCNetworkProtocolGetConfiguration(current),original) || !SCNetworkProtocolSetConfiguration(current,applied))
            return failed("Cannot stage unchanged original DNS preferences.",true);
    }
    if(!SCPreferencesCommitChanges(preferences))return failed("Cannot commit original DNS preferences.",true);
    SCPreferencesSynchronize(preferences);
    for(const auto &value:entries){
        const auto row=value.toObject();const auto current=protocol(preferences,row["service"]);const auto expected=decoded(row["applied"]);
        const bool verified=current && sameDnsState(row,readState) && equal(SCNetworkProtocolGetConfiguration(current),expected);
        if(current)CFRelease(current);CFRelease(expected);
        if(!verified)return failed("Original DNS preferences readback changed.",true);
    }
    auto active=installed;active["phase"]="active";result=checkpoint(active);
    if(!result.succeeded())return result;installed=active;
    if(!SCPreferencesApplyChanges(preferences))return failed("Cannot activate original DNS preferences.",true);
    result=waitForOriginalDns(entries,true,inspect);if(!result.succeeded())return result;
    return {Status::Success,{},true};
}
Result MacOriginalDns::restore(const QUuid &owner,const QJsonObject &record,const Checkpoint &checkpoint)
{
    if(!preferences || !valid(owner,record) || !checkpoint)return failed("Invalid original DNS recovery ownership.",true);
    SCPreferencesSynchronize(preferences);
    if(!SCPreferencesLock(preferences,false))return failed("Cannot lock original DNS restoration.",true);
    const auto unlock=qScopeGuard([&]{SCPreferencesUnlock(preferences);});
    auto restoring=record;restoring["phase"]="restoring";
    auto result=checkpoint(restoring);if(!result.succeeded())return result;installed=restoring;
    SCPreferencesSynchronize(preferences);bool changed=false;QJsonArray expected;
    for(const auto &value:record["entries"].toArray()){
        const auto row=value.toObject();const auto current=protocol(preferences,row["service"],false);
        if(!current)continue; // Removed services/protocols are not recreated.
        const auto release=qScopeGuard([&]{CFRelease(current);});
        const auto actual=SCNetworkProtocolGetConfiguration(current),original=decoded(row["original"]),applied=decoded(row["applied"]);
        const auto freeValues=qScopeGuard([&]{if(original)CFRelease(original);CFRelease(applied);});
        if(!sameEndpoint(actual,applied) || sameEndpoint(actual,original))continue;
        const auto restored=CFDictionaryCreateMutableCopy(nullptr,0,actual);
        const auto freeRestored=qScopeGuard([&]{CFRelease(restored);});
        for(const auto key:{kSCPropNetDNSServerAddresses,kSCPropNetDNSServerPort}){
            const auto before=original?CFDictionaryGetValue(original,key):nullptr;
            if(before)CFDictionarySetValue(restored,key,before);else CFDictionaryRemoveValue(restored,key);
        }
        const auto count=CFDictionaryGetCount(restored);
        const bool automatic=!original && (count==0 || (count==1 && CFDictionaryContainsKey(restored,kSCResvInactive)));
        const auto wanted=automatic?nullptr:restored;
        if(!SCNetworkProtocolSetConfiguration(current,wanted))return failed("Cannot stage owned original DNS restoration.",true);
        expected.append(QJsonObject{{"service",row["service"]},{"value",wanted?QJsonValue(QString::fromLatin1(encoded(wanted))):QJsonValue(QJsonValue::Null)}});
        changed=true;
    }
    if(changed && !SCPreferencesCommitChanges(preferences))return failed("Cannot commit original DNS restoration.",true);
    SCPreferencesSynchronize(preferences);
    for(const auto &value:expected){
        const auto row=value.toObject();const auto source=protocol(preferences,row["service"],false);const auto wanted=decoded(row["value"]);
        const bool verified=source && (wanted || row["value"].isNull()) && equal(SCNetworkProtocolGetConfiguration(source),wanted);
        if(source)CFRelease(source);if(wanted)CFRelease(wanted);
        if(!verified)return failed("Restored original DNS readback changed.",true);
    }
    if(!SCPreferencesApplyChanges(preferences))return failed("Cannot activate restored original DNS preferences.",true);
    result=waitForOriginalDns(record["entries"].toArray(),false,inspect);if(!result.succeeded())return result;
    result=checkpoint({});if(!result.succeeded())return result;installed={};
    return {};
}
