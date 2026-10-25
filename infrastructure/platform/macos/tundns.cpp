#include "tundns.h"
#include "infrastructure/platform/dnsdomains.h"
#include "infrastructure/platform/ipv4.h"
#include <QJsonArray>
#include <QScopeGuard>
#include <utility>
#include <unistd.h>

namespace {
PlatformOperationResult failed(const char *message)
{
    return {PlatformOperationResult::Status::Failed,QString::fromLatin1(message)+" "+QString::fromUtf8(SCErrorString(SCError()))};
}
CFArrayRef strings(const QStringList &values)
{
    const auto array = CFArrayCreateMutable(nullptr,0,&kCFTypeArrayCallBacks);
    for (const auto &value : values) {
        const auto text = value.toCFString(); CFArrayAppendValue(array,text); CFRelease(text);
    }
    return array;
}
}

QJsonObject MacTunDns::properties(const QString &peer,const QStringList &domains)
{
    return {{QString::fromCFString(kSCPropNetDNSServerAddresses),QJsonArray{peer}},
        {QString::fromCFString(kSCPropNetDNSSupplementalMatchDomains),QJsonArray::fromStringList(domains)},
        {QString::fromCFString(macDnsNoSearchKey()),MacDnsNoSearch}};
}

void MacTunDns::restore()
{
    // AddTemporaryValue transfers ownership on another session's update, even for equal values.
    if (store) CFRelease(store);
    store = nullptr; applied = {};
}

PlatformOperationResult MacTunDns::apply(const UnixTunDevice &device, const QStringList &domains)
{
    using Status = PlatformOperationResult::Status;
    if (::geteuid() != 0) return {Status::PermissionDenied,"TUN DNS requires its privileged owner."};
    const auto info = device.snapshot();
    const auto addresses = info["configuration"].toObject()["applied"].toObject()["ipv4"].toArray();
    const auto pair = addresses.size() == 1 ? addresses.first().toObject() : QJsonObject{};
    const auto name = info["interface"].toString(), source = pair["source"].toString(), peer = pair["peer"].toString();
    if (store || device.descriptor() < 0 || device.owner().isNull() || !validTunDnsDomains(domains)
        || !assignedUnixTunPair(name,quint32(info["index"].toInteger()),source,peer))
        return {Status::Failed,"Owned configured TUN and canonical supplemental DNS domains are required."};
    const auto owner = device.owner().toString(QUuid::WithoutBraces).toCFString();
    const auto ipv4Key = SCDynamicStoreKeyCreateNetworkServiceEntity(nullptr,kSCDynamicStoreDomainState,owner,kSCEntNetIPv4);
    const auto dnsKey = SCDynamicStoreKeyCreateNetworkServiceEntity(nullptr,kSCDynamicStoreDomainState,owner,kSCEntNetDNS);
    const auto interface = name.toCFString();
    const auto local = strings({source}), mask = strings({pair["netmask"].toString()});
    const auto servers = strings({peer}), matches = strings(domains);
    const void *ipv4Keys[]{kSCPropInterfaceName,kSCPropNetIPv4Addresses,kSCPropNetIPv4SubnetMasks};
    const void *ipv4Values[]{interface,local,mask};
    const auto ipv4 = CFDictionaryCreate(nullptr,ipv4Keys,ipv4Values,3,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    const auto noSearch = CFNumberCreate(nullptr,kCFNumberIntType,&MacDnsNoSearch);
    const void *dnsKeys[]{kSCPropNetDNSServerAddresses,kSCPropNetDNSSupplementalMatchDomains,macDnsNoSearchKey()};
    const void *dnsValues[]{servers,matches,noSearch};
    const auto dns = CFDictionaryCreate(nullptr,dnsKeys,dnsValues,3,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    const auto release = qScopeGuard([&] {
        for (const auto value : {CFTypeRef(owner),CFTypeRef(ipv4Key),CFTypeRef(dnsKey),CFTypeRef(interface),CFTypeRef(local),
                 CFTypeRef(mask),CFTypeRef(servers),CFTypeRef(matches),CFTypeRef(noSearch),CFTypeRef(ipv4),CFTypeRef(dns)}) CFRelease(value);
    });
    store = SCDynamicStoreCreate(nullptr,CFSTR("JustConnect owned TUN DNS"),nullptr,nullptr);
    if (!store) return failed("Cannot open the owned DNS session.");
    for (const auto key : {ipv4Key,dnsKey}) {
        const auto existing = SCDynamicStoreCopyValue(store,key);
        if (existing) { CFRelease(existing); restore(); return {Status::Failed,"Existing service DNS ownership is preserved."}; }
        if (SCError() != kSCStatusNoKey) { const auto result = failed("Cannot confirm an unused DNS service namespace."); restore(); return result; }
    }
    if (!add(store,ipv4Key,ipv4) || !add(store,dnsKey,dns)) {
        const auto result = failed("Cannot publish the owned supplemental DNS service."); restore(); return result;
    }
    const std::pair<CFStringRef,CFDictionaryRef> entries[]{{ipv4Key,ipv4},{dnsKey,dns}};
    for (const auto &entry : entries) {
        const auto current = SCDynamicStoreCopyValue(store,entry.first);
        const bool same = current && CFEqual(current,entry.second);
        if (current) CFRelease(current);
        if (!same) { restore(); return {Status::Failed,"Supplemental DNS readback changed; external values are preserved."}; }
    }
    if (!assignedUnixTunPair(name,quint32(info["index"].toInteger()),source,peer)) {
        restore(); return {Status::Failed,"Owned DNS interface changed during publication."};
    }
    applied = {{QString::fromCFString(ipv4Key),QJsonObject{{QString::fromCFString(kSCPropInterfaceName),name},
            {QString::fromCFString(kSCPropNetIPv4Addresses),QJsonArray{source}},{QString::fromCFString(kSCPropNetIPv4SubnetMasks),QJsonArray{pair["netmask"]}}}},
        {QString::fromCFString(dnsKey),properties(peer,domains)}};
    return {Status::Success,{},true};
}
