#include "infrastructure/dns/macos/resolver.h"
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *stage) { if (!value) throw std::runtime_error(stage); }
static QString resolver(const QString &domain,const QString &peer="198.18.0.2",int index=0,const QString &flags="Supplemental, Request A records")
{
    return QStringLiteral("resolver #1\n  domain : %1\n  nameserver[0] : %2\n  flags : %3\n").arg(domain,peer,flags)
        + (index ? QStringLiteral("  if_index : %1 (utun4)\n").arg(index) : QString{});
}
int main() try
{
    const QStringList domains{"campus.test","services.test"};
    const auto first=resolver(domains.first()),second=resolver(domains.last());
    const auto matches=[&](const QString &text){return macDnsResolverMatches(text,"198.18.0.2",domains);};
    check(matches("DNS configuration\n"+first+second),"complete owned resolvers were not recognized");
    check(!matches(first),"partial namespace publication was ready");
    check(!matches((first+second).replace("resolver #1\n","")),"headerless fields were accepted as active resolvers");
    check(!matches(first+resolver(domains.last(),"192.0.2.53")),"foreign DNS server was ready");
    check(!matches(first+resolver(domains.last(),"198.18.0.2",13)),"old interface resolver was ready");
    check(!matches(first+resolver(domains.last(),"198.18.0.2",13,"Scoped, Request A records")),"ordinary scoped resolver stood in for supplemental routing");
    check(!matches(first+resolver(domains.last(),"198.18.0.2",0,"Supplemental, Scoped")),"scoped flags without an interface were accepted");
    check(!matches(first+second+resolver(domains.first(),"192.0.2.53",13)),"conflicting resolver was hidden by an owned one");
    check(!matches(first+second+"  nameserver[1] : 192.0.2.53\n"),"extra DNS server was accepted");
    check(!matches(first+"DNS configuration (for scoped queries)\n  domain : services.test\n  flags : Supplemental\n"),"fields from different resolver sections were combined");
    check(matches(first+second+"DNS configuration (for scoped queries)\n"+resolver(domains.first(),"192.0.2.53",13,"Supplemental, Scoped")),"interface-scoped queries polluted ordinary resolver readiness");
    check(matches(first+"  port : 53\n"+second),"explicit standard DNS port did not match its implicit native default");
    check(!matches(first+"  port : 5353\n"+second),"a different effective DNS endpoint was accepted for the owned peer");
    check(!matches(first+"  options : mdns\n"+second),"multicast resolver options were accepted as owned plain DNS");
    const auto native = QStringLiteral("DNS configuration\nresolver #1\n  search domain[0] : saved.test\n"
        "  nameserver[0] : 192.0.2.53\n  nameserver[1] : 2001:db8::53\n  order : 200000\n  reach : 0x2 (Reachable)\n"
        "resolver #2\n  domain : static.test\n  nameserver[0] : 192.0.2.54\n  port : 5300\n  flags : Supplemental, Request A records\n"
        "DNS configuration (for scoped queries)\nresolver #1\n  domain : bound.test\n  nameserver[0] : 198.18.0.2\n"
        "  if_index : 13 (utun4)\n  flags : Scoped, Request A records\n"
        "DNS configuration (for service-specific queries)\nresolver #1\n  domain : service.test\n  service_identifier : 9\n");
    const auto parsed = parseMacDnsResolvers(native);
    check(parsed && parsed->size()==4,"native resolver sections were lost or combined");
    const auto primary=parsed->at(0).toObject(),supplemental=parsed->at(1).toObject(),scoped=parsed->at(2).toObject();
    check(primary["servers"].toArray()==QJsonArray{"192.0.2.53","2001:db8::53"}
        && primary["search"].toArray()==QJsonArray{"saved.test"} && primary["order"]==200000
        && supplemental["port"]==5300 && supplemental["scope"]=="unscoped"
        && scoped["interface_index"]==13 && scoped["interface_name"]=="utun4"
        && parsed->at(3).toObject()["scope"]=="service"
        && parsed->at(3).toObject()["properties"].toObject()["service_identifier"]=="9",
        "native server precedence, address families, port or query binding was guessed or dropped");
    check(parseMacDnsResolvers(QString(native).replace("0x2 (Reachable)","0x0 (Not Reachable)"))==parsed,
        "live reachability was mistaken for a DNS configuration change");
    check(macDnsResolverUsesPeer(scoped,"198.18.0.2",13) && !macDnsResolverUsesPeer(scoped,"198.18.0.2",14)
        && !macDnsResolverUsesPeer(scoped,"198.18.0.2"),"private scoped DNS could be removed as a foreign interface or ordinary resolver");
    for (const auto &bad : {QString{},QString(first+"  domain : duplicate.test\n"),
        QString(first).replace("nameserver[0]","nameserver[1]"),QString(first+"  if_index : invalid\n"),
        QString(first+"  port : 0\n"),QString(first+"  port : 65536\n"),QString(first+"DNS configuration (unknown scope)\n"),
        QString(first)+QString(MacDnsSnapshotBytes,' ')})
        check(!parseMacDnsResolvers(bad),"malformed or oversized native facts published a partial resolver view");
    check(parseMacDnsResolvers("No DNS configuration available")==std::optional<QJsonArray>(QJsonArray{}),
        "an explicit native no-DNS result became a read failure");
    int calls=0;
    auto result=waitForMacDnsResolver("198.18.0.2",domains,[&](const QString &,const QStringList &){
        ++calls;return PlatformCommandResult{{},calls==1?first:first+second,{}};
    });
    check(result.succeeded() && calls==2,"publication returned before all namespaces became effective");
    calls=0;
    result=waitForMacDnsResolver("198.18.0.2",domains,[&](const QString &,const QStringList &){
        ++calls;return PlatformCommandResult{{PlatformOperationResult::Status::PermissionDenied,"read denied"},{},{}};
    });
    check(result.status==PlatformOperationResult::Status::PermissionDenied && calls==1,"resolver inspection failure was hidden");
    std::cout<<"PASS: complete owned DNS scope, stale/foreign/conflicting rejection, publication wait and read failure\n";
    return 0;
} catch (const std::exception &error) {std::cerr<<error.what()<<'\n';return 1;}
