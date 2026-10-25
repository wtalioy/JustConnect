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
