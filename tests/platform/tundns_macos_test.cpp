#include "infrastructure/dns/macos/tundns.h"
#include "infrastructure/dns/macos/resolver.h"
#include "infrastructure/routing/macos/tunroutes.h"
#include "infrastructure/dns/macos/dnssnapshot.h"
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QJsonDocument>
#include <QScopeGuard>
#include <QThread>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

static void check(bool ok,const char *message) { if (!ok) throw std::runtime_error(message); }
template<class Predicate> static void wait(Predicate predicate,const char *message)
{
    QDeadlineTimer deadline(5000);
    while (!predicate() && !deadline.hasExpired()) QThread::msleep(10);
    check(predicate(),message);
}
static QJsonObject dnsSnapshot()
{
    const auto value = readMacDnsSnapshot(); check(value.result.succeeded(),qPrintable(value.result.detail)); return value.data;
}
static QJsonArray defaults()
{
    const auto value = readMacRoutes(); check(value.result.succeeded(),"Read default route inventory");
    QJsonArray result;
    for (const auto &row : value.rows) if (row.toObject()["prefix"] == "0.0.0.0/0") result.append(row);
    return result;
}
static int writes = 0;
static bool hasValue(SCDynamicStoreRef store,const QString &name)
{
    const auto key = name.toCFString();
    const auto value = SCDynamicStoreCopyValue(store,key); CFRelease(key);
    if (value) CFRelease(value);
    return value != nullptr;
}
static Boolean failSecond(SCDynamicStoreRef store,CFStringRef key,CFPropertyListRef value)
{
    if (++writes == 2) return false;
    return SCDynamicStoreAddTemporaryValue(store,key,value);
}
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv);
    if (app.arguments().value(1) == "--snapshot") {
        std::cout << QJsonDocument(dnsSnapshot()).toJson(QJsonDocument::Compact).constData() << std::endl; return 0;
    }
    MacTunDns dns; UnixTunDevice device;
    if (argc == 1) {
        check(::geteuid() != 0 && dns.apply(device,{"campus.test"}).status == PlatformOperationResult::Status::PermissionDenied,
            "Ordinary caller acquired DNS publication authority"); return 0;
    }
    check(argc == 2 && app.arguments()[1] == "--isolated" && ::geteuid() == 0 && qgetenv("GITHUB_ACTIONS") == "true" && qgetenv("RUNNER_OS") == "macOS",
        "Native DNS mutation requires the disposable macOS runner");
    check(device.createIpv4(QUuid::createUuid(),"198.18.0.1","198.18.0.2",1400).succeeded(),"Create owned DNS device");
    const auto before = dnsSnapshot();
    const auto routeBefore = defaults();
    const QStringList domains{"campus.justconnect-fixture.test"};
    const auto published = dns.apply(device,domains);
    check(published.succeeded(),qPrintable(published.detail));
    const auto expected = dns.snapshot(); check(expected.size() == 2,"Missing owned service binding");
    const auto inspector = SCDynamicStoreCreate(nullptr,CFSTR("JustConnect DNS fixture inspection"),nullptr,nullptr);
    check(inspector,"Open independent DNS inspection session");
    const auto closeInspector = qScopeGuard([&] { CFRelease(inspector); });
    const auto absent = [&] {
        for (auto it = expected.begin(); it != expected.end(); ++it) if (hasValue(inspector,it.key())) return false;
        return true;
    };
    const auto ipv4 = device.snapshot()["configuration"].toObject()["applied"].toObject()["ipv4"].toArray().first().toObject();
    check(macDnsResolverMatches(runPlatformCommand("/usr/sbin/scutil",{"--dns"}).output,ipv4["peer"].toString(),domains),"Publication returned before the complete owned resolver became effective");
    const auto global = SCDynamicStoreKeyCreateNetworkGlobalEntity(nullptr,kSCDynamicStoreDomainState,kSCEntNetDNS);
    const auto globalKey = QString::fromCFString(global); CFRelease(global);
    const auto originalGlobal = before["dynamic_store"].toObject().value(globalKey).toObject();
    wait([&] {
        const auto current = dnsSnapshot()["dynamic_store"].toObject().value(globalKey).toObject();
        return current.value("SearchDomains") == originalGlobal.value("SearchDomains") && current.value("ServerAddresses") == originalGlobal.value("ServerAddresses");
    },"Supplemental DNS changed the global search domains or primary servers");
    check(defaults() == routeBefore,"Supplemental DNS changed the original default route");
    dns.restore();
    wait(absent,"Owned DNS service keys survived session close");
    wait([&] { return dnsSnapshot() == before; },"Session close did not restore the original DNS inventory");
    int inspections = 0;
    MacTunDns unreadable(SCDynamicStoreAddTemporaryValue,[&](const QString &,const QStringList &) {
        ++inspections;return PlatformCommandResult{{PlatformOperationResult::Status::Failed,"resolver inspection failed"},{},{}};
    });
    check(!unreadable.apply(device,domains).succeeded() && inspections == 1 && unreadable.snapshot().isEmpty(),
        "Resolver inspection failure retained temporary DNS ownership");
    wait(absent,"Resolver inspection failure retained owned service keys");
    wait([&] { return dnsSnapshot() == before; },"Resolver inspection failure changed original DNS settings");
    MacTunDns partial(failSecond);
    check(!partial.apply(device,domains).succeeded() && writes == 2 && partial.snapshot().isEmpty(),"Partial publication did not fail");
    wait(absent,"The first real publication survived failure of the second key");
    wait([&] { return dnsSnapshot() == before; },"Partial DNS publication survived its session");
    check(dns.apply(device,domains).succeeded(),"Republish before an external same-value update");
    const auto external = SCDynamicStoreCreate(nullptr,CFSTR("JustConnect external DNS fixture"),nullptr,nullptr);
    check(external,"Open external actor session");
    QString dnsKey;
    for (auto it = expected.begin(); it != expected.end(); ++it) if (it.key().endsWith("/DNS")) dnsKey = it.key();
    const auto key = dnsKey.toCFString();
    const auto same = SCDynamicStoreCopyValue(external,key);
    const auto releaseExternal = qScopeGuard([&] {
        const auto current = SCDynamicStoreCopyValue(external,key);
        if (current) {
            if (same && CFEqual(current,same)) SCDynamicStoreRemoveValue(external,key);
            CFRelease(current);
        }
        if (same) CFRelease(same);
        CFRelease(key); CFRelease(external);
    });
    check(same && SCDynamicStoreSetValue(external,key,same),"Make an actual external same-value replacement");
    dns.restore();
    wait([&] {
        for (auto it = expected.begin(); it != expected.end(); ++it)
            if (it.key() != dnsKey && hasValue(inspector,it.key())) return false;
        return true;
    },"External update prevented cleanup of the independently owned companion key");
    wait([&] { return dnsSnapshot()["dynamic_store"].toObject().size() == before["dynamic_store"].toObject().size()+1; },"External DNS value was removed or owned companion remained");
    const auto retained = SCDynamicStoreCopyValue(external,key);
    check(retained && CFEqual(retained,same) && !dns.apply(device,domains).succeeded(),"External same-value ownership was deleted or adopted");
    CFRelease(retained);
    check(SCDynamicStoreRemoveValue(external,key),"Remove only the external fixture's own value");
    wait([&] { return dnsSnapshot() == before; },"Original DNS inventory differs after owned fixture cleanup");
    check(defaults() == routeBefore,"DNS recovery changed the original default route");
    device.close();
    std::cout << "PASS: supplemental DNS session ownership, partial rollback, same-value external preservation and unchanged default route\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n';return 1; }
