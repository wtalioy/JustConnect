#include "infrastructure/platform/macos/dnssnapshot.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <QScopeGuard>
#include <iostream>
#include <cstdlib>

static void check(bool ok, const char *message) {
    if (!ok) { std::cerr << message << '\n'; std::exit(1); }
}
static CFDictionaryRef fixture = nullptr;
static CFDictionaryRef readFixture(SCDynamicStoreRef store, CFArrayRef keys, CFArrayRef patterns)
{
    check(store && !keys && patterns && CFArrayGetCount(patterns) == 1, "Native DNS query shape changed");
    check(CFEqual(CFArrayGetValueAtIndex(patterns, 0), CFSTR("^(State|Setup):/Network/.*/DNS$")), "DNS source scopes changed");
    return fixture ? static_cast<CFDictionaryRef>(CFRetain(fixture)) : nullptr;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (app.arguments().contains("--native")) {
        const auto snapshot = readMacDnsSnapshot();
        check(snapshot.result.succeeded(), qPrintable(snapshot.result.detail));
        check(!snapshot.data["dynamic_store"].toObject().isEmpty(), "Native resolver store unexpectedly empty");
        std::cout << "Native global and scoped resolver store inspected without writes\n";
        return 0;
    }
    const auto entries = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    const auto dns = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    const auto release = qScopeGuard([&] { CFRelease(dns); CFRelease(entries); });
    const void *servers[]{CFSTR("192.0.2.53"), CFSTR("2001:db8::53")};
    const auto addresses = CFArrayCreate(nullptr, servers, 2, &kCFTypeArrayCallBacks);
    CFDictionarySetValue(dns, kSCPropNetDNSServerAddresses, addresses); CFRelease(addresses);
    const void *domains[]{CFSTR("overlay.test")};
    const auto matches = CFArrayCreate(nullptr, domains, 1, &kCFTypeArrayCallBacks);
    CFDictionarySetValue(dns, kSCPropNetDNSSupplementalMatchDomains, matches); CFRelease(matches);
    int port = 5353;
    const auto number = CFNumberCreate(nullptr, kCFNumberIntType, &port);
    CFDictionarySetValue(dns, kSCPropNetDNSServerPort, number); CFRelease(number);
    CFDictionarySetValue(dns, CFSTR("SupplementalMatchDomainsNoSearch"), kCFBooleanTrue);
    CFDictionarySetValue(entries, CFSTR("State:/Network/Service/fixture/DNS"), dns);
    CFDictionarySetValue(entries, CFSTR("Setup:/Network/Global/DNS"), dns);
    fixture = entries;
    const auto snapshot = readMacDnsSnapshot(readFixture);
    check(snapshot.result.succeeded(), qPrintable(snapshot.result.detail));
    const auto result = snapshot.data["dynamic_store"].toObject()["State:/Network/Service/fixture/DNS"].toObject();
    check(result["ServerAddresses"].toArray() == QJsonArray{"192.0.2.53", "2001:db8::53"}
          && result["SupplementalMatchDomains"].toArray() == QJsonArray{"overlay.test"}
          && result["ServerPort"] == 5353 && result["SupplementalMatchDomainsNoSearch"] == true,
          "Native address family, split-DNS or resolver options lost");
    check(snapshot.data["dynamic_store"].toObject().contains("Setup:/Network/Global/DNS"), "Configured and active DNS sources collapsed");
    fixture = nullptr;
    const auto unavailable = readMacDnsSnapshot(readFixture);
    check(!unavailable.result.succeeded() && unavailable.data.isEmpty(), "Native read failure published facts");
    fixture = entries;
    double fractional = 1.5;
    const auto fraction = CFNumberCreate(nullptr, kCFNumberDoubleType, &fractional);
    CFDictionarySetValue(dns, kSCPropNetDNSServerPort, fraction); CFRelease(fraction);
    const auto lossy = readMacDnsSnapshot(readFixture);
    check(!lossy.result.succeeded() && lossy.data.isEmpty(), "Fractional native option silently rounded");
    const auto originalPort = CFNumberCreate(nullptr, kCFNumberIntType, &port);
    CFDictionarySetValue(dns, kSCPropNetDNSServerPort, originalPort); CFRelease(originalPort);
    const auto binary = CFDataCreate(nullptr, nullptr, 0);
    CFDictionarySetValue(dns, CFSTR("Unsupported"), binary); CFRelease(binary);
    const auto invalid = readMacDnsSnapshot(readFixture);
    check(!invalid.result.succeeded() && invalid.data.isEmpty(), "Unsupported property silently omitted");
    CFDictionaryRemoveValue(dns, CFSTR("Unsupported"));
    const QString large(262145, 'x');
    const auto text = large.toCFString();
    CFDictionarySetValue(dns, CFSTR("Options"), text); CFRelease(text);
    const auto oversized = readMacDnsSnapshot(readFixture);
    check(!oversized.result.succeeded() && oversized.data.isEmpty(), "Oversized snapshot truncated or published");
    std::cout << "Resolver sources, split DNS, native types and failure boundaries passed\n";
}
