#include "infrastructure/networkhelper/linux/networkownership.h"
#include "infrastructure/dns/linux/linkdns.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include "networkhelperfixture.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <iostream>
#include <stdexcept>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    const QUuid owner("11111111-1111-4111-8111-111111111111");
    auto configuration = helperFixtureConfiguration({"198.18.4.0/24"}, 1400);
    configuration.dnsDomains = {"campus.test"};
    const auto name = QString::fromLatin1(linuxTunName(owner));
    const QJsonObject device{{"owner", owner.toString(QUuid::WithoutBraces)}, {"interface", name}, {"index", 7}};
    const auto metric = qint64(linuxRouteMetric(owner)), table = qint64(linuxSourceTable(owner));
    const auto filter = linuxOriginalNetworkView(owner, configuration, device, 2);
    check(bool(filter) && !linuxOriginalNetworkView(QUuid::createUuid(), configuration, device, 2)
          && !linuxOriginalNetworkView(owner, configuration, device, 0), "foreign or missing ownership accepted");
    const QJsonObject originalInterface{{"index", 2}, {"name", "helperorig0"}, {"up", true}, {"loopback", false},
        {"addresses", QJsonArray{"192.0.2.1/24"}}};
    const QJsonObject ownedInterface{{"index", 7}, {"name", name}, {"up", true}, {"loopback", false},
        {"addresses", QJsonArray{configuration.address + "/32"}}};
    const QJsonObject originalRoute{{"destination", "192.168.20.0/24"}, {"interface_index", 2}};
    const QJsonObject capture{{"destination", "198.18.4.0/24"}, {"interface_index", 7}, {"source", configuration.address},
        {"scope", 253}, {"table", qint64(linuxCaptureTable(owner))}, {"metric", metric}, {"protocol", 4}, {"kind", 1}};
    const QJsonObject source{{"destination", "198.18.4.0/24"}, {"interface_index", 2}, {"source", configuration.originalSource},
        {"table", table}, {"metric", metric}, {"protocol", 4}, {"scope", 253}, {"kind", 1}};
    const QJsonObject peer{{"destination", configuration.peer + "/32"}, {"interface_index", 7}, {"source", configuration.address},
        {"table", 254}, {"protocol", 2}, {"scope", 253}, {"kind", 1}};
    const QJsonObject local{{"destination", configuration.address + "/32"}, {"interface_index", 7}, {"source", configuration.address},
        {"table", 255}, {"protocol", 2}, {"scope", 254}, {"kind", 2}};
    auto word = [](quint32 value) { return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(&value), sizeof(value)).toHex()); };
    QJsonObject rule{{"family", AF_INET}, {"priority", 1}, {"table", table}, {"action", FR_ACT_TO_TBL}, {"flags", 0}, {"tos", 0},
        {"source", configuration.originalSource + "/32"}, {"attributes", QJsonArray{
            QJsonObject{{"type", FRA_SRC}, {"value_hex", "c0000201"}}, QJsonObject{{"type", FRA_PRIORITY}, {"value_hex", word(1)}},
            QJsonObject{{"type", FRA_TABLE}, {"value_hex", word(quint32(table))}}, QJsonObject{{"type", FRA_PROTOCOL}, {"value_hex", "04"}},
            QJsonObject{{"type", FRA_SUPPRESS_PREFIXLEN}, {"value_hex", word(0xffffffffu)}}}}};
    QJsonObject network{{"interfaces", QJsonArray{originalInterface, ownedInterface}},
        {"routes", QJsonArray{originalRoute, capture, source, peer, local}}, {"policy_rules", QJsonArray{rule}}};
    auto captureRule = rule;
    captureRule.remove("source");captureRule["priority"] = LinuxCaptureRulePriority;captureRule["table"] = qint64(linuxCaptureTable(owner));
    captureRule["attributes"] = QJsonArray{QJsonObject{{"type", FRA_PRIORITY}, {"value_hex", word(LinuxCaptureRulePriority)}},
        QJsonObject{{"type", FRA_TABLE}, {"value_hex", word(linuxCaptureTable(owner))}}, QJsonObject{{"type", FRA_PROTOCOL}, {"value_hex", "04"}}};
    network["policy_rules"] = QJsonArray{rule,captureRule};
    const QJsonObject originalNetwork{{"interfaces", QJsonArray{originalInterface}}, {"routes", QJsonArray{originalRoute}}, {"policy_rules", QJsonArray{}}};
    const QJsonObject server{{"interface_index", 7}, {"family", AF_INET}, {"address", configuration.peer}, {"port", 53}, {"server_name", ""}};
    const QJsonObject domain{{"interface_index", 7}, {"domain", "campus.test"}, {"route_only", true}};
    const QJsonObject link{{"interface_index", 7}, {"name", name}, {"DefaultRoute", false}};
    auto foreignServer = server; foreignServer["interface_index"] = 2;
    auto foreignDomain = domain; foreignDomain["interface_index"] = 2; foreignDomain["domain"] = "original.test";
    const QJsonObject originalResolved{{"status", "available"}, {"DNS", QJsonArray{foreignServer}},
        {"Domains", QJsonArray{foreignDomain}}, {"Links", QJsonArray{}}};
    auto resolved = originalResolved;resolved["DNS"] = QJsonArray{server, foreignServer};resolved["Domains"] = QJsonArray{domain, foreignDomain};resolved["Links"] = QJsonArray{link};
    const QJsonObject dns{{"resolved", resolved}, {"resolv_conf", QJsonObject{{"contents", "nameserver 127.0.0.53\n"}}}};
    const auto view = filter(network, dns);
    check(view && view->first == originalNetwork && view->second["resolved"] == originalResolved
          && view->second["resolv_conf"] == dns["resolv_conf"], "owned records became original scopes or original data changed");
    for (const auto &key : {"gateway", "source", "metric", "table", "interface_index", "protocol", "scope", "kind", "flags", "unknown"}) {
        auto changed = capture;
        changed[key] = QString(key) == "gateway" || QString(key) == "source" ? QJsonValue("192.0.2.9") : QJsonValue(99);
        auto input = network;auto rows = input["routes"].toArray();rows[1] = changed;input["routes"] = rows;
        const auto preserved = filter(input, dns);
        check(preserved && preserved->first["routes"].toArray().contains(changed), "external route modification was filtered as owned");
    }
    auto duplicate = network;auto duplicated = duplicate["routes"].toArray();duplicated.append(capture);duplicate["routes"] = duplicated;
    check(filter(duplicate, dns)->first["routes"].toArray().contains(capture), "ambiguous duplicate was silently excluded");
    auto alteredRule = rule;auto attributes = rule["attributes"].toArray();attributes.append(QJsonObject{{"type", FRA_FWMARK}, {"value_hex", word(1)}});alteredRule["attributes"] = attributes;
    auto ruleNetwork = network;ruleNetwork["policy_rules"] = QJsonArray{alteredRule};
    check(filter(ruleNetwork, dns)->first["policy_rules"].toArray() == QJsonArray{alteredRule}, "unknown rule selector was discarded");
    auto extraInterface = ownedInterface;extraInterface["addresses"] = QJsonArray{configuration.address + "/32", "203.0.113.8/32"};
    auto extraNetwork = network;extraNetwork["interfaces"] = QJsonArray{originalInterface, extraInterface};
    check(filter(extraNetwork, dns)->first["interfaces"].toArray().last().toObject()["addresses"].toArray() == QJsonArray{"203.0.113.8/32"}, "foreign interface address was hidden");
    auto renamed = ownedInterface;renamed["name"] = "foreign0";extraNetwork["interfaces"] = QJsonArray{originalInterface, renamed};
    check(!filter(extraNetwork, dns), "reused or renamed interface authorized an exclusion");
    auto foreignDns = dns;auto values = resolved;values["Domains"] = QJsonArray{domain, foreignDomain, QJsonObject{{"interface_index", 7}, {"domain", "foreign.test"}, {"route_only", true}}};foreignDns["resolved"] = values;
    check(filter(network, foreignDns)->second["resolved"].toObject()["Domains"].toArray().size() == 2, "foreign DNS scope on an owned link was hidden");
    values = resolved;auto wrongLink = link;wrongLink["name"] = "foreign0";values["Links"] = QJsonArray{wrongLink};foreignDns["resolved"] = values;
    check(!filter(network, foreignDns), "DNS link identity mismatch was accepted");

    auto dnsConfiguration = configuration;
    const QJsonObject originalServer{{"family", AF_INET}, {"address", "192.0.2.53"}, {"port", 0}, {"name", ""}};
    const QJsonObject ipv6Server{{"family", AF_INET6}, {"address", "2001:db8::53"}, {"port", 5353}, {"name", "upstream.test"}};
    const QJsonObject expected{{"index", 3}, {"provider", QJsonObject{{"bus", QString(32, 'a')}, {"owner", ":1.2"}}},
        {"profile", QJsonObject{{"dns", QJsonArray{originalServer, ipv6Server}},
            {"domains", QJsonArray{QJsonObject{{"name", "original.test"}, {"route_only", true}}}}, {"default_route", true}}},
        {"security", QJsonObject{{"DNSOverTLS", "no"}, {"DNSSEC", "yes"}}}};
    dnsConfiguration.originalDns = {{"helperdns0", "192.0.3.1", 47321, expected}};
    const auto originalFilter = linuxOriginalNetworkView(owner, dnsConfiguration, device, 2);
    check(bool(originalFilter), "A confirmed native source could not create its original view");
    auto nativeRow = [](QJsonObject endpoint, int index) {
        endpoint["server_name"] = endpoint["name"]; endpoint.remove("name"); endpoint["interface_index"] = index;
        return endpoint;
    };
    const auto replaced = nativeRow(linuxLinkDnsEndpoint(owner, "192.0.3.1", 47321), 3);
    const auto originalRow = nativeRow(originalServer, 3), ipv6Row = nativeRow(ipv6Server, 3);
    auto unrelated = foreignServer; unrelated["interface_index"] = 4;
    const QJsonObject nativeLink{{"interface_index", 3}, {"name", "helperdns0"}, {"DefaultRoute", true},
        {"DNSOverTLS", "no"}, {"DNSSEC", "yes"}};
    auto nativeNetwork = network; auto interfaces = network["interfaces"].toArray();
    const QJsonObject sourceInterface{{"index", 3}, {"name", "helperdns0"}, {"up", true}, {"loopback", false},
        {"addresses", QJsonArray{"192.0.3.1/24"}}};
    interfaces.append(sourceInterface); nativeNetwork["interfaces"] = interfaces;
    auto nativeDomain = foreignDomain; nativeDomain["interface_index"] = 3;
    auto nativeResolved = resolved; nativeResolved["ResolvConfMode"] = "stub";
    nativeResolved["Domains"] = QJsonArray{domain, nativeDomain, foreignDomain};
    nativeResolved["DNS"] = QJsonArray{server, replaced, unrelated};
    nativeResolved["Links"] = QJsonArray{link, nativeLink};
    auto nativeDns = dns; nativeDns["resolved"] = nativeResolved;
    const auto restoredView = originalFilter(nativeNetwork, nativeDns);
    auto before = nativeResolved; before["DNS"] = QJsonArray{originalRow, ipv6Row, unrelated};
    before["Links"] = QJsonArray{nativeLink}; before["Domains"] = QJsonArray{nativeDomain, foreignDomain};
    check(restoredView && restoredView->second["resolved"] == before
        && linuxOriginalDnsSourcesMatch(dnsConfiguration, restoredView->first, restoredView->second),
        "Owned original DNS did not project exact ordered IPv4/IPv6 servers and security");
    auto rerouted = restoredView->second;
    auto foreignRouting = rerouted["resolved"].toObject(); foreignRouting["ResolvConfMode"] = "foreign"; rerouted["resolved"] = foreignRouting;
    check(!linuxOriginalDnsSourcesMatch(dnsConfiguration,restoredView->first,rerouted),
        "Changing the system resolver path kept the old native source active");
    for (const auto &key : {"port", "server_name", "addition", "missing-link", "duplicate-link"}) {
        auto changed = nativeResolved; auto endpoint = replaced;
        if (QString(key) == "port") endpoint["port"] = 47322;
        else if (QString(key) == "server_name") endpoint["server_name"] = "foreign.test";
        auto servers = QJsonArray{server, endpoint, unrelated};
        if (QString(key) == "addition") servers.append(originalRow);
        if (QString(key) == "missing-link") changed["Links"] = QJsonArray{link};
        if (QString(key) == "duplicate-link") changed["Links"] = QJsonArray{link, nativeLink, nativeLink};
        changed["DNS"] = servers; auto snapshot = dns; snapshot["resolved"] = changed;
        const auto external = originalFilter(nativeNetwork, snapshot);
        servers.removeFirst();
        check(external && external->second["resolved"].toObject()["DNS"].toArray() == servers
            && !linuxOriginalDnsSourcesMatch(dnsConfiguration, external->first, external->second),
            "External original DNS or ambiguous identity was hidden instead of invalidating its source");
    }
    for (const auto &key : {"Domains", "DefaultRoute", "DNSOverTLS", "DNSSEC"}) {
        auto changed = nativeResolved;
        if (QString(key) == "Domains") {
            auto updated = nativeDomain; updated["domain"] = "changed.test"; changed["Domains"] = QJsonArray{domain, updated, foreignDomain};
        } else {
            auto updated = nativeLink;
            updated[key] = QString(key) == "DefaultRoute" ? QJsonValue(false) : QJsonValue("changed");
            changed["Links"] = QJsonArray{link, updated};
        }
        auto snapshot = dns; snapshot["resolved"] = changed;
        const auto external = originalFilter(nativeNetwork, snapshot);
        auto visibleDomains = changed["Domains"].toArray(), visibleLinks = changed["Links"].toArray();
        visibleDomains.removeFirst(); visibleLinks.removeFirst();
        check(external && external->second["resolved"].toObject()["DNS"].toArray() == before["DNS"].toArray()
            && external->second["resolved"].toObject()["Domains"].toArray() == visibleDomains
            && external->second["resolved"].toObject()["Links"].toArray() == visibleLinks
            && !linuxOriginalDnsSourcesMatch(dnsConfiguration, external->first, external->second),
            "An external DNS scope/default/security change was hidden by endpoint projection");
    }
    for (const auto &key : {"name", "up", "addresses"}) {
        auto changed = sourceInterface;
        changed[key] = QString(key) == "name" ? QJsonValue("reused0") : QString(key) == "up" ? QJsonValue(false) : QJsonValue(QJsonArray{"192.0.3.2/24"});
        auto moved = restoredView->first; moved["interfaces"] = QJsonArray{originalInterface, changed};
        check(!linuxOriginalDnsSourcesMatch(dnsConfiguration, moved, restoredView->second),
            "A changed DNS-only interface or listener address was hidden by the unchanged data exit");
    }
    auto inheritedConfiguration = dnsConfiguration;
    auto inheritedExpected = expected; auto inheritedSecurity = expected["security"].toObject();
    inheritedSecurity["DNSOverTLS"] = ""; inheritedExpected["security"] = inheritedSecurity;
    inheritedConfiguration.originalDns[0].expected = inheritedExpected;
    auto inherited = before; auto inheritedLink = nativeLink; inheritedLink["DNSOverTLS"] = "";
    inherited["Links"] = QJsonArray{inheritedLink}; inherited["DNSOverTLS"] = "no";
    check(linuxOriginalDnsSourcesMatch(inheritedConfiguration, restoredView->first, {{"resolved", inherited}}),
        "An unchanged inherited plain transport was rejected");
    inherited["DNSOverTLS"] = "yes";
    check(!linuxOriginalDnsSourcesMatch(inheritedConfiguration, restoredView->first, {{"resolved", inherited}}),
        "Changed inherited encryption kept forwarding through the plain listener");
    inherited["Links"] = QJsonArray{nativeLink};
    check(linuxOriginalDnsSourcesMatch(dnsConfiguration, restoredView->first, {{"resolved", inherited}}),
        "A global mode change overrode the explicit native link transport");
    configuration.dnsDomains.clear();
    check(linuxOriginalNetworkView(owner, configuration, device, 2)(network, dns)->second == dns, "IP-only ownership changed the DNS view");
    std::cout << "PASS: owned network projection, external routes/selectors/addresses/DNS, identity and duplicate guards\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
