#include "infrastructure/networkhelper/linux/networkownership.h"
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
    configuration.dnsDomains.clear();
    check(linuxOriginalNetworkView(owner, configuration, device, 2)(network, dns)->second == dns, "IP-only ownership changed the DNS view");
    std::cout << "PASS: owned network projection, external routes/selectors/addresses/DNS, identity and duplicate guards\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
