#include "application/networkprotection.h"
#include <QCoreApplication>
#include <QHostAddress>
#include <QJsonDocument>
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    auto network = QJsonDocument::fromJson(R"({
        "interfaces":[
            {"name":"ethernet","addresses":["192.168.24.19/24","fe80::1/64"]},
            {"name":"overlay","addresses":["100.74.12.3/32","fd7a:115c:a1e0::1234/128"]}
        ],
        "routes":[
            {"destination":"0.0.0.0/0"}, {"destination":"0.0.0.0/1"}, {"destination":"128.0.0.0/1"},
            {"destination":"::/0"}, {"destination":"::/1"}, {"destination":"8000::/1"},
            {"destination":"192.168.24.0/24","interface_index":1},
            {"destination":"172.27.16.0/20","interface_index":2},
            {"destination":"10.42.0.0/16","table":52,"interface_index":3},
            {"destination":"2001:db8:1234::/48","table":52,"next_hops":[{"interface_index":3},{"interface_index":4}]}
        ],
        "policy_rules":[{"priority":100,"table":52,"attributes":[{"type":10,"value_hex":"01000000"}]}]
    })").object();
    const auto original = network;
    const auto targets = originalNetworkProtection(network);
    check(targets.has_value() && network == original, "Native facts changed or model rejected");
    auto protectedTarget = [&](const QString &ip) {
        for (const auto &value : *targets) {
            const auto subnet = QHostAddress::parseSubnet(value.toObject()["prefix"].toString());
            if (QHostAddress(ip).isInSubnet(subnet)) return true;
        }
        return false;
    };
    for (const auto &ip : {"127.17.4.9", "::1", "192.168.24.254", "fe80::123", "100.74.12.3",
                           "fd7a:115c:a1e0::1234", "172.27.31.254", "10.42.255.254", "2001:db8:1234:1::1"})
        check(protectedTarget(ip), "Actual local, WSL or overlay destination lost");
    for (const auto &ip : {"8.8.8.8", "10.43.0.1", "192.168.25.1", "100.74.12.4", "2001:4860::8888", "fd00::1"})
        check(!protectedTarget(ip), "Exit or unrelated private address became a protected target");
    bool explained = false;
    for (const auto &value : *targets) {
        const auto target = value.toObject();
        if (target["prefix"] == "192.168.24.0/24") {
            const auto sources = target["sources"].toArray();
            explained = sources.size() == 2 && sources[0].toObject()["interface"] == 0
                && sources[1].toObject()["route"] == 6;
        }
    }
    check(explained, "Merged scope lost native interface or route provenance");
    auto resources = QJsonDocument::fromJson(R"({
        "ip_resources":[
            {"ip_min":"192.168.24.250","ip_max":"192.168.25.8","protocol":"tcp","port_min":22,"port_max":22},
            {"ip_min":"10.41.255.255","ip_max":"10.43.0.0","protocol":"udp","port_min":53,"port_max":53},
            {"ip_min":"8.8.8.8","ip_max":"8.8.8.8","protocol":"all","port_min":1,"port_max":65535}
        ],
        "dns_records":{"mapped.campus.test":["fd7a:115c:a1e0::1234","192.168.25.1"]},
        "campus_dns":"100.74.12.3"
    })").object();
    const auto conflicts = campusProtectionConflicts(*targets, resources);
    check(conflicts && conflicts->size() == 4, "Partial, enclosing or IPv6/DNS overlaps incorrectly explained");
    bool range = false, record = false, dns = false;
    for (const auto &value : *conflicts) {
        const auto conflict = value.toObject();
        const auto prefix = (*targets)[conflict["target"].toInt()].toObject()["prefix"].toString();
        if (conflict["kind"] == "ip_resource" && conflict["resource"] == 1) range = prefix == "10.42.0.0/16";
        if (conflict["kind"] == "dns_record") record = prefix == "fd7a:115c:a1e0::1234/128"
            && conflict["domain"] == "mapped.campus.test" && conflict["record"] == 0;
        if (conflict["kind"] == "campus_dns") dns = prefix == "100.74.12.3/32";
    }
    check(range && record && dns, "Conflict lost original scope or resource role");
    for (const auto &bad : {QJsonObject{{"ip_min", "10.42.1.1"}, {"ip_max", "10.41.1.1"}},
                           QJsonObject{{"ip_min", "::1"}, {"ip_max", "127.0.0.1"}},
                           QJsonObject{{"ip_min", "::ffff:127.0.0.1"}, {"ip_max", "::ffff:127.0.0.1"}}}) {
        auto changed = resources;
        changed["ip_resources"] = QJsonArray{bad};
        check(!campusProtectionConflicts(*targets, changed), "Invalid resource published partial conflicts");
    }
    resources["dns_records"] = QJsonObject{{"broken.campus.test", "100.74.12.3"}};
    check(!campusProtectionConflicts(*targets, resources), "Collapsed DNS array hid a conflict");
    QJsonArray many;
    for (int i = 0; i < 4097; ++i) many.append("100.74.12.3");
    resources["dns_records"] = QJsonObject{{"large.campus.test", many}};
    resources["ip_resources"] = QJsonArray{};
    check(!campusProtectionConflicts(*targets, resources), "Excessive conflicts published a truncated explanation");
    for (const auto &bad : {QString("broken"), QString("::ffff:192.0.2.0/120"), QString("fe80::1%eth0/64")}) {
        auto changed = network;
        changed["routes"] = QJsonArray{QJsonObject{{"destination", bad}}};
        check(!originalNetworkProtection(changed), "Unusable route published a partial model");
    }
    network["interfaces"] = QJsonArray{QJsonObject{{"addresses", QJsonArray{"10.0.0.1/1"}}}};
    check(!originalNetworkProtection(network), "Unrepresentable interface protection silently discarded");
    check(!originalNetworkProtection({}), "Missing native facts treated as an empty network");
    std::cout << "PASS: actual original targets, exit exclusions, native provenance and invalid snapshot rejection\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
