#include "infrastructure/platform/linux/networkhelperpreparation.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonArray>
#include <QHostAddress>
#include <iostream>
#include <stdexcept>

static void check(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
int main(int argc, char **argv) try {
    QCoreApplication app(argc,argv);
    const auto resources = QJsonDocument::fromJson(R"({"ip_resources":[{"ip_min":"203.0.113.8","ip_max":"203.0.113.9","protocol":"tcp","port_min":22,"port_max":22}],
        "domain_resources":{"campus.test":[{"protocol":"tcp","port_min":22,"port_max":22}]},"dns_records":{},"campus_dns":"203.0.113.53","campus_dns_enabled":true,"underlay_interface":"original0"})").object();
    const auto policy = QJsonObject{{"protected",QJsonArray{"192.0.2.0/24"}},{"campus",QJsonArray{}},
        {"protected_names",QJsonArray{}},{"campus_names",QJsonArray{}}};
    const auto network = QJsonObject{{"interfaces",QJsonArray{QJsonObject{{"name","original0"},{"up",true},{"loopback",false},
        {"addresses",QJsonArray{"192.0.2.1/24"}}}}},{"routes",QJsonArray{QJsonObject{{"destination","0.0.0.0/0"}}}}};
    const DnsSnapshot dns{{},QJsonDocument::fromJson(R"({"resolv_conf":{"content":"nameserver 10.0.0.1\n"},"resolved":{"DNS":[{"address":"10.0.0.2"}]}})").object()};
    QJsonArray rows;
    for (const auto *address : {"203.0.113.8","203.0.113.9","203.0.113.53"})
        rows.append(QJsonObject{{"dst",address},{"dev","original0"},{"prefsrc","192.0.2.1"},{"gateway","192.0.2.254"},{"flags",QJsonArray{}}});
    int reads = 0;
    auto reader = [&](const QString &, const QStringList &arguments) {
        check(arguments == QStringList{"-N","-j","-4","-batch","-"},"preparation changed its read-only batch command");
        ++reads;
        QString output;
        for (const auto &row : rows) output += QString::fromUtf8(QJsonDocument(QJsonArray{row}).toJson(QJsonDocument::Compact))+"\n";
        return PlatformCommandResult{{},output,{}};
    };
    const auto prepared = prepareLinuxNetworkHelper(resources,policy,network,dns,"10.0.0.3:53",1400,reader);
    check(prepared.result.succeeded() && reads == 1,"complete preparation did not use a single route batch");
    const auto &config = prepared.configuration;
    check(config.originalInterface == "original0" && config.originalSource == "192.0.2.1" && config.originalGateway == "192.0.2.254"
          && config.capturePrefixes == QStringList{"203.0.113.8/31","203.0.113.53/32"}
          && config.originalPrefixes == config.capturePrefixes && config.dnsDomains == QStringList{"campus.test"},
          "prepared helper configuration lost actual exit or resource targets");
    check(config.address != config.peer && !QHostAddress(config.address).isInSubnet(QHostAddress::parseSubnet("192.0.2.0/24")),
          "prepared point-to-point addresses collide with the original network");
    for (const auto &address : {config.address,config.peer})
        check(address != "10.0.0.1" && address != "10.0.0.2" && address != "10.0.0.3",
              "device allocation stole a system or explicitly configured DNS server");
    auto held = config;
    held.capturePrefixes.append("203.0.113.70/32");
    auto nextPolicy = policy;
    nextPolicy["protected"] = QJsonArray{"192.0.2.0/24","203.0.113.8/31"};
    check(updatedLinuxCapturePrefixes(resources,policy,nextPolicy,held) == std::optional<QStringList>{{"203.0.113.53/32","203.0.113.70/32"}},
          "Live policy failed to withdraw static capture or lost a confirmed DNS target");
    nextPolicy["campus"] = QJsonArray{"203.0.113.8"};
    check(updatedLinuxCapturePrefixes(resources,policy,nextPolicy,held) == std::optional<QStringList>{{"203.0.113.8/32","203.0.113.53/32","203.0.113.70/32"}},
          "Explicit campus choice did not restore its exact host route");
    nextPolicy["protected"] = QJsonArray{"192.0.2.0/24","203.0.113.70/32"};
    check(updatedLinuxCapturePrefixes(resources,policy,nextPolicy,held) == std::optional<QStringList>{config.capturePrefixes},
          "New protection did not withdraw a previously published DNS target");
    nextPolicy["protected_names"] = QJsonArray{QJsonObject{{"kind","suffix"},{"value","campus.test"}}};
    check(!updatedLinuxCapturePrefixes(resources,policy,nextPolicy,held),"A policy changed DNS ownership without a supported DNS transition");
    QJsonArray exitRows;
    for (const auto *target : {"203.0.113.8","203.0.113.9","203.0.113.53"})
        exitRows.append(QJsonObject{{"dst",target},{"from",config.originalSource},{"dev",config.originalInterface},
            {"gateway",config.originalGateway},{"flags",QJsonArray{}}});
    auto exitReader = [&](const QString &, const QStringList &) {
        QString result;
        for (const auto &row : exitRows) result += QString::fromUtf8(QJsonDocument(QJsonArray{row}).toJson(QJsonDocument::Compact))+"\n";
        return PlatformCommandResult{{},result,{}};
    };
    check(verifyLinuxCaptureExit(config,config.capturePrefixes,exitReader).succeeded(),"Confirmed bound-source exit was rejected");
    const auto exits = exitRows;
    for (const auto &changed : {QJsonObject{{"dev","other0"}},QJsonObject{{"gateway","192.0.2.253"}},QJsonObject{{"from","192.0.2.2"}}}) {
        exitRows = exits;
        auto row = exitRows[1].toObject();
        for (auto it=changed.begin(); it!=changed.end(); ++it) row[it.key()] = it.value();
        exitRows[1] = row;
        check(!verifyLinuxCaptureExit(config,config.capturePrefixes,exitReader).succeeded(),"Live policy accepted changed original routing");
    }
    exitRows = QJsonArray{exits[0]};
    check(!verifyLinuxCaptureExit(config,config.capturePrefixes,exitReader).succeeded(),"Truncated original exit accepted");
    auto native = network;auto iface = native["interfaces"].toArray()[0].toObject();iface["index"] = 2;
    native["interfaces"] = QJsonArray{iface};
    native["routes"] = QJsonArray{QJsonObject{{"destination","0.0.0.0/0"},{"interface_index",2},{"gateway",config.originalGateway}}};
    native["policy_rules"] = QJsonArray{QJsonObject{{"priority",0},{"table",255}}};
    const auto baselineExit = linuxOriginalExitSnapshot(native,config);
    check(bool(baselineExit),"Read complete original exit identity");
    auto overlay = native;
    auto interfaces = overlay["interfaces"].toArray();interfaces.append(QJsonObject{{"name","overlay0"},{"index",3},
        {"up",true},{"loopback",false},{"addresses",QJsonArray{"100.64.0.1/24"}}});overlay["interfaces"] = interfaces;
    auto nativeRoutes = overlay["routes"].toArray();nativeRoutes.append(QJsonObject{{"destination","100.64.0.0/24"},{"interface_index",3}});
    overlay["routes"] = nativeRoutes;
    check(linuxOriginalExitSnapshot(overlay,config) == baselineExit,"Unrelated overlay protection invalidated the confirmed original exit");
    auto changed = native;iface["up"] = false;changed["interfaces"] = QJsonArray{iface};
    check(!linuxOriginalExitSnapshot(changed,config),"A down original interface remained valid");
    changed = native;auto changedRoute = native["routes"].toArray()[0].toObject();changedRoute["gateway"] = "192.0.2.253";
    changed["routes"] = QJsonArray{changedRoute};
    check(linuxOriginalExitSnapshot(changed,config) != baselineExit,"Owned source pins hid an externally changed gateway");
    changed = native;changed["policy_rules"] = QJsonArray{QJsonObject{{"priority",1},{"table",123}}};
    check(linuxOriginalExitSnapshot(changed,config) != baselineExit,"Changed external policy routing remained trusted");
    auto injection = resources;
    injection["underlay_interface"] = "original0\nroute del default";
    check(!prepareLinuxNetworkHelper(injection,policy,network,dns,"10.0.0.3:53",1400,reader).result.succeeded() && reads == 1,
          "invalid interface reached the batch input");
    const auto original = rows;
    for (const auto &change : {QJsonObject{{"dst","203.0.113.99"}}, QJsonObject{{"dev","another0"}},
            QJsonObject{{"prefsrc","192.0.2.2"}}, QJsonObject{{"gateway","192.0.2.253"}},
            QJsonObject{{"flags",QJsonArray{"linkdown"}}}, QJsonObject{{"type","local"}}, QJsonObject{{"nhid",1}}}) {
        rows = original;
        auto changed = rows[1].toObject();
        for (auto it=change.begin(); it!=change.end(); ++it) changed[it.key()] = it.value();
        rows[1] = changed;
        const auto invalid = prepareLinuxNetworkHelper(resources,policy,network,dns,"10.0.0.3:53",1400,reader);
        check(!invalid.result.succeeded() && invalid.configuration.address.isEmpty(),"ambiguous exit produced a partial configuration");
    }
    rows = QJsonArray{original[0]};
    check(!prepareLinuxNetworkHelper(resources,policy,network,dns,"10.0.0.3:53",1400,reader).result.succeeded(),"truncated route batch accepted");
    const auto beforeDNSFailure = reads;
    const DnsSnapshot unavailable{{PlatformOperationResult::Status::Failed,"cannot inspect original DNS"},{}};
    const auto missingDNS = prepareLinuxNetworkHelper(resources,policy,network,unavailable,{},1400,reader);
    check(!missingDNS.result.succeeded() && missingDNS.configuration.address.isEmpty() && reads == beforeDNSFailure,
          "unknown original DNS proceeded to route preparation");
    const auto denied = prepareLinuxNetworkHelper(resources,policy,network,dns,"10.0.0.3:53",1400,
        [](const QString &, const QStringList &) { return PlatformCommandResult{{PlatformOperationResult::Status::PermissionDenied,"denied"},{},{}}; });
    check(denied.result.status == PlatformOperationResult::Status::PermissionDenied && denied.configuration.address.isEmpty(),
          "native route query failure was hidden");
    std::cout << "PASS: bounded original-exit batch, private address allocation, conflict/input guards and native failure propagation\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
