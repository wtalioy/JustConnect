#include "infrastructure/networkhelper/macos/networkhelper.h"
#include "infrastructure/networkhelper/macos/networkhelperpreparation.h"
#include <QJsonDocument>
#include <QCoreApplication>
#include <QJsonArray>
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv);
    const auto owner = QUuid::createUuid(), request = QUuid::createUuid();
    const MacHelperConfiguration configuration{"198.18.0.1","198.18.0.2",1400,{"198.18.0.6/32","198.18.1.0/24"},{"campus.example.test"}};
    const auto packet = macHelperApplyRequest(owner,request,configuration);
    const auto parsed = parseMacHelperApply(packet);
    check(parsed && parsed->address == configuration.address && parsed->peer == configuration.peer
        && parsed->mtu == configuration.mtu && parsed->capturePrefixes == configuration.capturePrefixes
        && parsed->dnsDomains == configuration.dnsDomains,"Valid complete configuration lost its semantics");
    for (const auto &domains : {QJsonValue("campus.example.test"),QJsonValue(QJsonArray{"."}),QJsonValue(QJsonArray{"campus.example.test","campus.example.test"}),
            QJsonValue(QJsonArray{"Upper.test"}),QJsonValue(QJsonArray{"a..test"}),QJsonValue(QJsonArray{1}),QJsonValue(QJsonArray{"-bad.test"})}) {
        auto broken = packet; auto config = broken["configuration"].toObject(); config["dns_domains"] = domains; broken["configuration"] = config;
        check(!parseMacHelperApply(broken),"Malformed or default DNS scope was accepted");
    }
    auto noDns = packet; auto noDnsConfig = noDns["configuration"].toObject(); noDnsConfig["dns_domains"] = QJsonArray{}; noDns["configuration"] = noDnsConfig;
    check(parseMacHelperApply(noDns).has_value(),"Explicitly disabled system DNS was rejected");
    const auto extension = macHelperExtendRequest(owner,request,{"198.18.0.7","198.18.0.7","198.18.0.6"});
    check(parseMacHelperExtend(extension) == std::optional(QStringList{"198.18.0.7","198.18.0.6"}),"DNS address request lost its canonical unique targets");
    for (const auto &addresses : {QJsonArray{},QJsonArray{1},QJsonArray{"127.0.0.1"},QJsonArray{"224.0.0.1"},QJsonArray{"198.18.0.7/32"},QJsonArray{"198.18.00.7"}}) {
        auto invalid = extension; invalid["addresses"] = addresses;
        check(!parseMacHelperExtend(invalid),"Invalid DNS publication crossed the privilege boundary");
    }
    auto injected = extension; injected["program"] = "/bin/sh";
    check(!parseMacHelperExtend(injected),"DNS publication accepted an arbitrary execution field");
    const auto routes = macHelperRoutesRequest(owner,request,{"198.18.0.7/32","198.18.1.0/24"});
    check(parseMacHelperRoutes(routes) == std::optional(QStringList{"198.18.0.7/32","198.18.1.0/24"})
        && parseMacHelperRoutes(macHelperRoutesRequest(owner,request,{})) == std::optional(QStringList{}),"Capture replacement lost its targets or explicit withdrawal");
    for (const auto &prefixes : {QJsonArray{1},QJsonArray{"127.0.0.1/32"},QJsonArray{"0.0.0.0/0"},
            QJsonArray{"198.18.0.7/31"},QJsonArray{"198.18.0.7/32","198.18.0.7/32"}}) {
        auto invalid = routes; invalid["prefixes"] = prefixes;
        check(!parseMacHelperRoutes(invalid),"Unsafe replacement crossed the privilege boundary");
    }
    injected = routes; injected["program"] = "/bin/sh";
    check(!parseMacHelperRoutes(injected),"Capture replacement accepted an arbitrary execution field");
    for (const auto *operation : {"probe","restore","recover","cleanup"})
        check(validMacHelperRequest(macHelperRequest(operation,owner,request)),"Bound owner operation was rejected");
    for (const auto *key : {"schema_version","owner","request_id","operation"}) {
        auto broken = packet; broken.remove(key);
        check(!parseMacHelperApply(broken),"Incomplete request reached privileged preparation");
    }
    for (const auto &bad : {QJsonValue(1400.5),QJsonValue(-1),QJsonValue("1400"),QJsonValue(65536)}) {
        auto broken = packet; auto config = broken["configuration"].toObject();config["mtu"] = bad;broken["configuration"] = config;
        check(!parseMacHelperApply(broken),"Invalid MTU reached device preparation");
    }
    for (const auto &prefixes : {QStringList{"127.0.0.1/32"},QStringList{"64.0.0.0/2"},QStringList{"192.0.0.0/2"},
             QStringList{"224.0.0.0/4"},QStringList{"0.0.0.0/8"},QStringList{"198.18.0.1/32"},
             QStringList{"198.18.0.6/32","198.18.0.6/32"},QStringList{"198.18.0.7/31"},QStringList{}}) {
        auto broken = packet;auto config = broken["configuration"].toObject();config["prefixes"] = QJsonArray::fromStringList(prefixes);broken["configuration"] = config;
        check(!parseMacHelperApply(broken),"Unsafe, duplicate or noncanonical capture was accepted");
    }
    auto unexpected = packet;unexpected["program"] = "/bin/sh";
    check(!parseMacHelperApply(unexpected),"Arbitrary execution field was accepted");
    unexpected = packet;unexpected["owner"] = owner.toString();
    check(!parseMacHelperApply(unexpected),"Noncanonical owner crossed the boundary");
    const auto successful = macHelperResponse(extension,{});
    check(!parseMacHelperResponse(successful,extension),"Success without confirmed network facts was accepted");
    auto scoped = successful; scoped["network"] = QJsonObject{{"capture",QJsonObject{}},{"dns",QJsonObject{}},{"device_routes",QJsonArray{}}};
    check(parseMacHelperResponse(scoped,extension).has_value(),"Typed network-view envelope was rejected");
    scoped["operation"] = "restore";
    check(!parseMacHelperResponse(scoped,macHelperRequest("restore",owner,request)),"Restore acquired an unrelated active network view");
    const auto resources = QJsonDocument::fromJson(R"({"ip_resources":[{"ip_min":"203.0.113.8","ip_max":"203.0.113.9","protocol":"tcp","port_min":22,"port_max":22}],
        "domain_resources":{"campus.test":[{"protocol":"tcp","port_min":22,"port_max":22}]},"dns_records":{},"campus_dns":"203.0.113.53","campus_dns_enabled":true,"underlay_interface":""})").object();
    const QJsonObject protection{{"protected",QJsonArray{"192.0.2.0/24"}},{"campus",QJsonArray{}},{"protected_names",QJsonArray{}},{"campus_names",QJsonArray{}}};
    const QJsonObject network{{"interfaces",QJsonArray{QJsonObject{{"addresses",QJsonArray{"192.0.2.1/24"}}}}},{"routes",QJsonArray{QJsonObject{{"destination","0.0.0.0/0"}}}}};
    const QJsonObject dns{{"dynamic_store",QJsonObject{{"fixture",QJsonObject{{"ServerAddresses",QJsonArray{"10.0.0.1","10.0.0.2"}}}}}}};
    const auto prepared = prepareMacNetworkHelper(resources,protection,network,dns,"10.0.0.3:53",1400);
    check(prepared.result.succeeded() && prepared.configuration.capturePrefixes == QStringList{"203.0.113.8/31","203.0.113.53/32"}
        && prepared.configuration.dnsDomains == QStringList{"campus.test"},"Mac preparation lost actual resource scopes");
    for (const auto &address : {prepared.configuration.address,prepared.configuration.peer})
        check(address != "10.0.0.1" && address != "10.0.0.2" && address != "10.0.0.3","Mac preparation captured an existing DNS endpoint");
    auto missing = resources; missing["underlay_interface"] = "justconnect-nonexistent-interface";
    check(!prepareMacNetworkHelper(missing,protection,network,dns,{},1400).result.succeeded(),"Missing selected underlay was silently ignored");
    const auto response = macHelperResponse(packet,{PlatformOperationResult::Status::PermissionDenied,"denied",true});
    const auto result = parseMacHelperResponse(response,packet);
    check(result && result->status == PlatformOperationResult::Status::PermissionDenied && result->mayHaveChanged,"Typed denial or retained responsibility was lost");
    auto wrong = response;wrong["request_id"] = QUuid::createUuid().toString(QUuid::WithoutBraces);
    check(!parseMacHelperResponse(wrong,packet),"Stale reply was accepted");
    wrong = response;wrong["device"] = QJsonObject{{"owner",owner.toString(QUuid::WithoutBraces)}};
    check(!parseMacHelperResponse(wrong,packet),"Failed operation delivered a device");
    wrong = response;wrong["detail"] = QString(MacHelperPacketBytes,'x');
    check(!parseMacHelperResponse(wrong,packet),"Oversized response was accepted");
    const auto probe = macHelperRequest("probe",owner,request);
    auto receipts = macHelperResponse(probe,{});
    check(!parseMacHelperResponse(receipts,probe),"Incomplete ownership discovery was accepted");
    receipts["owners"] = QJsonArray{QJsonObject{{"owner",owner.toString(QUuid::WithoutBraces)},{"phase","active"}}};
    check(parseMacHelperResponse(receipts,probe).has_value(),"Current user ownership discovery was rejected");
    auto invalid = receipts;auto list = invalid["owners"].toArray();list.append(list.first());invalid["owners"] = list;
    check(!parseMacHelperResponse(invalid,probe),"Duplicate recovery responsibility was accepted");
    invalid = receipts;invalid["owners"] = QJsonArray{QJsonObject{{"owner",owner.toString(QUuid::WithoutBraces)},{"phase","invented"}}};
    check(!parseMacHelperResponse(invalid,probe),"Unknown recovery state was accepted");
    std::cout << "PASS: bounded macOS helper requests, configuration, owner binding and typed responses\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n';return 1; }
