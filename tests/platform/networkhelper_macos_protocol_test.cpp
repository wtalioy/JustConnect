#include "infrastructure/platform/macos/networkhelper.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv);
    const auto owner = QUuid::createUuid(), request = QUuid::createUuid();
    const MacHelperConfiguration configuration{"198.18.0.1","198.18.0.2",1400,{"198.18.0.6/32","198.18.1.0/24"}};
    const auto packet = macHelperApplyRequest(owner,request,configuration);
    const auto parsed = parseMacHelperApply(packet);
    check(parsed && parsed->address == configuration.address && parsed->peer == configuration.peer
        && parsed->mtu == configuration.mtu && parsed->capturePrefixes == configuration.capturePrefixes,"Valid complete configuration lost its semantics");
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
