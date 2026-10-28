#include "application/networkprotection.h"
#include "infrastructure/networkhelper/windows/networkhelperpreparation.h"
#include <QCoreApplication>
#include <algorithm>
#include <QHostAddress>
#include <QJsonDocument>
#include <QSet>
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }


static void captureTargets()
{
    auto resources = QJsonDocument::fromJson(R"({
        "ip_resources":[
            {"ip_min":"192.168.24.250","ip_max":"192.168.25.8","protocol":"tcp","port_min":22,"port_max":22},
            {"ip_min":"100.74.12.3","ip_max":"100.74.12.3","protocol":"udp","port_min":53,"port_max":53},
            {"ip_min":"127.9.0.1","ip_max":"127.9.0.1","protocol":"all","port_min":1,"port_max":65535},
            {"ip_min":"2001:db8::1","ip_max":"2001:db8::ffff","protocol":"tcp","port_min":80,"port_max":80}
        ],
        "domain_resources":{"*.campus.test":[{"protocol":"tcp","port_min":22,"port_max":22}],".campus.test":[{"protocol":"tcp","port_min":80,"port_max":80}]},
        "dns_records":{"mapped.campus.test":["192.168.25.1","2001:db8::7"]},
        "campus_dns":"203.0.113.53","campus_dns_enabled":true
    })").object();
    auto policy = QJsonObject{{"protected",QJsonArray{"192.168.24.0/24","100.74.12.3/32","127.0.0.0/8","::1/128"}},
        {"campus",QJsonArray{"192.168.24.253","100.74.12.3","127.9.0.1"}},
        {"protected_names",QJsonArray{QJsonObject{{"kind","exact"},{"value","localhost"}}}}, {"campus_names",QJsonArray{}}};
    const auto plan = campusCaptureTargets(resources, policy);
    check(plan && plan->ipv4Prefixes == QStringList{"100.74.12.3/32","192.168.24.253/32","192.168.25.0/29","192.168.25.8/32","203.0.113.53/32"},
          "Initial capture lost exact choices, range boundaries, coalescing or actual DNS");
    check(plan->dnsDomains == QStringList{"campus.test"},"DNS domains were not derived from normalized resources");
    auto originalAnswers = resources;
    originalAnswers["original_dns_records"] = QJsonObject{{"private.original.test",QJsonArray{"203.0.113.9","192.168.24.252"}}};
    auto originalPolicy = policy;
    auto protectedNames = policy["protected_names"].toArray();
    protectedNames.append(QJsonObject{{"kind","suffix"},{"value","original.test"}});
    originalPolicy["protected_names"] = protectedNames;
    auto originalIPs = resources["ip_resources"].toArray();
    originalIPs.append(QJsonObject{{"ip_min","203.0.113.0"},{"ip_max","203.0.113.255"},{"protocol","tcp"},{"port_min",80},{"port_max",80}});
    originalAnswers["ip_resources"] = originalIPs;
    originalAnswers["original_dns_records"] = QJsonObject{{"private.original.test",QJsonArray{"203.0.113.9","192.168.24.253"}}};
    const auto originalCapture = campusCaptureTargets(originalAnswers, originalPolicy);
    const auto contains = [](const QStringList &prefixes, const QString &address) {
        return std::any_of(prefixes.begin(),prefixes.end(),[&](const QString &prefix) { return QHostAddress(address).isInSubnet(QHostAddress::parseSubnet(prefix)); });
    };
    check(originalCapture && !contains(originalCapture->ipv4Prefixes,"203.0.113.9")
          && !contains(originalCapture->ipv4Prefixes,"192.168.24.253")
          && contains(originalCapture->ipv4Prefixes,"203.0.113.8") && contains(originalCapture->ipv4Prefixes,"203.0.113.10")
          && originalCapture->dnsDomains == plan->dnsDomains,
          "Original name protection did not withdraw capture or lost unrelated campus targets");
    originalPolicy["campus_names"] = QJsonArray{"private.original.test"};
    const auto chosen = campusCaptureTargets(originalAnswers,originalPolicy);
    check(chosen && contains(chosen->ipv4Prefixes,"203.0.113.9") && contains(chosen->ipv4Prefixes,"192.168.24.253"),
          "Exact campus name choice did not release its original exclusion");
    auto shared = originalAnswers["original_dns_records"].toObject();
    shared["other.original.test"] = QJsonArray{"203.0.113.9"}; originalAnswers["original_dns_records"] = shared;
    const auto stillProtected = campusCaptureTargets(originalAnswers,originalPolicy);
    check(stillProtected && !contains(stillProtected->ipv4Prefixes,"203.0.113.9"),"One chosen name removed another name's shared-IP protection");
    originalPolicy["campus_names"] = QJsonArray{};
    check(campusCaptureTargets(originalAnswers,originalPolicy)->ipv4Prefixes == originalCapture->ipv4Prefixes,
          "Withdrawing the campus choice failed to restore original exclusions");
    for (const auto &rule : {QJsonObject{{"kind","exact"},{"value","private.original.test"}},
                             QJsonObject{{"kind","prefix"},{"value","private"}},
                             QJsonObject{{"kind","single_label"},{"value",""}}}) {
        auto scoped = originalPolicy;
        scoped["protected_names"] = QJsonArray{rule};
        auto answers = originalAnswers;
        answers["campus_dns_enabled"] = false;
        answers["dns_records"] = QJsonObject{};
        const auto name = rule["kind"] == "single_label" ? QStringLiteral("private") : QStringLiteral("private.original.test");
        answers["original_dns_records"] = QJsonObject{{name,QJsonArray{"203.0.113.9"}}};
        const auto planned = campusCaptureTargets(answers,scoped);
        check(planned && !contains(planned->ipv4Prefixes,"203.0.113.9"),"Native exact/prefix/single-label protection lost its exclusion");
    }
    const auto withdrawn = excludeCampusCaptureAddresses({"198.51.100.0/30","203.0.113.7/32"},
                                                       {"198.51.100.1","203.0.113.7","198.51.100.200"});
    check(withdrawn && *withdrawn == QStringList{"198.51.100.0/32","198.51.100.2/31"},"Live withdrawal captured new addresses or lost retained targets");
    const auto emptyCapture = excludeCampusCaptureAddresses({}, {"203.0.113.7"});
    check(emptyCapture && emptyCapture->isEmpty(),"An empty owned capture gained authority");
    for (const auto &invalid : {QStringList{"0.0.0.0/0"},QStringList{"198.51.100.1/24"},QStringList{"::/64"},QStringList{"bad"}})
        check(!excludeCampusCaptureAddresses(invalid,{"203.0.113.7"}),"Invalid owned prefix produced a partial withdrawal");
    check(!excludeCampusCaptureAddresses({"203.0.113.7/32"},{"::1"}),"Invalid exclusion address was accepted");
    for (const auto &invalid : {QJsonObject{{"Bad.original.test",QJsonArray{"203.0.113.9"}}},
                               QJsonObject{{"private.original.test",QJsonArray{"invalid"}}},
                               QJsonObject{{"private.original.test",QJsonArray{42}}}}) {
        originalAnswers["original_dns_records"] = invalid;
        check(!campusCaptureTargets(originalAnswers, originalPolicy),"Invalid original answer produced a partial capture plan");
    }
    const QJsonObject allocationNetwork{{"interfaces",QJsonArray{QJsonObject{{"addresses",QJsonArray{"10.0.0.1/8","172.16.0.1/16","2001:db8::1/64"}}}}},
        {"routes",QJsonArray{QJsonObject{{"destination","0.0.0.0/0"}}}}};
    const auto pair = privateTUNAddresses(allocationNetwork, {"172.17.0.0/16","192.168.0.0/16"});
    check(pair && QHostAddress(pair->second).toIPv4Address() == QHostAddress(pair->first).toIPv4Address()+1,
          "Private point-to-point allocation did not return two distinct consecutive addresses");
    for (const auto &address : {pair->first,pair->second}) {
        check(QHostAddress(address).isInSubnet(QHostAddress::parseSubnet("172.16.0.0/12"))
            && !QHostAddress(address).isInSubnet(QHostAddress::parseSubnet("172.16.0.0/16"))
            && !QHostAddress(address).isInSubnet(QHostAddress::parseSubnet("172.17.0.0/16")),
              "Private TUN allocation overlapped an original or campus target");
    }
    check(!privateTUNAddresses(allocationNetwork,{"172.16.0.0/12","192.168.0.0/16"}),
          "Exhausted private pools reused an occupied address");
    check(!privateTUNAddresses(allocationNetwork,{"172.16.0.1/16"}),"Invalid capture prefix reached device allocation");
    resources["underlay_interface"]="";
    const QJsonObject dns{{"interfaces",QJsonArray{QJsonObject{{"ServerAddresses",QJsonArray{"172.17.0.1","172.17.0.2"}}}}}};
    const auto prepared=prepareWindowsNetworkHelper(resources,policy,allocationNetwork,dns,"172.17.0.3:53",1400);
    check(prepared.result.succeeded() && prepared.configuration["capture_prefixes"]==QJsonArray::fromStringList(plan->ipv4Prefixes)
        && prepared.configuration["dns_domains"]==QJsonArray::fromStringList(plan->dnsDomains)
        && prepared.configuration.value("original_dns").isArray() && prepared.configuration.value("original_dns").toArray().isEmpty(),"Windows preparation lost confirmed resource scopes or native source contract");
    for(const auto &field:{"address","peer"}){
        const QHostAddress address(prepared.configuration[field].toString());
        check(!address.isInSubnet(QHostAddress::parseSubnet("10.0.0.0/8"))
            && !address.isInSubnet(QHostAddress::parseSubnet("172.16.0.0/16"))
            && !QStringList{"172.17.0.1","172.17.0.2","172.17.0.3"}.contains(address.toString()),
            "Windows preparation reused original network or DNS addresses");
    }
    auto missingUnderlay=resources;missingUnderlay["underlay_interface"]="missing-underlay";
    check(!prepareWindowsNetworkHelper(missingUnderlay,policy,allocationNetwork,dns,{},1400).result.succeeded(),
        "Windows preparation ignored a missing selected underlay");
    const QJsonObject preparedScope{{"kind","suffix"},{"value","campus.test"}};
    auto nativePolicy=policy;nativePolicy["protected_names"]=QJsonArray{preparedScope};
    auto nativeNetwork=allocationNetwork;auto nativeInterfaces=nativeNetwork["interfaces"].toArray();
    nativeInterfaces.append(QJsonObject{{"up",true},{"addresses",QJsonArray{"127.0.0.1/8"}}});nativeNetwork["interfaces"]=nativeInterfaces;
    const QJsonObject rawSource{{"store","local"},{"id","{F370639C-C387-4C4B-AC01-BF4C748A90C2}"},{"class","original provider"},
        {"namespaces",QJsonArray{".campus.test"}},{"servers","192.168.25.1;192.168.25.2"},{"version",1},{"options",8},{"owner",QJsonValue::Null}};
    QJsonObject nativeDNS{{"nrpt",QJsonArray{QJsonObject{{"Namespace",rawSource["namespaces"]},{"NameServers",QJsonArray{"192.168.25.1","192.168.25.2"}}}}},
        {"nrpt_sources",QJsonArray{rawSource}},{"native_global",QJsonObject{{"Status",0},{"Value",QJsonObject{{"SettingFlags","129"}}}}},
        {"configured_encryption",QJsonArray{}},{"doh_supported",true},{"doh",QJsonArray{}}};
    const auto native=prepareWindowsNetworkHelper(resources,nativePolicy,nativeNetwork,nativeDNS,{},1400);
    check(native.result.succeeded() && native.originalSources.size()==1 && native.configuration["dns_domains"].toArray().isEmpty(),
        "Native NRPT source was not prepared without a competing campus namespace");
    check(native.configuration["original_dns"].toArray().first().toObject()["source"]==rawSource
        && native.originalSources.first().toObject().value("servers").toArray()==QJsonArray{"192.168.25.1:53","192.168.25.2:53"},
        "Native source identity, raw formatting or ordered upstream group was lost");
    check(completeWindowsOriginalDNS(native.configuration,{{"127.0.0.1:53","127.0.0.1:53"}}).has_value()
        && !completeWindowsOriginalDNS(native.configuration,{{"127.0.0.1:53","127.0.0.1:5300"}}),"An unconfirmed native listener was accepted");
    check(updatedWindowsCapturePrefixes(resources,nativePolicy,native.configuration,native.originalSources).has_value(),
        "Prepared native namespaces could not reconcile campus captures");
    check(windowsOriginalDnsSourcesMatch(native.originalSources,native.originalContext,nativeNetwork,nativeDNS),
        "Confirmed source observation depended on current campus choices or nonempty captures");
    auto rootSource=rawSource;rootSource["namespaces"]=QJsonArray{".",".campus.test"};
    auto rootDNS=nativeDNS;rootDNS["nrpt_sources"]=QJsonArray{rootSource};
    auto rootPolicy=nativeDNS["nrpt"].toArray().first().toObject();rootPolicy["Namespace"]=rootSource["namespaces"];
    rootDNS["nrpt"]=QJsonArray{rootPolicy};
    const auto root=prepareWindowsNetworkHelper(resources,nativePolicy,nativeNetwork,rootDNS,{},1400);
    check(root.result.succeeded() && root.originalSources.size()==1 && root.originalSources.first().toObject()["default"]==true
        && root.originalSources.first().toObject()["name"]==preparedScope,
        "An explicit root provider lost its default context or expanded name protection");
    check(windowsOriginalDnsSourcesMatch(root.originalSources,root.originalContext,nativeNetwork,rootDNS)
        && !windowsOriginalDnsSourcesMatch(root.originalSources,root.originalContext,nativeNetwork,nativeDNS),
        "Native default changes did not invalidate their original context");
    auto changedSource=rawSource;changedSource["class"]="recreated provider";
    auto changedDNS=nativeDNS;changedDNS["nrpt_sources"]=QJsonArray{changedSource};
    check(!windowsOriginalDnsSourcesMatch(native.originalSources,native.originalContext,nativeNetwork,changedDNS),
        "Recreated original source retained the prepared query context");
    auto changedPolicy=nativeDNS["nrpt"].toArray().first().toObject();changedPolicy["QueryPolicy"]="changed native security";
    changedDNS=nativeDNS;changedDNS["nrpt"]=QJsonArray{changedPolicy};
    check(!windowsOriginalDnsSourcesMatch(native.originalSources,native.originalContext,nativeNetwork,changedDNS),
        "Native security policy change retained the prepared query context");
    const auto prefixes=native.configuration["capture_prefixes"].toArray();
    check(!contains([&]{QStringList result;for(const auto &value:prefixes)result.append(value.toString());return result;}(),"192.168.25.1"),
        "Original DNS server was recaptured by campus routing");
    for(const auto &field:{"configured_encryption","doh"}){
        auto encrypted=nativeDNS;encrypted[field]=field==QString("doh")?QJsonArray{QJsonObject{{"ServerAddress","192.168.25.1"}}}:QJsonArray{"192.168.25.1"};
        check(!prepareWindowsNetworkHelper(resources,nativePolicy,nativeNetwork,encrypted,{},1400).result.succeeded(),"Native encryption was downgraded");
    }
    auto ambiguous=nativeDNS;auto foreign=rawSource;foreign["id"]="{ED2C083A-0914-410C-A462-09FEC57B31FA}";
    ambiguous["nrpt_sources"]=QJsonArray{rawSource,foreign};
    check(!prepareWindowsNetworkHelper(resources,nativePolicy,nativeNetwork,ambiguous,{},1400).result.succeeded(),"Ambiguous native provider acquired ownership");
    check(!prepareWindowsNetworkHelper(resources,nativePolicy,allocationNetwork,nativeDNS,{},1400).result.succeeded(),"An unassigned loopback listener was invented");
    auto protectedPolicy = policy;
    protectedPolicy["protected_names"] = QJsonArray{QJsonObject{{"kind","exact"},{"value","host.campus.test"}}};
    check(!campusCaptureTargets(resources, protectedPolicy),"Protected descendant name reached a broad campus DNS route");
    protectedPolicy["campus_names"] = QJsonArray{"host.campus.test"};
    check(campusCaptureTargets(resources, protectedPolicy).has_value(),"Confirmed exact campus name choice was ignored");
    protectedPolicy["protected_names"] = QJsonArray{QJsonObject{{"kind","suffix"},{"value","campus.test"}}};
    protectedPolicy["campus_names"] = QJsonArray{"campus.test"};
    check(!campusCaptureTargets(resources, protectedPolicy),"One exact choice unprotected an entire namespace");
    protectedPolicy = policy;
    protectedPolicy["protected"] = QJsonArray{"203.0.113.53/32"};
    QString dnsDiagnostic;
    check(!campusCaptureTargets(resources, protectedPolicy, {}, {}, &dnsDiagnostic)
        && dnsDiagnostic.contains("protected original network"),"Protected campus DNS lost its refusal or useful conflict reason");
    auto forwardedPolicy = policy;
    const QJsonObject nativeScope{{"kind","suffix"},{"value","campus.test"}};
    forwardedPolicy["protected_names"] = QJsonArray{nativeScope};
    const QJsonArray sources{QJsonObject{{"name",nativeScope},{"servers",QJsonArray{"192.168.25.1:5353"}}}};
    const auto forwarded = campusCaptureTargets(resources,forwardedPolicy,{},sources);
    check(forwarded && forwarded->dnsDomains == QStringList{"campus.test"}
        && !contains(forwarded->ipv4Prefixes,"192.168.25.1") && contains(forwarded->ipv4Prefixes,"192.168.25.2"),
        "Prepared native scope lost the campus DNS route or recaptured its original server");
    const QJsonArray collision{QJsonObject{{"name",nativeScope},{"servers",QJsonArray{"203.0.113.53:53"}}}};
    check(!campusCaptureTargets(resources,forwardedPolicy,{},collision),"A shared original/campus DNS endpoint silently looped");
    const QJsonArray invalidSource{QJsonObject{{"name",nativeScope},{"servers",QJsonArray{"resolver.original.test:53"}}}};
    check(!campusCaptureTargets(resources,forwardedPolicy,{},invalidSource),"A hostname invented an original DNS route exclusion");
    auto disabled = resources;
    disabled["campus_dns_enabled"] = false;
    const auto localRecords = campusCaptureTargets(disabled, policy);
    check(localRecords && localRecords->dnsDomains == QStringList{"mapped.campus.test"}
          && !localRecords->ipv4Prefixes.contains("203.0.113.53/32"),"Disabled remote DNS still captured its server or domains");
    for (const auto &bad : {QJsonObject{{"ip_min","192.168.25.9"},{"ip_max","192.168.25.1"},{"protocol","tcp"},{"port_min",22},{"port_max",22}},
                           QJsonObject{{"ip_min","::1"},{"ip_max","127.0.0.1"},{"protocol","tcp"},{"port_min",22},{"port_max",22}},
                           QJsonObject{{"ip_min","203.0.113.7"},{"ip_max","203.0.113.7"},{"protocol","tcp"},{"port_min",0},{"port_max",22}}}) {
        auto invalid = resources;
        invalid["ip_resources"] = QJsonArray{bad};
        QString diagnostic;
        check(!campusCaptureTargets(invalid, policy, {}, {}, &diagnostic) && !diagnostic.isEmpty(),
              "Invalid resource published a partial plan or lost its failure reason");
        const auto rejected = prepareWindowsNetworkHelper(invalid,policy,allocationNetwork,dns,{},1400);
        check(!rejected.result.succeeded() && rejected.result.detail == diagnostic,
              "Initial helper preparation replaced the capture failure reason");
    }
    auto wide = resources;
    wide["ip_resources"] = QJsonArray{QJsonObject{{"ip_min","0.0.0.0"},{"ip_max","255.255.255.255"},{"protocol","all"},{"port_min",1},{"port_max",65535}}};
    const auto full = campusCaptureTargets(wide, policy);
    check(full.has_value(),"Wide IPv4 range overflowed");
    auto captured = [&](const QString &address) {
        for (const auto &prefix : full->ipv4Prefixes) {
            const auto subnet = QHostAddress::parseSubnet(prefix);
            check(subnet.second >= 2,"Initial capture synthesized a default route");
            if (QHostAddress(address).isInSubnet(subnet)) return true;
        }
        return false;
    };
    for (const auto *address : {"1.0.0.0","126.255.255.255","128.0.0.0","223.255.255.255","192.168.24.253"})
        check(captured(QString::fromLatin1(address)),"Wide range lost an allowed boundary");
    for (const auto *address : {"0.0.0.0","0.255.255.255","127.0.0.1","127.9.0.1","224.0.0.0","255.255.255.255","192.168.24.252"})
        check(!captured(QString::fromLatin1(address)),"Protected, multicast or reserved address was captured");
    QJsonArray fragmented;
    for (quint32 index=0; index<4096; ++index) fragmented.append(QHostAddress(0x01000000u+index*2).toString()+"/32");
    protectedPolicy = policy;
    protectedPolicy["protected"] = fragmented;
    protectedPolicy["campus"] = QJsonArray{};
    check(!campusCaptureTargets(wide, protectedPolicy),"Fragmented capture plan silently exceeded its output bound");
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    captureTargets();
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
    auto cached = network;
    auto nativeRoutes = cached["routes"].toArray();
    nativeRoutes.append(QJsonObject{{"destination","203.0.113.8/32"},{"cloned",true},{"flags",0x45020007}});
    nativeRoutes.append(QJsonObject{{"destination","203.0.113.9/32"},{"cloned",false}});
    cached["routes"] = nativeRoutes;
    const auto cacheTargets = originalNetworkProtection(cached); check(cacheTargets.has_value(),"Kernel cache annotation rejected a complete snapshot");
    bool protectedCache = false, protectedStatic = false;
    for (const auto &value : *cacheTargets) {
        protectedCache |= value.toObject()["prefix"] == "203.0.113.8/32";
        protectedStatic |= value.toObject()["prefix"] == "203.0.113.9/32";
    }
    check(!protectedCache && protectedStatic && cached["routes"].toArray() == nativeRoutes,"Kernel-derived cache became protection or static/raw routes were discarded");
    nativeRoutes[nativeRoutes.size()-1] = QJsonObject{{"destination","broken"},{"cloned",true}}; cached["routes"] = nativeRoutes;
    check(!originalNetworkProtection(cached),"Cache annotation hid an invalid native destination");
    nativeRoutes[nativeRoutes.size()-1] = QJsonObject{{"destination","203.0.113.9/32"},{"cloned","yes"}}; cached["routes"] = nativeRoutes;
    check(!originalNetworkProtection(cached),"Malformed native cache classification published partial protection");
    const QJsonObject cachedAddress{{"interfaces",QJsonArray{QJsonObject{{"addresses",QJsonArray{"192.0.2.1/24"}}}}},
        {"routes",QJsonArray{QJsonObject{{"destination","10.0.0.1/32"},{"cloned",true}}}}};
    const auto unused = privateTUNAddresses(cachedAddress,{});
    check(unused && unused->first != "10.0.0.1" && unused->second != "10.0.0.1","TUN allocation reused a private address present in a raw kernel cache");
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
    const auto config = protectionConfiguration(*targets, QJsonArray{QJsonObject{
        {"kind", "suffix"}, {"value", "lan.test"}, {"sources", QJsonArray{0}}}});
    check(config["protected"].toArray().contains("192.168.24.0/24")
          && config["protected_names"].toArray() == QJsonArray{QJsonObject{{"kind", "suffix"}, {"value", "lan.test"}}}
          && config["campus"].toArray().isEmpty() && config["campus_names"].toArray().isEmpty(),
          "Core configuration lost native scopes or leaked inspection metadata");
    check(canonicalProtectionName("HOST.Example.TEST.") == QString("host.example.test")
          && canonicalProtectionName(QStringLiteral("bücher.test")) == QString("xn--bcher-kva.test"),
          "Name input lost case, absolute-query or ACE normalization");
    for (const auto &bad : QStringList{"", ".", "*.mesh.test", "192.0.2.10", "::1", " a.test", "a..test", "-a.test", "a.test..", QString(64, 'a')+".test", QString("a")+QChar(0)+".test"})
        check(!canonicalProtectionName(bad), "Invalid concrete name reached policy submission");
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
    auto dnsFacts = QJsonDocument::fromJson(R"({
        "resolv_conf":{"contents":"search obsolete.test\ndomain old.test\nsearch lan.test overlay.test\noptions ndots:5\n"},
        "resolved":{"status":"available","Domains":[
            {"domain":".","route_only":true,"interface_index":0},
            {"domain":"mesh.test","route_only":false,"interface_index":7},
            {"domain":"private.test","route_only":true,"interface_index":7}]},
        "nrpt":[{"Namespace":[".overlay.test","host","host.example.test",".0.10.in-addr.arpa","."]}],
        "clients":[{"ConnectionSpecificSuffix":"lan.test","ConnectionSpecificSuffixSearchList":["other.test"]}],
        "global":{"SuffixSearchList":["global.test"]},
        "dynamic_store":{
            "State:/Network/Service/a/DNS":{"SupplementalMatchDomains":["","mesh.test"],"SearchDomains":["mesh"],"DomainName":"mesh.test","SupplementalMatchDomainsNoSearch":1},
            "Setup:/Network/Service/a/DNS":{"SearchDomains":["configured.test"]}},
        "macos_resolvers":[{"scope":"unscoped","resolver":1,"interface_index":0,"domain":"mesh.test","search":["mesh"]}]
    })").object();
    const auto unchangedDns = dnsFacts;
    const auto namespaces = originalDnsNamespaces(dnsFacts);
    check(namespaces && namespaces->size() == 20 && dnsFacts == unchangedDns,
          "DNS namespace roles, duplicate sources or original native expressions lost");
    bool lastSearch=false, rootRoute=false, searchRoute=false, hostNrpt=false, configured=false, active=false;
    for (const auto &value : *namespaces) {
        const auto item=value.toObject(), source=item["source"].toObject();
        check(item["name"]!="obsolete.test" && item["name"]!="old.test", "Superseded resolver search directive retained");
        if (item["name"]=="lan.test" && source["provider"]=="resolv_conf")
            lastSearch=item["role"]=="search_configuration" && source["line"]==2 && source["item"]==0;
        if (item["name"]=="." && source["provider"]=="resolved") rootRoute=item["role"]=="route";
        if (item["name"]=="mesh.test" && source["provider"]=="resolved")
            searchRoute=item["role"]=="search_route" && source["row"]==1 && source["interface_index"]==7;
        if (item["name"]=="host") hostNrpt=item["role"]=="nrpt" && source["item"]==1;
        if (item["name"]=="configured.test") configured=source["key"]=="Setup:/Network/Service/a/DNS";
        if (item["name"]=="" && source["provider"]=="dynamic_store") active=source["key"]=="State:/Network/Service/a/DNS";
    }
    check(lastSearch && rootRoute && searchRoute && hostNrpt && configured && active,
          "DNS sources conflated search, routing, native NRPT or configured/current store data");
    const auto nameModel=originalDnsProtection(dnsFacts);
    check(nameModel && (*nameModel)["namespaces"].toArray()==*namespaces && dnsFacts==unchangedDns,
          "Name rules changed native facts or lost their source identities");
    const auto nameTargets=(*nameModel)["targets"].toArray();
    auto rule=[&](const QString &kind,const QString &name) {
        for(const auto &value:nameTargets) {
            const auto target=value.toObject();
            if(target["kind"]==kind && target["value"]==name) return target;
        }
        return QJsonObject{};
    };
    check(!rule("prefix","host").isEmpty() && rule("exact","host").isEmpty()
          && !rule("exact","host.example.test").isEmpty() && rule("suffix","host.example.test").isEmpty(),
          "NRPT prefix or FQDN was widened to a different matching scope");
    check(rule("suffix","overlay.test")["sources"].toArray().size()==2
          && !rule("suffix","0.10.in-addr.arpa").isEmpty()
          && rule("suffix",".").isEmpty() && rule("suffix","configured.test").isEmpty(),
          "Repeated sources, reverse scope, root exclusion or inactive Setup semantics changed");
    check(rule("suffix","localhost")["sources"].toArray()==QJsonArray{QJsonObject{{"kind","loopback"}}},
          "Reserved loopback names depend on configured DNS");
    bool explicitSearch=false;
    for(const auto &value:rule("single_label","")["sources"].toArray()) {
        const auto index=value.toObject()["index"].toInt(-1);
        check(index>=0 && index<namespaces->size(),"Name source escaped its original namespace array");
        const auto fact=(*namespaces)[index].toObject();
        check(fact["role"]!="route" && fact["role"]!="match_configuration" && fact["role"]!="domain_configuration",
              "Route-only or NoSearch namespace invented a search scope");
        explicitSearch|=fact["source"].toObject()["provider"]=="macos_resolver";
    }
    check(explicitSearch,"Explicit macOS search domains were suppressed by supplemental NoSearch");
    const QJsonArray effectiveResolvers{
        QJsonObject{{"scope","unscoped"},{"resolver",2},{"interface_index",0},{"domain","static.test"},{"search",QJsonArray{"active.search"}}},
        QJsonObject{{"scope","interface"},{"resolver",1},{"interface_index",7},{"domain","bound.test"},{"search",QJsonArray{"bound.search"}}},
        QJsonObject{{"scope","service"},{"resolver",1},{"interface_index",0},{"domain","service.test"},{"search",QJsonArray{}}}};
    const QJsonObject configuredOnly{{"Setup:/Network/Service/a/DNS",QJsonObject{{"SupplementalMatchDomains",QJsonArray{"static.test","inactive.test"}}}}};
    const auto effectiveProtection=originalDnsProtection({{"dynamic_store",configuredOnly},{"macos_resolvers",effectiveResolvers}});
    check(effectiveProtection.has_value(),"Valid effective macOS query contexts were rejected");
    QSet<QString> effectiveNames;bool effectiveBare=false;
    for(const auto &value:(*effectiveProtection)["targets"].toArray()){
        const auto row=value.toObject();
        if(row["kind"]=="suffix")effectiveNames.insert(row["value"].toString());
        if(row["kind"]=="single_label"){
            effectiveBare=true;
            for(const auto &source:row["sources"].toArray()){
                const auto fact=(*effectiveProtection)["namespaces"].toArray()[source.toObject()["index"].toInt()].toObject();
                check(fact["source"].toObject()["scope"]=="unscoped","Interface-only search settings claimed ordinary bare-name queries");
            }
        }
    }
    check(effectiveNames.contains("static.test") && effectiveNames.contains("active.search") && effectiveBare
        && !effectiveNames.contains("inactive.test") && !effectiveNames.contains("bound.test")
        && !effectiveNames.contains("bound.search") && !effectiveNames.contains("service.test"),
        "Effective Setup routing was lost or inactive/interface/service-only settings claimed ordinary queries");
    auto invalidEffective=effectiveResolvers;auto invalidResolver=invalidEffective[0].toObject();
    invalidResolver["interface_index"]=1.5;invalidEffective[0]=invalidResolver;
    check(!originalDnsProtection({{"macos_resolvers",invalidEffective}}),"Fractional effective source interface published partial name protection");
    invalidResolver["interface_index"]=0;invalidResolver["scope"]="unknown";invalidEffective[0]=invalidResolver;
    check(!originalDnsProtection({{"macos_resolvers",invalidEffective}}),"Unknown native query scope was silently treated as ordinary DNS");
    auto namespaceRules=[](const QJsonArray &names) {
        return originalDnsProtection({{"nrpt",QJsonArray{QJsonObject{{"Namespace",names}}}}});
    };
    const auto canonical=namespaceRules({".MESH.TEST.",QStringLiteral(".b\u00fccher.example"),"only.example.","_service"});
    check(bool(canonical),"Valid case, absolute name, IDNA or underscore namespace rejected");
    bool ace=false, absolute=false, folded=false;
    for(const auto &value:(*canonical)["targets"].toArray()) {
        const auto target=value.toObject();
        ace|=target["value"]=="xn--bcher-kva.example";
        absolute|=target["kind"]=="exact" && target["value"]=="only.example";
        folded|=target["value"]=="mesh.test";
    }
    check(ace && absolute && folded,"Native name normalization lost IDNA, case or absolute FQDN meaning");
    const auto emptySearch=originalDnsProtection({{"global",QJsonObject{{"SuffixSearchList",QJsonArray{""}}}}});
    check(emptySearch && (*emptySearch)["targets"].toArray().size()==1,"Empty search suffix invented a scope for every bare name");
    const QJsonObject rawMac{{"State:/Network/Service/a/DNS",QJsonObject{
        {"SupplementalMatchDomains",QJsonArray{"mesh.test"}},{"SupplementalMatchDomainsNoSearch",0}}}};
    check(!originalDnsProtection({{"dynamic_store",rawMac}}),"Raw macOS inputs were treated as complete effective DNS facts");
    const auto macRules=[&](QString domain,QJsonArray search,QString scope="unscoped") {
        return originalDnsProtection({{"dynamic_store",rawMac},{"macos_resolvers",QJsonArray{QJsonObject{
            {"scope",scope},{"resolver",1},{"interface_index",scope=="interface"?7:0},{"domain",domain},{"search",search}}}}});
    };
    const auto searchable=macRules("mesh.test",{"mesh.test"}),noSearch=macRules("mesh.test",{});
    check(searchable && noSearch && (*searchable)["targets"].toArray().size()==3 && (*noSearch)["targets"].toArray().size()==2,
        "Actual merged search domains were overridden by a raw NoSearch guess");
    for(const auto &scope:QStringList{"interface","service"}) {
        const auto scoped=macRules("mesh.test",{"mesh.test"},scope);
        check(scoped && (*scoped)["targets"].toArray().size()==1,"Interface/service-only DNS became ordinary name or bare-name protection");
    }
    const auto reverse=macRules("0.10.in-addr.arpa",{});
    check(reverse && (*reverse)["targets"].toArray().size()==2,"Reverse routing invented an unreported bare-name search domain");
    const auto implicit=macRules("primary.test",{"primary.test"}),overridden=macRules("primary.test",{});
    check(implicit && overridden && (*implicit)["targets"].toArray().size()==3 && (*overridden)["targets"].toArray().size()==2,
        "An empty effective search list was replaced with a configured domain-name fallback");
    for(const auto &name:QStringList{".bad..test","*.test","127.0.0.1","-bad.test","bad-.test","bad.test.."," bad.test",QStringLiteral(".\u00a0mesh.test"),QStringLiteral("\u6821\u56ed"),QStringLiteral("bad\ufffd.test")})
        check(!namespaceRules({name}),"Unsupported namespace published a partial rule model");
    QJsonArray uniqueNames;
    for(int i=0;i<4095;++i) uniqueNames.append(QStringLiteral(".n%1.test").arg(i));
    const auto boundary=namespaceRules(uniqueNames);
    check(boundary && (*boundary)["targets"].toArray().size()==4096,"Reserved name counted outside the valid rule boundary");
    uniqueNames.append(".overflow.test");
    check(!namespaceRules(uniqueNames),"Normalized name rule capacity silently truncated a complete native snapshot");
    const auto fileSyntax=originalDnsNamespaces({{"resolv_conf",QJsonObject{
        {"contents","search kept.test # literal\n search ignored.test\ndomain \t\n; search ignored.test\n"}}}});
    check(fileSyntax && fileSyntax->size()==3 && fileSyntax->last().toObject()["name"]=="literal",
          "Resolver file syntax invented inline comments, indented directives or an empty override");
    for (const auto &bad : {QJsonObject{{"resolved",QJsonObject{{"status","available"}}}},
                            QJsonObject{{"nrpt",QJsonArray{QJsonObject{{"Namespace","collapsed"}}}}},
                            QJsonObject{{"dynamic_store",QJsonObject{{"State:/Network/Global/DNS",QJsonObject{{"SearchDomains",QJsonArray{7}}}}}}},
                            QJsonObject{{"global",QJsonObject{{"SuffixSearchList",QJsonArray{QString("bad")+QChar::Null+"name"}}}}}})
        check(!originalDnsNamespaces(bad), "Malformed DNS source published partial namespace facts");
    QJsonArray tooMany;
    for (int i=0;i<4096;++i) tooMany.append("same.test");
    dnsFacts={{"nrpt",QJsonArray{QJsonObject{{"Namespace",tooMany}}}}};
    check(originalDnsNamespaces(dnsFacts)->size()==4096,"DNS namespace capacity rejected exact boundary");
    const auto repeated=originalDnsProtection(dnsFacts);
    check(repeated && (*repeated)["targets"].toArray().size()==2,"Duplicate native expressions became duplicate policies");
    for(const auto &value:(*repeated)["targets"].toArray())
        if(value.toObject()["value"]=="same.test")
            check(value.toObject()["sources"].toArray().size()==4096,"Merged name rule dropped independent source references");
    tooMany.append("overflow.test");dnsFacts["nrpt"]=QJsonArray{QJsonObject{{"Namespace",tooMany}}};
    check(!originalDnsNamespaces(dnsFacts),"DNS namespace capacity silently truncated sources");
    check(originalDnsNamespaces({{"resolved",QJsonObject{{"status","unavailable"}}}})->isEmpty(),
          "Unavailable resolved treated as an invented namespace");
    std::cout << "PASS: actual original targets, exit exclusions, native provenance and invalid snapshot rejection\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
