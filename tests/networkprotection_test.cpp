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
    const auto config = protectionConfiguration(*targets, QJsonArray{QJsonObject{
        {"kind", "suffix"}, {"value", "lan.test"}, {"sources", QJsonArray{0}}}});
    check(config["protected"].toArray().contains("192.168.24.0/24")
          && config["protected_names"].toArray() == QJsonArray{QJsonObject{{"kind", "suffix"}, {"value", "lan.test"}}}
          && config["campus"].toArray().isEmpty() && config["campus_names"].toArray().isEmpty(),
          "Core configuration lost native scopes or leaked inspection metadata");
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
            "Setup:/Network/Service/a/DNS":{"SearchDomains":["configured.test"]}}
    })").object();
    const auto unchangedDns = dnsFacts;
    const auto namespaces = originalDnsNamespaces(dnsFacts);
    check(namespaces && namespaces->size() == 18 && dnsFacts == unchangedDns,
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
        explicitSearch|=fact["source"].toObject()["provider"]=="dynamic_store";
    }
    check(explicitSearch,"Explicit macOS search domains were suppressed by supplemental NoSearch");
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
    auto macRules=[](QJsonObject row) {
        return originalDnsProtection({{"dynamic_store",QJsonObject{{"State:/Network/Service/a/DNS",row}}}});
    };
    QJsonObject supplemental{{"SupplementalMatchDomains",QJsonArray{"mesh.test"}}, {"ServerAddresses",QJsonArray{"192.0.2.53"}}};
    const auto searchable=macRules(supplemental);
    check(searchable && (*searchable)["targets"].toArray().size()==3,"Searchable macOS supplemental scope lost bare-name protection");
    supplemental["SupplementalMatchDomainsNoSearch"]=2;
    const auto noSearch=macRules(supplemental);
    check(noSearch && (*noSearch)["targets"].toArray().size()==2,"Nonzero native NoSearch flag became a search domain");
    supplemental["SupplementalMatchDomainsNoSearch"]=true;
    check(!macRules(supplemental),"Boolean masquerading as a native numeric flag was accepted");
    supplemental["SupplementalMatchDomainsNoSearch"]=0;
    for(const auto &options:QStringList{"pdns","interface=utun7"}) {
        supplemental["Options"]=options;
        const auto scoped=macRules(supplemental);
        check(scoped && (*scoped)["targets"].toArray().size()==2,"Private/scoped macOS resolver invented global search");
    }
    supplemental.remove("Options"); supplemental["SupplementalMatchDomains"]=QJsonArray{"0.10.in-addr.arpa"};
    const auto reverse=macRules(supplemental);
    check(reverse && (*reverse)["targets"].toArray().size()==2,"Reverse namespace became a bare-name search domain");
    const QJsonObject primary{{"DomainName","primary.test"}};
    const auto implicit=macRules(primary), overridden=macRules({{"DomainName","primary.test"},{"SearchDomains",QJsonArray{}}});
    check(implicit && overridden && (*implicit)["targets"].toArray().size()==3 && (*overridden)["targets"].toArray().size()==2,
          "Explicit empty search list did not override domain-name fallback");
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
