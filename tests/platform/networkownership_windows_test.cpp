#include "infrastructure/networkhelper/windows/networkownership.h"
#include <QCoreApplication>
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *message){if(!value)throw std::runtime_error(message);}
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv);
    const QJsonObject configuration{{"address","10.222.0.1"},{"peer","10.222.0.2"},
        {"capture_prefixes",QJsonArray{"198.18.0.6/32"}},{"dns_domains",QJsonArray{"campus.test"}}};
    const QJsonObject device{{"index",91},{"name","JustConnect fixture"},{"address",configuration["address"]},{"peer",configuration["peer"]},
        {"guid","{2717939F-2E6F-4F37-A293-8A4F3EDBC3E5}"},{"luid","9100"},{"dns_id","{45B2ED4A-5997-484A-A655-F8A53E311894}"}};
    const QJsonObject lan{{"index",7},{"name","original"},{"up",true},{"addresses",QJsonArray{"192.168.1.2/24"}}};
    const QJsonObject tun{{"index",91},{"name",device["name"]},{"up",true},{"addresses",QJsonArray{"10.222.0.1/32","fe80::1/64"}}};
    const QJsonObject peer{{"interface_index",91},{"destination","10.222.0.2/32"},{"gateway","0.0.0.0"},{"metric",1},{"protocol",3}};
    auto target=peer;target["destination"]="198.18.0.6/32";target["gateway"]=device["peer"];
    auto source=peer;source["destination"]="10.222.0.1/32";source["metric"]=256;source["protocol"]=2;
    const QJsonObject originalRoute{{"interface_index",7},{"destination","192.168.1.0/24"},{"protocol",2}};
    const QJsonObject network{{"interfaces",QJsonArray{lan,tun}},{"routes",QJsonArray{originalRoute,peer,target,source}}};
    const QJsonObject originalPolicy{{"Namespace",QJsonArray{".original.test"}},{"NameServers",QJsonArray{"192.168.1.53"}}};
    const QJsonObject ownedPolicy{{"Namespace",QJsonArray{".campus.test"}},{"NameServers",QJsonArray{"10.222.0.2"}},{"QueryPolicy",""}};
    const QJsonObject originalAdapter{{"InterfaceIndex",7},{"Ipv6IfIndex",7},{"Guid","{3B167A5B-284D-4E65-A202-5DD4B12743E4}"},
        {"Luid","7000"},{"DnsServers",QJsonArray{QJsonObject{{"Address","192.168.1.53"},{"Port",53}}}}};
    const QJsonObject ownedAdapter{{"InterfaceIndex",91},{"Ipv6IfIndex",91},{"Guid",device["guid"]},{"Luid",device["luid"]},
        {"DnsServers",QJsonArray{}},{"Settings",QJsonObject{{"Status",2},{"Value",QJsonValue::Null}}}};
    const QJsonObject originalSource{{"store","local"},{"id","{F370639C-C387-4C4B-AC01-BF4C748A90C2}"},{"class",""},
        {"namespaces",QJsonArray{".original.test"}},{"servers","192.168.1.53"},{"version",1},{"options",8},{"owner",QJsonValue::Null}};
    const QJsonObject ownedSource{{"store","local"},{"id",device["dns_id"]},{"class","JustConnect/{FE849806-C126-44E5-A7CE-738D56C7D7B7}"},
        {"namespaces",QJsonArray{".campus.test"}},{"servers",device["peer"]},{"version",1},{"options",8},{"owner",QJsonValue::Null}};
    const QJsonObject dns{{"nrpt",QJsonArray{originalPolicy,ownedPolicy}},{"interfaces",QJsonArray{}},{"clients",QJsonArray{}},
        {"adapters",QJsonArray{originalAdapter,ownedAdapter}},{"nrpt_sources",QJsonArray{originalSource,ownedSource}}};
    const auto ownership=WindowsNetworkOwnership::capture(configuration,device,network,dns);
    check(ownership.has_value(),"confirmed owned snapshot was rejected");
    const auto filter=ownership->filter(configuration);check(bool(filter),"confirmed capture set was rejected");
    const auto clean=filter(network,dns);check(clean && clean->first["interfaces"]==QJsonArray{lan}
        && clean->first["routes"]==QJsonArray{originalRoute} && clean->second["nrpt"]==QJsonArray{originalPolicy}
        && clean->second["adapters"]==QJsonArray{originalAdapter} && clean->second["nrpt_sources"]==QJsonArray{originalSource},"original network was not restored in the read model");
    auto sourceChange=dns,foreignSource=ownedSource;
    foreignSource["class"]="JustConnect/{ED2C083A-0914-410C-A462-09FEC57B31FA}";
    sourceChange["nrpt_sources"]=QJsonArray{originalSource,foreignSource};
    check(!filter(network,sourceChange),"same-namespace source replacement was hidden as current ownership");
    auto editedOriginal=originalSource;editedOriginal["servers"]="192.168.1.54";
    sourceChange["nrpt_sources"]=QJsonArray{editedOriginal,ownedSource};
    const auto sourceView=filter(network,sourceChange);
    check(sourceView && sourceView->second["nrpt_sources"]==QJsonArray{editedOriginal},"foreign original NRPT source change was hidden");
    auto foreignDns=dns, editedAdapter=ownedAdapter;
    editedAdapter["DnsServers"]=QJsonArray{QJsonObject{{"Address","203.0.113.53"},{"Port",5353}}};
    foreignDns["adapters"]=QJsonArray{originalAdapter,editedAdapter};
    const auto nativeEdit=filter(network,foreignDns);
    check(nativeEdit && nativeEdit->second["adapters"].toArray().contains(editedAdapter),"external native DNS source was hidden");
    editedAdapter=ownedAdapter;editedAdapter["Luid"]="9101";foreignDns["adapters"]=QJsonArray{originalAdapter,editedAdapter};
    check(!WindowsNetworkOwnership::capture(configuration,device,network,foreignDns),"reused interface index acquired native DNS ownership");
    auto changedNetwork=network,changedDns=dns;
    auto changedTun=tun;changedTun["addresses"]=QJsonArray{"10.222.0.1/32","fe80::1/64","203.0.113.8/32"};
    changedNetwork["interfaces"]=QJsonArray{lan,changedTun};
    auto foreign=peer;foreign["destination"]="203.0.113.9/32";foreign["protocol"]=99;
    auto routes=network["routes"].toArray();routes.append(foreign);changedNetwork["routes"]=routes;
    auto editedPolicy=ownedPolicy;editedPolicy["external_option"]=true;changedDns["nrpt"]=QJsonArray{originalPolicy,editedPolicy};
    const auto preserved=filter(changedNetwork,changedDns);
    check(preserved && preserved->first["routes"].toArray().contains(foreign)
        && preserved->first["interfaces"].toArray().last().toObject()["addresses"].toArray()==QJsonArray{"203.0.113.8/32"}
        && preserved->second["nrpt"].toArray().contains(editedPolicy),"external address, route or DNS edit was hidden");
    changedTun=tun;changedTun["external_attribute"]="kept";changedNetwork["interfaces"]=QJsonArray{lan,changedTun};
    const auto attributes=filter(changedNetwork,dns);
    check(attributes && attributes->first["interfaces"].toArray().last().toObject()["external_attribute"]=="kept",
        "external interface attributes were hidden");
    auto editedTarget=target;editedTarget["metric"]=9;changedNetwork["routes"]=QJsonArray{originalRoute,peer,editedTarget,source};
    check(!filter(changedNetwork,dns),"missing or edited capture was treated as active ownership");
    auto onLink=target;onLink["gateway"]="0.0.0.0";changedNetwork["routes"]=QJsonArray{originalRoute,peer,onLink,source};
    check(!filter(changedNetwork,dns),"on-link capture was accepted as a remote campus route");
    auto withPeer=configuration;withPeer["capture_prefixes"]=QJsonArray{"198.18.0.6/32",peer["destination"]};
    const auto peerFilter=ownership->filter(withPeer);check(bool(peerFilter),"explicit peer capture unavailable");
    const auto peerView=peerFilter(network,dns);check(peerView && peerView->first["routes"]==QJsonArray{originalRoute},"peer host route became a gateway to itself");
    auto next=configuration;next["capture_prefixes"]=QJsonArray{"198.18.0.7/32"};auto nextTarget=target;nextTarget["destination"]="198.18.0.7/32";
    changedNetwork["routes"]=QJsonArray{originalRoute,peer,nextTarget,source,target};
    const auto replacement=ownership->filter(next);check(bool(replacement),"new confirmed capture was rejected");
    const auto replaced=replacement(changedNetwork,dns);check(replaced && replaced->first["routes"].toArray().contains(target),"revoked capture was hidden after external reappearance");
    auto merged=configuration;merged["capture_prefixes"]=QJsonArray{"198.18.0.6/31"};
    auto mergedTarget=target;mergedTarget["destination"]="198.18.0.6/31";
    auto broadcast=source;broadcast["destination"]="198.18.0.7/32";
    changedNetwork=network;changedNetwork["routes"]=QJsonArray{originalRoute,peer,source,mergedTarget};
    const auto mergedFilter=ownership->filter(merged);check(bool(mergedFilter),"coalesced capture filter unavailable");
    const auto mergedView=mergedFilter(changedNetwork,dns);
    check(mergedView && mergedView->first["routes"]==QJsonArray{originalRoute},"coalesced remote capture leaked into original protection");
    changedNetwork["routes"]=QJsonArray{originalRoute,peer,source,mergedTarget,broadcast};
    const auto externalView=mergedFilter(changedNetwork,dns);
    check(externalView && externalView->first["routes"].toArray().contains(broadcast),"unowned local host route was hidden by remote capture filtering");
    changedDns["nrpt"]=QJsonArray{originalPolicy};
    check(!WindowsNetworkOwnership::capture(configuration,device,network,changedDns),"ineffective owned DNS acquired a read filter");
    std::cout<<"PASS: original Windows read model, exact captures, DNS coverage and external-value preservation\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
