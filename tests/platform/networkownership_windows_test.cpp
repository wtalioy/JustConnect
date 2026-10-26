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
    const QJsonObject device{{"index",91},{"name","JustConnect fixture"},{"address",configuration["address"]},{"peer",configuration["peer"]}};
    const QJsonObject lan{{"index",7},{"name","original"},{"up",true},{"addresses",QJsonArray{"192.168.1.2/24"}}};
    const QJsonObject tun{{"index",91},{"name",device["name"]},{"up",true},{"addresses",QJsonArray{"10.222.0.1/32","fe80::1/64"}}};
    const QJsonObject peer{{"interface_index",91},{"destination","10.222.0.2/32"},{"gateway","0.0.0.0"},{"metric",1},{"protocol",3}};
    auto target=peer;target["destination"]="198.18.0.6/32";
    auto source=peer;source["destination"]="10.222.0.1/32";source["metric"]=256;source["protocol"]=2;
    const QJsonObject originalRoute{{"interface_index",7},{"destination","192.168.1.0/24"},{"protocol",2}};
    const QJsonObject network{{"interfaces",QJsonArray{lan,tun}},{"routes",QJsonArray{originalRoute,peer,target,source}}};
    const QJsonObject originalPolicy{{"Namespace",QJsonArray{".original.test"}},{"NameServers",QJsonArray{"192.168.1.53"}}};
    const QJsonObject ownedPolicy{{"Namespace",QJsonArray{".campus.test"}},{"NameServers",QJsonArray{"10.222.0.2"}},{"QueryPolicy",""}};
    const QJsonObject dns{{"nrpt",QJsonArray{originalPolicy,ownedPolicy}},{"interfaces",QJsonArray{}},{"clients",QJsonArray{}}};
    const auto ownership=WindowsNetworkOwnership::capture(configuration,device,network,dns);
    check(ownership.has_value(),"confirmed owned snapshot was rejected");
    const auto filter=ownership->filter(configuration);check(bool(filter),"confirmed capture set was rejected");
    const auto clean=filter(network,dns);check(clean && clean->first["interfaces"]==QJsonArray{lan}
        && clean->first["routes"]==QJsonArray{originalRoute} && clean->second["nrpt"]==QJsonArray{originalPolicy},"original network was not restored in the read model");
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
    auto next=configuration;next["capture_prefixes"]=QJsonArray{"198.18.0.7/32"};auto nextTarget=target;nextTarget["destination"]="198.18.0.7/32";
    changedNetwork["routes"]=QJsonArray{originalRoute,peer,nextTarget,source,target};
    const auto replacement=ownership->filter(next);check(bool(replacement),"new confirmed capture was rejected");
    const auto replaced=replacement(changedNetwork,dns);check(replaced && replaced->first["routes"].toArray().contains(target),"revoked capture was hidden after external reappearance");
    auto merged=configuration;merged["capture_prefixes"]=QJsonArray{"198.18.0.6/31"};
    auto mergedTarget=target;mergedTarget["destination"]="198.18.0.6/31";
    auto broadcast=source;broadcast["destination"]="198.18.0.7/32";
    changedNetwork=network;changedNetwork["routes"]=QJsonArray{originalRoute,peer,source,mergedTarget,broadcast};
    const auto mergedFilter=ownership->filter(merged);check(bool(mergedFilter),"coalesced capture filter unavailable");
    const auto mergedView=mergedFilter(changedNetwork,dns);
    check(mergedView && mergedView->first["routes"]==QJsonArray{originalRoute},"new kernel broadcast host route leaked into original protection after capture coalescing");
    for(const auto &field:{"protocol","metric","interface_index"}){
        auto external=broadcast;external[field]=999;
        changedNetwork["routes"]=QJsonArray{originalRoute,peer,source,mergedTarget,external};
        const auto externalView=mergedFilter(changedNetwork,dns);
        check(externalView && externalView->first["routes"].toArray().contains(external),"external broadcast-scope route was hidden");
    }
    changedNetwork["routes"]=QJsonArray{originalRoute,peer,source,target,broadcast};
    const auto withdrawn=filter(changedNetwork,dns);
    check(withdrawn && withdrawn->first["routes"].toArray().contains(broadcast),"broadcast-scope row remained hidden after its owning prefix was withdrawn");
    changedDns["nrpt"]=QJsonArray{originalPolicy};
    check(!WindowsNetworkOwnership::capture(configuration,device,network,changedDns),"ineffective owned DNS acquired a read filter");
    std::cout<<"PASS: original Windows read model, exact captures, DNS coverage and external-value preservation\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
