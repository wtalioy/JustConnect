#include "infrastructure/routing/originalexit.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *message){if(!value)throw std::runtime_error(message);}
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv);
    const QJsonObject exitInterface{{"index",7},{"name","original"},{"up",true},{"addresses",QJsonArray{"192.168.1.2/24","fe80::1/64"}}};
    const QJsonObject defaultRoute{{"interface_index",7},{"destination","0.0.0.0/0"},{"gateway","192.168.1.1"},{"metric",9}};
    const QJsonObject exitNetwork{{"interfaces",QJsonArray{exitInterface}},{"routes",QJsonArray{defaultRoute}}};
    const auto originalExit=originalExitSnapshot(exitNetwork,"original");
    check(originalExit.has_value(),"Actual selected exit was rejected");
    auto reorderedExit=exitNetwork,reorderedInterface=exitInterface;
    reorderedInterface["addresses"]=QJsonArray{"fe80::1/64","192.168.1.2/24"};reorderedExit["interfaces"]=QJsonArray{reorderedInterface};
    check(originalExitSnapshot(reorderedExit,"original")==originalExit,"Address order invented an exit change");
    auto changedInterface=exitInterface,changedNetwork=exitNetwork;
    auto addresses=changedInterface["addresses"].toArray();addresses.append("192.0.2.1/32");
    changedInterface["addresses"]=addresses;changedNetwork["interfaces"]=QJsonArray{changedInterface};
    check(originalExitSnapshot(changedNetwork,{})!=originalExit,"Actual address addition on the default exit was hidden");
    auto changedRoute=defaultRoute;changedRoute["gateway"]="192.168.1.254";reorderedExit["routes"]=QJsonArray{changedRoute};
    check(originalExitSnapshot(reorderedExit,"original")!=originalExit,"Actual gateway change was hidden");
    check(!originalExitSnapshot(exitNetwork,"missing"),"Missing selected exit was accepted");
    std::cout<<"PASS: standalone platform exit snapshot, stable order, actual gateway and missing-exit rejection\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
