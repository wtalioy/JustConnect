#include "infrastructure/networkaccess/windows/networkaccess.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "tests/platform/windows_device/controlhandoff.h"
#include "tuntraffic.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QHostInfo>
#include <QJsonDocument>
#include <QLibrary>
#include <QMap>
#include <QNetworkInterface>
#include <QStandardPaths>
#include <QCryptographicHash>
#include <QtConcurrent>
#include <cstring>
#include <iostream>
#include <objbase.h>

using ProxyCheck::check;
template<class Predicate> static void until(const char *stage,Predicate done,int timeout=10000){
    QElapsedTimer timer;timer.start();
    while(!done() && timer.elapsed()<timeout)QCoreApplication::processEvents(QEventLoop::AllEvents,10);
    check(done(),stage);
}
static QJsonObject dnsSnapshot(){
    auto future=QtConcurrent::run(readSystemDnsSnapshot);until("complete native DNS snapshot",[&]{return future.isFinished();});
    const auto result=future.result();check(result.result.succeeded(),"ordinary application reads complete system DNS");
    auto data=result.data;
    for(const auto &key:{"interfaces","clients","nrpt","doh"}){
        QMultiMap<QByteArray,QJsonValue> sorted;
        for(const auto &row:data[key].toArray())sorted.insert(QJsonDocument(row.toObject()).toJson(QJsonDocument::Compact),row);
        QJsonArray rows;for(const auto &row:sorted)rows.append(row);
        data[key]=rows;
    }
    return data;
}
static QStringList interfaceAddresses(){
    QStringList result;
    for(const auto &adapter:QNetworkInterface::allInterfaces())for(const auto &address:adapter.addressEntries())
        result.append(QString::number(adapter.index())+"/"+adapter.name()+"/"+address.ip().toString()+"/"+QString::number(address.prefixLength()));
    result.sort();return result;
}
int main(int argc,char **argv) try
{
    qInstallMessageHandler([](QtMsgType,const QMessageLogContext &,const QString &message){std::cerr<<"qt: "<<message.toStdString()<<'\n';});
    QCoreApplication app(argc,argv);QStandardPaths::setTestModeEnabled(true);
    check((argc==5 || argc==6) && QByteArray(argv[1])=="--client" && QByteArray(argv[3])=="network" && qgetenv("GITHUB_ACTIONS")=="true","disposable Windows application fixture only");
    const auto fault=argc==6?QByteArray(argv[5]):QByteArray{};
    check(fault.isEmpty() || fault=="helper-loss" || fault=="dual-kill","known application fault scenario");
    bool valid=false;const auto replyValue=QByteArray(argv[4]).toULongLong(&valid);check(valid && replyValue,"application approval reply pipe");
    const auto reply=reinterpret_cast<HANDLE>(quintptr(replyValue));
    HANDLE token=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token),"ordinary application token");
    TOKEN_ELEVATION elevation{};DWORD bytes=0;
    const auto inspected=GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes);CloseHandle(token);
    check(inspected && !elevation.TokenIsElevated,"Qt, application and Go core remain ordinary");
    QLibrary runtime(QCoreApplication::applicationDirPath()+"/"+QStringLiteral(JC_SHARED_LIBRARY));runtime.setLoadHints(QLibrary::PreventUnloadHint);
    check(runtime.load(),"load the actual embedded Windows core runtime");
    const auto initialDns=dnsSnapshot();const auto initialAddresses=interfaceAddresses();
    WindowsNetworkFingerprint baseline;
    const auto dnsHash=QCryptographicHash::hash(QJsonDocument(initialDns).toJson(QJsonDocument::Compact),QCryptographicHash::Sha256);
    const auto interfaceHash=QCryptographicHash::hash(initialAddresses.join('\n').toUtf8(),QCryptographicHash::Sha256);
    std::memcpy(baseline.dns.data(),dnsHash.constData(),baseline.dns.size());
    std::memcpy(baseline.interfaces.data(),interfaceHash.constData(),baseline.interfaces.size());
    const auto config=QJsonDocument::fromJson(qgetenv("JC_WINDOWS_SESSION_CONFIG")).object();
    const auto server=config["server"].toObject(),auth=config["auth"].toObject();ConnectionProfile profile;
    profile.endpoint.server=server["host"].toString();profile.endpoint.port=server["port"].toInt();
    profile.endpoint.authType=auth["method"].toString().mid(QStringLiteral("auth/").size());
    profile.endpoint.phone=auth["phone"].toString();profile.endpoint.loginDomain=auth["domain"].toString();
    profile.tls.caPem=config["tls"].toObject()["ca_pem"].toString();profile.keepAlive.mode="off";
    int authorizations=0,approvals=0;
    auto *engine=new EmbeddedCoreEngine;
    NetworkPolicySession policy(engine,readSystemDnsSnapshot);
    const auto mtu=EmbeddedCoreEngine::buildInfo()["capabilities"].toObject()["tunnel_mtu"].toInt();
    auto *access=new WindowsNetworkAccess(engine,&policy,mtu,nullptr,[&](const QUuid &id,auto ready){
        ++authorizations;
        if(authorizations<=2){const DWORD error=authorizations==1?ERROR_ACCESS_DENIED:ERROR_CANCELLED;QTimer::singleShot(0,&app,[ready,error]{ready(nullptr,error);});return;}
        check(++approvals==1,"one approved process per application connection");
        GUID requested{};const auto text=id.toString(QUuid::WithBraces);DWORD count=0;
        check(SUCCEEDED(CLSIDFromString(reinterpret_cast<LPCOLESTR>(text.utf16()),&requested))
            && WriteFile(reply,&requested,sizeof(requested),&count,nullptr) && count==sizeof(requested),"actual application UUID reaches the approval fixture");
        if(fault.isEmpty())CloseHandle(reply);WindowsControlFixtureInput input;
        check(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&input,sizeof(input),&count,nullptr) && count==sizeof(input),"approved native process handoff");
        check(!input.hasBaseline || (input.baseline.dns==baseline.dns && input.baseline.interfaces==baseline.interfaces),"new ordinary application confirms complete pre-crash DNS and interface baseline");
        const auto handle=reinterpret_cast<HANDLE>(input.server);QTimer::singleShot(0,&app,[ready,handle]{ready(handle,0);});
    });
    QJsonObject initialProtection;bool coreStarted=false,coreStopped=false,quiesced=false,networkStopped=false,normal=false,recoveryBlocked=false;int finished=0;
    QObject::connect(access,&NetworkAccess::quiesced,[&](const QUuid &){check(!networkStopped,"capture release precedes final network release");quiesced=true;});
    QObject::connect(access,&NetworkAccess::stopped,[&](const QUuid &,PlatformOperationResult result){
        if(normal && !fault.isEmpty()){check(!result.succeeded(),"lost helper cannot confirm an owned release");recoveryBlocked=true;return;}
        check(result.succeeded() && (normal?coreStopped:!coreStarted),"final network release follows core shutdown, or no core started after refusal");
        if(normal)networkStopped=true;
    });
    ConnectionSession session(engine,nullptr,access);
    QObject::connect(&session,&ConnectionSession::diagnostic,[](const QString &value){std::cerr<<value.toStdString()<<'\n';});
    QObject::connect(&session,&ConnectionSession::progressChanged,[&]{std::cerr<<"application phase="<<int(session.phase())<<'\n';});
    QObject::connect(access,&NetworkAccess::ready,[](const QUuid &,PlatformOperationResult result){std::cerr<<"network ready="<<result.succeeded()<<" "<<result.detail.toStdString()<<'\n';});

    QObject::connect(engine,&CoreEngine::authenticationRequired,[engine](const QJsonObject &request){engine->respond(CoreEngine::responseFor(request,{{"action","submit"},{"code","fixture-code"}}));});
    QObject::connect(engine,&CoreEngine::sessionStarted,[&]{coreStarted=true;});
    QObject::connect(engine,&CoreEngine::initialProtectionApplied,[&](const QJsonObject &value){initialProtection=value;});
    QObject::connect(engine,&CoreEngine::finished,[&](ConnectionError error){
        if(fault.isEmpty())check(error==ConnectionError::NONE && quiesced && !networkStopped,"normal core shutdown occurs between capture and device release");
        else check(!networkStopped,"helper loss does not report a final network release");
        coreStopped=true;
    });
    QObject::connect(&session,&ConnectionSession::finished,[&](ConnectionError error){
        if(!normal)check(error==(finished==0?ConnectionError::PERMISSION_DENIED:ConnectionError::NONE) && !coreStarted,"refused/cancelled authorization terminates without starting the core");
        else check(error==ConnectionError::NONE && networkStopped,"application confirms every owned release before finishing");
        ++finished;
    });
    for(int prefix=1;prefix<=2;++prefix){
        check(session.start(profile,{}),"start explicit refusal/cancellation attempt");until("finish refused or cancelled authorization",[&]{return finished==prefix;});
        check(authorizations==prefix && !session.isActive() && !coreStarted,"permission refusal never loops authorization or starts the core");
    }
    normal=true;
    check(session.start(profile,{}),"start complete Windows application connection");
    until("reach CampusReady after native attachment",[&]{return session.state()==ConnectionState::Running || finished>2;},20000);
    check(finished==2 && session.phase()==ConnectionPhase::CampusReady,"application reports campus readiness only after authorized device attachment");
    until("finish original-network policy observation",[&]{return !policy.isBusy();});
    check(policy.status()==CoreEngine::RequestStatus::Success && policy.confirmedProtection()["protected"]==initialProtection["protected"]
        && policy.confirmedProtection()["protected_names"]==initialProtection["protected_names"],"owned routes/DNS never become original protection");
    auto lookup=QtConcurrent::run([]{return QHostInfo::fromName("campus.test");});until("complete system campus DNS lookup",[&]{return lookup.isFinished();});
    const auto answer=lookup.result();check(answer.error()==QHostInfo::NoError && answer.addresses().contains(QHostAddress("198.18.0.7")),"ordinary Windows system DNS follows campus CNAME through the actual core");
    exerciseNativeTUNTraffic(QHostAddress("198.18.0.7"));
    until("finish original-network policy observation",[&]{return !policy.isBusy();});check(policy.refresh(),"refresh original view after DNS capture publication");until("finish original-network policy observation",[&]{return !policy.isBusy();});
    check(policy.status()==CoreEngine::RequestStatus::Success && policy.confirmedProtection()["protected"]==initialProtection["protected"],"new DNS captures remain excluded from original protection");
    exerciseNativeTUNTraffic(QHostAddress("198.18.0.7"));
    if(!fault.isEmpty()){
        DWORD count=0;
        check(WriteFile(reply,&baseline,sizeof(baseline),&count,nullptr) && count==sizeof(baseline),"real traffic checkpoint reaches root fixture");CloseHandle(reply);
        if(fault=="dual-kill")until("root fixture kills the live Qt/core process",[]{return false;},20000);
        until("helper loss stops the actual core and retains recovery responsibility",[&]{return coreStopped && recoveryBlocked;},20000);
        check(finished==2 && session.isActive() && !session.start(profile,{}) && authorizations==3,"pending recovery blocks a new connection and repeated authorization");
        unsigned char restored=0;
        check(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&restored,1,&count,nullptr) && count==1 && restored==1,"independent service confirms its durable recovery receipt");
        check(interfaceAddresses()==initialAddresses && dnsSnapshot()==initialDns,"independent service restores complete DNS and interfaces while the application remains alive");
        std::cout<<"PASS: helper loss stops core, blocks new authorization and preserves responsibility through independent restoration\n";return 0;
    }
    session.stop();until("finish staged network/core restoration",[&]{return finished==3;},20000);
    check(authorizations==3 && approvals==1 && !session.isActive() && interfaceAddresses()==initialAddresses && dnsSnapshot()==initialDns,
        "single approval, owned device removal and complete original DNS/interface restoration");
    std::cout<<"PASS: ordinary Windows application/native helper/Go core system DNS, TCP/UDP and empty datagrams, staged stop and complete restore\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
