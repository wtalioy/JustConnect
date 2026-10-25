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
#include <QtConcurrent>
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
    QCoreApplication app(argc,argv);QStandardPaths::setTestModeEnabled(true);
    check(argc==5 && QByteArray(argv[1])=="--client" && QByteArray(argv[3])=="network" && qgetenv("GITHUB_ACTIONS")=="true","disposable Windows application fixture only");
    bool valid=false;const auto replyValue=QByteArray(argv[4]).toULongLong(&valid);check(valid && replyValue,"application approval reply pipe");
    const auto reply=reinterpret_cast<HANDLE>(quintptr(replyValue));
    HANDLE token=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token),"ordinary application token");
    TOKEN_ELEVATION elevation{};DWORD bytes=0;
    const auto inspected=GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes);CloseHandle(token);
    check(inspected && !elevation.TokenIsElevated,"Qt, application and Go core remain ordinary");
    QLibrary runtime(QCoreApplication::applicationDirPath()+"/"+QStringLiteral(JC_SHARED_LIBRARY));runtime.setLoadHints(QLibrary::PreventUnloadHint);
    check(runtime.load(),"load the actual embedded Windows core runtime");
    const auto initialDns=dnsSnapshot();const auto initialAddresses=interfaceAddresses();
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
        CloseHandle(reply);WindowsControlFixtureInput input;
        check(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&input,sizeof(input),&count,nullptr) && count==sizeof(input),"approved native process handoff");
        const auto handle=reinterpret_cast<HANDLE>(input.server);QTimer::singleShot(0,&app,[ready,handle]{ready(handle,0);});
    });
    QJsonObject initialProtection;bool coreStarted=false,coreStopped=false,quiesced=false,networkStopped=false,normal=false;int finished=0;
    QObject::connect(access,&NetworkAccess::quiesced,[&](const QUuid &){check(!networkStopped,"capture release precedes final network release");quiesced=true;});
    QObject::connect(access,&NetworkAccess::stopped,[&](const QUuid &,PlatformOperationResult result){
        check(result.succeeded() && (normal?coreStopped:!coreStarted),"final network release follows core shutdown, or no core started after refusal");
        if(normal)networkStopped=true;
    });
    ConnectionSession session(engine,nullptr,access);
    QObject::connect(&session,&ConnectionSession::diagnostic,[](const QString &value){std::cerr<<value.toStdString()<<'\n';});
    QObject::connect(&session,&ConnectionSession::progressChanged,[&]{std::cerr<<"application phase="<<int(session.phase())<<'\n';});
    QObject::connect(&policy,&NetworkPolicySession::changed,[&]{
        std::cerr<<"policy status="<<int(policy.status())<<" busy="<<policy.isBusy()<<" confirmed="<<!policy.confirmedProtection().isEmpty()<<'\n';
    });
    QObject::connect(engine,&CoreEngine::snapshotReady,[](CoreEngine::Snapshot kind,const QString &,const QJsonObject &,CoreEngine::RequestStatus status){
        std::cerr<<"native snapshot kind="<<int(kind)<<" status="<<int(status)<<'\n';
    });
    QObject::connect(engine,&CoreEngine::tunAttached,[](const QString &,CoreEngine::RequestStatus status){std::cerr<<"native pipe attachment="<<int(status)<<'\n';});
    QObject::connect(access,&NetworkAccess::ready,[](const QUuid &,PlatformOperationResult result){std::cerr<<"network ready="<<result.succeeded()<<" "<<result.detail.toStdString()<<'\n';});

    QObject::connect(engine,&CoreEngine::authenticationRequired,[engine](const QJsonObject &request){engine->respond(CoreEngine::responseFor(request,{{"action","submit"},{"code","fixture-code"}}));});
    QObject::connect(engine,&CoreEngine::sessionStarted,[&]{coreStarted=true;});
    QObject::connect(engine,&CoreEngine::initialProtectionApplied,[&](const QJsonObject &value){initialProtection=value;});
    QObject::connect(engine,&CoreEngine::finished,[&](ConnectionError error){check(error==ConnectionError::NONE && quiesced && !networkStopped,"normal core shutdown occurs between capture and device release");coreStopped=true;});
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
    session.stop();until("finish staged network/core restoration",[&]{return finished==3;},20000);
    check(authorizations==3 && approvals==1 && !session.isActive() && interfaceAddresses()==initialAddresses && dnsSnapshot()==initialDns,
        "single approval, owned device removal and complete original DNS/interface restoration");
    std::cout<<"PASS: ordinary Windows application/native helper/Go core system DNS, TCP/UDP and empty datagrams, staged stop and complete restore\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
