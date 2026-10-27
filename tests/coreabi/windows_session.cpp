#include <winsock2.h>
#include <ws2tcpip.h>
#include "infrastructure/networkaccess/windows/networkaccess.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/routing/originalexit.h"
#include "tests/platform/windows_device/controlhandoff.h"
#include "tests/platform/networksnapshotcheck.h"
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
#include <QSet>
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
static bool sameNetwork(const QJsonObject &beforeDns,const QJsonObject &afterDns,
    const QStringList &beforeAddresses,const QStringList &afterAddresses){
    if(beforeDns==afterDns && beforeAddresses==afterAddresses)return true;
    QJsonObject difference{{"dns",NetworkSnapshotCheck::difference(beforeDns,afterDns)}};
    if(beforeAddresses!=afterAddresses)difference["interfaces"]=QJsonObject{
        {"before",QJsonArray::fromStringList(beforeAddresses)},{"after",QJsonArray::fromStringList(afterAddresses)}};
    std::cerr<<"network_restoration_difference="<<QJsonDocument(difference).toJson(QJsonDocument::Compact).constData()<<'\n';
    return false;
}
int main(int argc,char **argv) try
{
    qInstallMessageHandler([](QtMsgType,const QMessageLogContext &,const QString &message){std::cerr<<"qt: "<<message.toStdString()<<'\n';});
    QCoreApplication app(argc,argv);QStandardPaths::setTestModeEnabled(true);
    WSADATA sockets{};check(WSAStartup(MAKEWORD(2,2),&sockets)==0,"start ordinary system DNS sockets");
    struct SocketCleanup {~SocketCleanup(){WSACleanup();}} socketCleanup;
    check((argc==5 || argc==6) && QByteArray(argv[1])=="--client" && QByteArray(argv[3])=="network" && qgetenv("GITHUB_ACTIONS")=="true","disposable Windows application fixture only");
    const auto fault=argc==6?QByteArray(argv[5]):QByteArray{};
    const bool policyChanges=qgetenv("JC_WINDOWS_SESSION_POLICY")=="true";
    const bool exitChange=qgetenv("JC_WINDOWS_SESSION_EXIT_CHANGE")=="true";
    check(!policyChanges || fault.isEmpty(),"policy changes use normal ownership restoration");
    check(!exitChange || (!policyChanges && fault.isEmpty()),"exit change has its own ordinary two-session scenario");
    check(fault.isEmpty() || fault=="helper-loss" || fault=="dual-kill","known application fault scenario");
    bool valid=false;const auto replyValue=QByteArray(argv[4]).toULongLong(&valid);check(valid && replyValue,"application approval reply pipe");
    const auto reply=reinterpret_cast<HANDLE>(quintptr(replyValue));
    HANDLE token=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token),"ordinary application token");
    TOKEN_ELEVATION elevation{};DWORD bytes=0;
    const auto inspected=GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes);CloseHandle(token);
    check(inspected && !elevation.TokenIsElevated,"Qt, application and Go core remain ordinary");
    QLibrary runtime(QCoreApplication::applicationDirPath()+"/"+QStringLiteral(JC_SHARED_LIBRARY));runtime.setLoadHints(QLibrary::PreventUnloadHint);
    check(runtime.load(),"load the actual embedded Windows core runtime");
    const bool originalDNS=!qgetenv("JC_WINDOWS_SESSION_ORIGINAL_DNS_SERVER").isEmpty();
    const auto queryOriginal=[&](const QString &expected){
        auto lookup=QtConcurrent::run([]{
            ADDRINFOW hints{};hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;ADDRINFOW *addresses=nullptr;
            QStringList result;
            if(GetAddrInfoW(L"host.campus.test",nullptr,&hints,&addresses)==0){
                for(auto item=addresses;item;item=item->ai_next)
                    result.append(QHostAddress(ntohl(reinterpret_cast<sockaddr_in *>(item->ai_addr)->sin_addr.s_addr)).toString());
                FreeAddrInfoW(addresses);
            }
            return result;
        });
        until("ordinary protected-name lookup",[&]{return lookup.isFinished();});
        check(lookup.result().contains(expected),"original/campus name choice follows its confirmed source");
    };
    if(originalDNS)queryOriginal("203.0.113.9"); // Prewarm the actual Windows DNS cache before connection.
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
        check(++approvals<=(exitChange?2:1),"one approved process per application connection");
        GUID requested{};const auto text=id.toString(QUuid::WithBraces);DWORD count=0;
        check(SUCCEEDED(CLSIDFromString(reinterpret_cast<LPCOLESTR>(text.utf16()),&requested))
            && WriteFile(reply,&requested,sizeof(requested),&count,nullptr) && count==sizeof(requested),"actual application UUID reaches the approval fixture");
        if(fault.isEmpty() && !exitChange)CloseHandle(reply);WindowsControlFixtureInput input;
        check(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&input,sizeof(input),&count,nullptr) && count==sizeof(input),"approved native process handoff");
        check(!input.hasBaseline || (input.baseline.dns==baseline.dns && input.baseline.interfaces==baseline.interfaces),"new ordinary application confirms complete pre-crash DNS and interface baseline");
        const auto handle=reinterpret_cast<HANDLE>(input.server);QTimer::singleShot(0,&app,[ready,handle]{ready(handle,0);});
    });
    QJsonObject initialProtection;bool coreStarted=false,coreStopped=false,quiesced=false,networkStopped=false,normal=false,recoveryBlocked=false;int finished=0,coreFinishes=0;
    QObject::connect(access,&NetworkAccess::quiesced,[&](const QUuid &){check(!networkStopped,"capture release precedes final network release");quiesced=true;});
    QObject::connect(access,&NetworkAccess::stopped,[&](const QUuid &,PlatformOperationResult result){
        std::cerr<<"network stopped status="<<int(result.status)<<" changed="<<result.mayHaveChanged
            <<" core_started="<<coreStarted<<" core_stopped="<<coreStopped<<" quiesced="<<quiesced
            <<" normal="<<normal<<" fault="<<fault.constData()<<" detail="<<result.detail.toStdString()<<'\n';
        if(normal && !fault.isEmpty()){check(!result.succeeded(),"lost helper cannot confirm an owned release");recoveryBlocked=true;return;}
        check(result.succeeded() && (normal?coreStopped:!coreStarted),"final network release follows core shutdown, or no core started after refusal");
        if(normal)networkStopped=true;
    });
    ConnectionSession session(engine,nullptr,access);
    QObject::connect(&session,&ConnectionSession::diagnostic,[](const QString &value){std::cerr<<value.toStdString()<<'\n';});
    QObject::connect(&session,&ConnectionSession::progressChanged,[&]{std::cerr<<"application phase="<<int(session.phase())<<'\n';});
    QObject::connect(access,&NetworkAccess::ready,[](const QUuid &,PlatformOperationResult result){std::cerr<<"network ready="<<result.succeeded()<<" "<<result.detail.toStdString()<<'\n';});

    QObject::connect(engine,&CoreEngine::authenticationRequired,[engine](const QJsonObject &request){engine->respond(CoreEngine::responseFor(request,{{"action","submit"},{"code","fixture-code"}}));});
    QObject::connect(engine,&CoreEngine::sessionStarted,[&]{
        if(exitChange && coreStopped)coreStopped=quiesced=networkStopped=false;
        coreStarted=true;
    });
    QObject::connect(engine,&CoreEngine::initialProtectionApplied,[&](const QJsonObject &value){initialProtection=value;});
    QObject::connect(engine,&CoreEngine::finished,[&](ConnectionError error){
        if(fault.isEmpty())check(error==ConnectionError::NONE && quiesced && !networkStopped,"normal core shutdown occurs between capture and device release");
        else check(!networkStopped,"helper loss does not report a final network release");
        coreStopped=true;++coreFinishes;
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
    check(session.start(profile,{exitChange,1000}),"start complete Windows application connection");
    until("reach CampusReady after native attachment",[&]{return session.state()==ConnectionState::Running || finished>2;},20000);
    check(finished==2 && session.phase()==ConnectionPhase::CampusReady,"application reports campus readiness only after authorized device attachment");
    const auto traffic=[&]{
        until("finish original-network policy observation",[&]{return !policy.isBusy();});
        check(policy.status()==CoreEngine::RequestStatus::Success && policy.confirmedProtection()["protected"]==initialProtection["protected"]
            && policy.confirmedProtection()["protected_names"]==initialProtection["protected_names"],"owned routes/DNS never become original protection");
        const auto chooseCampus=[&](bool campus){
            for(const auto *address:{"198.18.0.6","198.18.0.7"}){
                check(policy.setCampusAddress(QString::fromLatin1(address),campus),"choose each overlapping TCP/UDP target");
                until("confirm core and helper target policy",[&]{return !policy.isBusy();});
                check(policy.policyStatus()==CoreEngine::RequestStatus::Success,"core and native helper confirm the target choice");
            }
        };
        if(policyChanges){
            check(policy.campusAddresses().isEmpty(),"overlapping targets default to their original network");
            exerciseOriginalNetworkTraffic();
            chooseCampus(true);
        }
        auto lookup=QtConcurrent::run([]{return QHostInfo::fromName("campus.test");});until("complete system campus DNS lookup",[&]{return lookup.isFinished();});
        const auto answer=lookup.result();check(answer.error()==QHostInfo::NoError && answer.addresses().contains(QHostAddress("198.18.0.7")),"ordinary Windows system DNS follows campus CNAME through the actual core");
        exerciseNativeTUNTraffic(QHostAddress("198.18.0.7"));
        exerciseNativeSSH(QHostAddress("198.18.0.7"));
        if(policyChanges)exerciseNonCampusNetworkTraffic();
        until("finish original-network policy observation",[&]{return !policy.isBusy();});check(policy.refresh(),"refresh original view after DNS capture publication");until("finish original-network policy observation",[&]{return !policy.isBusy();});
        check(policy.status()==CoreEngine::RequestStatus::Success && policy.confirmedProtection()["protected"]==initialProtection["protected"],"new DNS captures remain excluded from original protection");
        exerciseNativeTUNTraffic(QHostAddress("198.18.0.7"));
        if(policyChanges){
            const auto generation=policy.currentGeneration();
            chooseCampus(false);
            check(policy.campusAddresses().isEmpty() && session.state()==ConnectionState::Running && policy.currentGeneration()==generation,
                "returning to the original network preserves the authenticated session");
            exerciseOriginalNetworkTraffic();
        }
    };
    traffic();
    if(originalDNS){
        queryOriginal("203.0.113.9");
        for(const bool campus:{true,false}){
            check(policy.setCampusName("host.campus.test",campus),"choose the overlapping original DNS name");
            until("confirm original-name policy",[&]{return !policy.isBusy();});
            check(policy.policyStatus()==CoreEngine::RequestStatus::Success,"core and helper confirm the name choice");
            queryOriginal(campus?"198.18.0.7":"203.0.113.9");
        }
    }
    WindowsExitChangeFixtureInput changed;
    if(exitChange){
        const auto previousGeneration=policy.currentGeneration();const auto model=policy.model();
        const auto exit=originalExitSnapshot(model["network"].toObject(),{});
        check(exit.has_value(),"complete original exit snapshot before address change");
        QSet<int> indexes;
        for(const auto &value:(*exit)["routes"].toArray()){
            const auto route=value.toObject();if(route["destination"]=="0.0.0.0/0")indexes.insert(route["interface_index"].toInt());
        }
        check(indexes.size()==1 && *indexes.begin()>0,"one actual IPv4 default interface for the exit change");
        changed.interfaceIndex=quint32(*indexes.begin());
        const auto barrier=QObject::connect(&session,&ConnectionSession::reconnectScheduled,&session,[&](int){
            check(finished==2 && coreStopped && networkStopped && session.state()==ConnectionState::Reconnecting,
                "changed exit restores the old helper and core before scheduling reconnect");
            DWORD count=0;
            check(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&changed,sizeof(changed),&count,nullptr) && count==sizeof(changed) && changed.address,
                "native observer confirms old ownership release and the external exit alias");
        });
        DWORD count=0;
        check(WriteFile(reply,&changed,sizeof(changed),&count,nullptr) && count==sizeof(changed),"actual default interface reaches the external change observer");
        until("automatic reconnect after original exit address change",[&]{return (session.state()==ConnectionState::Running && coreFinishes==1) || finished>2;},20000);
        QObject::disconnect(barrier);
        check(finished==2 && session.phase()==ConnectionPhase::CampusReady && session.reconnectAttempt()==1
            && policy.currentGeneration()!=previousGeneration,"changed exit reconnects once with a fresh generation");
        until("complete changed original-network policy view",[&]{return !policy.isBusy();});
        bool adopted=false;
        for(const auto &value:policy.model()["network"].toObject()["interfaces"].toArray()){
            const auto row=value.toObject();if(row["index"].toInt()!=int(changed.interfaceIndex))continue;
            adopted=row["addresses"].toArray().contains(QHostAddress(changed.address).toString()+"/32");
        }
        check(adopted,"fresh connection adopts the actual external exit address");
        traffic();
    }
    if(!fault.isEmpty()){
        DWORD count=0;
        check(WriteFile(reply,&baseline,sizeof(baseline),&count,nullptr) && count==sizeof(baseline),"real traffic checkpoint reaches root fixture");CloseHandle(reply);
        if(fault=="dual-kill")until("root fixture kills the live Qt/core process",[]{return false;},20000);
        until("helper loss stops the actual core and retains recovery responsibility",[&]{return coreStopped && recoveryBlocked;},20000);
        check(finished==2 && session.isActive() && !session.start(profile,{}) && authorizations==3,"pending recovery blocks a new connection and repeated authorization");
        unsigned char restored=0;
        check(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&restored,1,&count,nullptr) && count==1 && restored==1,"independent service confirms its durable recovery receipt");
        check(sameNetwork(initialDns,dnsSnapshot(),initialAddresses,interfaceAddresses()),"independent service restores complete DNS and interfaces while the application remains alive");
        std::cout<<"PASS: helper loss stops core, blocks new authorization and preserves responsibility through independent restoration\n";return 0;
    }
    session.stop();until("finish staged network/core restoration",[&]{return finished==3;},20000);
    if(exitChange){
        unsigned char complete=1;DWORD count=0;
        check(coreFinishes==2 && WriteFile(reply,&complete,1,&count,nullptr) && count==1,"both real cores and owned network generations finish before fixture cleanup");CloseHandle(reply);
        check(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&complete,1,&count,nullptr) && count==1 && complete==1,"external observer removes only its own exit alias after network restoration");
    }
    const auto restored=sameNetwork(initialDns,dnsSnapshot(),initialAddresses,interfaceAddresses());
    check(authorizations==(exitChange?4:3) && approvals==(exitChange?2:1) && !session.isActive() && restored,
        "single approval, owned device removal and complete original DNS/interface restoration");
    if(originalDNS){queryOriginal("203.0.113.9");std::cout<<"PASS: prewarmed Windows original NRPT source, automatic listener, name choice/withdrawal and exact restoration\n";}
    if(exitChange)std::cout<<"PASS: changed Windows original exit restores before automatic reconnect, fresh generation, system DNS/TCP/UDP/SSH and complete final restoration\n";
    if(policyChanges)std::cout<<"PASS: Windows same-IP original/campus/original TCP, UDP and empty datagrams without reauthentication\n";
    std::cout<<"PASS: ordinary Windows application/native helper/Go core system DNS, TCP/UDP and empty datagrams, staged stop and complete restore\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
