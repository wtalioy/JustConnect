#include "infrastructure/networkhelper/windows/networkhelperclient.h"
#include "controlhandoff.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QTimer>
#include <QThread>
#include <QJsonObject>
#include <iostream>
#include <objbase.h>
#include <cstdint>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <thread>
#include <vector>
#include <atomic>
#include <cstring>
#include <system_error>

namespace {
void check(bool value,const char *stage){if(!value)throw std::runtime_error(stage);}
using Input=WindowsControlFixtureInput;
QUuid uuid(const GUID &id){wchar_t value[39]{};check(StringFromGUID2(id,value,39)!=0,"Qt test ownership UUID");return QUuid(QString::fromWCharArray(value));}
bool contains(const QJsonArray &owners,const QUuid &id){for(const auto &item:owners)if(QUuid(item.toObject()["owner"].toString())==id)return true;return false;}

void transfer(HANDLE pipe,void *data,DWORD size,bool write){
    const auto event=CreateEventW(nullptr,TRUE,FALSE,nullptr);check(event,"packet pump event");
    struct Close{HANDLE event;~Close(){CloseHandle(event);}} close{event};
    auto *bytes=static_cast<unsigned char *>(data);
    while(size){
        OVERLAPPED operation{};operation.hEvent=event;ResetEvent(event);DWORD count=0;
        const auto started=write?WriteFile(pipe,bytes,size,&count,&operation):ReadFile(pipe,bytes,size,&count,&operation);
        if(!started){const auto code=GetLastError();if(code!=ERROR_IO_PENDING)throw std::system_error(code,std::system_category());
            if(WaitForSingleObject(event,15000)!=WAIT_OBJECT_0){CancelIoEx(pipe,&operation);GetOverlappedResult(pipe,&operation,&count,TRUE);throw std::runtime_error("packet pump deadline");}
            if(!GetOverlappedResult(pipe,&operation,&count,FALSE))throw std::system_error(GetLastError(),std::system_category());}
        check(count>0,"empty packet pump transfer");bytes+=count;size-=count;
    }
}
void ping(const char *target){
    const auto socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);check(socket!=INVALID_SOCKET,"ordinary UDP socket");
    struct Close{SOCKET socket;~Close(){closesocket(socket);}} close{socket};
    sockaddr_in local{};local.sin_family=AF_INET;InetPtonA(AF_INET,"198.18.0.1",&local.sin_addr);
    check(bind(socket,reinterpret_cast<sockaddr *>(&local),sizeof(local))==0,"ordinary UDP source");
    sockaddr_in peer{};peer.sin_family=AF_INET;peer.sin_port=htons(43877);InetPtonA(AF_INET,target,&peer.sin_addr);
    DWORD timeout=5000;setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char *>(&timeout),sizeof(timeout));
    check(connect(socket,reinterpret_cast<sockaddr *>(&peer),sizeof(peer))==0 && send(socket,"ping",4,0)==4,"ordinary UDP request");
    char answer[8]{};check(recv(socket,answer,sizeof(answer),0)==4 && std::string(answer,4)=="pong","ordinary UDP response through owned device");
}
bool captured(const QJsonObject &device,const wchar_t *target,UCHAR bits=32){
    MIB_IPFORWARD_ROW2 route{};InitializeIpForwardEntry(&route);
    route.InterfaceLuid.Value=device["luid"].toString().toULongLong();route.DestinationPrefix.Prefix.si_family=AF_INET;
    InetPtonW(AF_INET,target,&route.DestinationPrefix.Prefix.Ipv4.sin_addr);route.DestinationPrefix.PrefixLength=bits;route.NextHop.si_family=AF_INET;
    const auto peer=device["peer"].toString();check(InetPtonW(AF_INET,reinterpret_cast<LPCWSTR>(peer.utf16()),&route.NextHop.Ipv4.sin_addr)==1,"confirmed capture gateway");
    const auto status=GetIpForwardEntry2(&route);
    check(status==NO_ERROR || status==ERROR_NOT_FOUND || status==ERROR_FILE_NOT_FOUND,"query actual owned route");return status==NO_ERROR;
}
bool dnsPresent(const QJsonObject &device){
    const auto path=QStringLiteral("SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig\\")+device["dns_id"].toString();
    HKEY key=nullptr;const auto status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,reinterpret_cast<LPCWSTR>(path.utf16()),0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key);
    if(key)RegCloseKey(key);check(status==ERROR_SUCCESS || status==ERROR_FILE_NOT_FOUND,"query owned DNS policy");return status==ERROR_SUCCESS;
}
}

int main(int argc,char **argv) try
{
    QCoreApplication application(argc,argv);
    const auto args=application.arguments();check(args.size()==4 && args[1]=="--client","Qt control fixture arguments");
    Input input;DWORD size=0;
    check(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&input,sizeof(input),&size,nullptr) && size==sizeof(input),"actual Qt approved process handoff");
    HANDLE token=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token),"Qt control process token");
    TOKEN_ELEVATION elevation{};DWORD bytes=0;
    const auto queried=GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes);CloseHandle(token);
    check(queried && !elevation.TokenIsElevated,"Qt control process must stay ordinary");
    const QUuid session(args[2]);check(!session.isNull(),"actual Qt control session");
    auto approved=reinterpret_cast<HANDLE>(input.server);
    int authorizations=0;
    WindowsNetworkHelperClient client(nullptr,[&](const QUuid &id,auto ready){
        ++authorizations;check(id==session && approved,"Qt authorization changed connection identity");
        const auto handle=approved;approved=nullptr;QTimer::singleShot(0,&application,[ready,handle]{ready(handle,0);});
    });
    QEventLoop loop;
    PlatformOperationResult result;WindowsNetworkHelperClient::Operation completed{};bool finished=false;
    QObject::connect(&client,&WindowsNetworkHelperClient::finished,&application,[&](auto operation,auto value){
        check(QThread::currentThread()==application.thread(),"Qt result escaped the GUI thread");
        completed=operation;result=value;finished=true;loop.quit();
    });
    QTimer deadline;deadline.setSingleShot(true);
    QObject::connect(&deadline,&QTimer::timeout,&loop,&QEventLoop::quit);
    auto wait=[&](auto operation){deadline.start(15000);if(!finished)loop.exec();deadline.stop();check(finished && completed==operation,"Qt control operation deadline");finished=false;check(result.succeeded(),"Qt native control operation failed");};
    client.inspect(session);wait(WindowsNetworkHelperClient::Operation::Inspect);
    if(args[3]=="network"){
        WSADATA sockets{};check(WSAStartup(MAKEWORD(2,2),&sockets)==0,"ordinary network fixture sockets");
        struct CleanupSockets{~CleanupSockets(){WSACleanup();}} cleanupSockets;
        const QJsonObject configuration{{"address","198.18.0.1"},{"peer","198.18.0.2"},{"mtu",1400},
            {"capture_prefixes",QJsonArray{"198.18.0.6/32"}},{"dns_domains",QJsonArray{session.toString(QUuid::WithoutBraces)+".invalid"}}};
        client.apply(configuration);wait(WindowsNetworkHelperClient::Operation::Apply);
        const auto device=client.ownedDevice();
        check(client.state()==WindowsNetworkHelperClient::State::Active && client.packetPipeHandle() && client.helperPID(),"actual network attachment metadata");
        check(captured(device,L"198.18.0.6") && dnsPresent(device),"actual capture and DNS not active");
        HANDLE data=nullptr;check(DuplicateHandle(GetCurrentProcess(),reinterpret_cast<HANDLE>(quintptr(client.packetPipeHandle())),GetCurrentProcess(),&data,0,FALSE,DUPLICATE_SAME_ACCESS),"ordinary core packet pipe duplicate");
        std::exception_ptr error;std::atomic<int> packets=0;
        std::jthread pump([&]{try{while(packets<3){
            unsigned char length[4]{};transfer(data,length,4,false);
            const DWORD size=(DWORD(length[0])<<24)|(DWORD(length[1])<<16)|(DWORD(length[2])<<8)|length[3];
            check(size>=20 && size<=1400,"bounded IPv4 packet frame");std::vector<unsigned char> packet(size);transfer(data,packet.data(),size,false);
            if(size!=32 || packet[0]!=0x45 || packet[9]!=17 || ((packet[22]<<8)|packet[23])!=43877)continue;
            check(std::string(reinterpret_cast<char *>(packet.data()+28),4)=="ping","actual UDP request frame");
            for(int offset=0;offset<4;++offset)std::swap(packet[12+offset],packet[16+offset]);
            std::swap(packet[20],packet[22]);std::swap(packet[21],packet[23]);packet[26]=packet[27]=0;
            std::memcpy(packet.data()+28,"pong",4);packet[10]=packet[11]=0;
            unsigned int sum=0;for(int offset=0;offset<20;offset+=2)sum+=(packet[offset]<<8)|packet[offset+1];while(sum>65535)sum=(sum&65535)+(sum>>16);
            const auto checksum=static_cast<unsigned short>(~sum);packet[10]=static_cast<unsigned char>(checksum>>8);packet[11]=static_cast<unsigned char>(checksum);
            transfer(data,length,4,true);transfer(data,packet.data(),size,true);++packets;
        }}catch(...){error=std::current_exception();}});
        ping("198.18.0.6");
        client.extend({"198.18.0.7"});wait(WindowsNetworkHelperClient::Operation::Extend);
        check(client.ownedConfiguration()["capture_prefixes"].toArray()==QJsonArray{"198.18.0.6/32","198.18.0.7/32"},"confirmed extension was not retained by the ordinary client");
        check(captured(device,L"198.18.0.7"),"dynamic capture was not confirmed");ping("198.18.0.7");
        client.reconcile({"198.18.0.6/31"});wait(WindowsNetworkHelperClient::Operation::Routes);
        check(captured(device,L"198.18.0.6",31) && !captured(device,L"198.18.0.6") && !captured(device,L"198.18.0.7"),"remote capture coalescing left host routes");
        ping("198.18.0.7");
        pump.join();CloseHandle(data);if(error)std::rethrow_exception(error);check(packets==3,"owned data path omitted a packet");
        client.reconcile({"198.18.0.7/32"});wait(WindowsNetworkHelperClient::Operation::Routes);
        check(client.ownedConfiguration()["capture_prefixes"].toArray()==QJsonArray{"198.18.0.7/32"},"confirmed replacement was not retained by the ordinary client");
        check(!captured(device,L"198.18.0.6") && captured(device,L"198.18.0.7"),"capture replacement did not preserve its intended set");
        client.quiesce();wait(WindowsNetworkHelperClient::Operation::Quiesce);
        check(!captured(device,L"198.18.0.7") && !dnsPresent(device) && client.state()==WindowsNetworkHelperClient::State::Quiesced,"capture/DNS were not released before core stop");
        client.inspect(session);wait(WindowsNetworkHelperClient::Operation::Inspect);
        bool restoring=false;for(const auto &item:client.pendingOwners())if(QUuid(item.toObject()["owner"].toString())==session)restoring=item.toObject()["phase"]=="restoring";
        check(restoring,"capture release did not preserve its durable restore intent");
        client.restore();wait(WindowsNetworkHelperClient::Operation::Restore);
        check(client.packetPipeHandle()==0 && client.state()==WindowsNetworkHelperClient::State::Ready,"device was not released after core stop");
        client.cleanupRestored(session);wait(WindowsNetworkHelperClient::Operation::Acknowledge);
        client.close();wait(WindowsNetworkHelperClient::Operation::Close);
        check(authorizations==1,"network lifecycle repeated authorization");
        std::cout<<"PASS: ordinary Qt native write-ahead session, real UDP, dynamic captures, DNS release before core stop, device/receipt cleanup\n";return 0;
    }
    check(client.state()==WindowsNetworkHelperClient::State::Ready && contains(client.pendingOwners(),uuid(input.dead)) && contains(client.pendingOwners(),uuid(input.live)) && !contains(client.pendingOwners(),uuid(input.foreign)),"Qt inspection crossed account ownership");
    client.recover(uuid(input.dead));wait(WindowsNetworkHelperClient::Operation::Recover);
    client.cleanupRestored(uuid(input.dead));wait(WindowsNetworkHelperClient::Operation::Acknowledge);
    client.close();wait(WindowsNetworkHelperClient::Operation::Close);
    check(client.state()==WindowsNetworkHelperClient::State::Idle && authorizations==1,"Qt recovery repeated authorization or retained its channel");
    bool cancelled=false,lateClosed=false;
    std::function<void(HANDLE,DWORD)> late;
    WindowsNetworkHelperClient pending(nullptr,[&](const QUuid &,auto ready){late=ready;});
    QObject::connect(&pending,&WindowsNetworkHelperClient::finished,&application,[&](auto,auto value){cancelled=value.status==PlatformOperationResult::Status::Cancelled;});
    pending.inspect(QUuid::createUuid());pending.cancel();
    check(cancelled && pending.state()==WindowsNetworkHelperClient::State::Idle,"pending Qt authorization blocked cancellation");
    HANDLE stale=nullptr;check(DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&stale,PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0),"late approval fixture handle");
    late(stale,0);SetLastError(0);DWORD flags=0;lateClosed=!GetHandleInformation(stale,&flags) && GetLastError()==ERROR_INVALID_HANDLE;
    check(lateClosed && pending.state()==WindowsNetworkHelperClient::State::Idle,"late Qt approval survived cancellation");
    std::cout<<"PASS: ordinary Qt actual native inspect/recover/ack/close, single approval, cancellation and late-approval disposal\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
