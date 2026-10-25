#include "infrastructure/networkhelper/windows/networkhelperclient.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QTimer>
#include <QThread>
#include <QJsonObject>
#include <iostream>
#include <objbase.h>
#include <cstdint>

namespace {
void check(bool value,const char *stage){if(!value)throw std::runtime_error(stage);}
struct Input {std::uintptr_t server=0;GUID dead{},live{},foreign{};};
QUuid uuid(const GUID &id){wchar_t value[39]{};check(StringFromGUID2(id,value,39)!=0,"Qt test ownership UUID");return QUuid(QString::fromWCharArray(value));}
bool contains(const QJsonArray &owners,const QUuid &id){for(const auto &item:owners)if(QUuid(item.toObject()["owner"].toString())==id)return true;return false;}
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
