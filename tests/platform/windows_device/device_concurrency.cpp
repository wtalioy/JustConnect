#include "infrastructure/tundevice/windows/adapter.h"
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
HANDLE entered=nullptr;
BYTE *WINAPI fullRing(WINTUN_SESSION_HANDLE,DWORD)
{
    SetEvent(entered);
    SetLastError(ERROR_BUFFER_OVERFLOW);
    return nullptr;
}
void check(bool value,const char *message) { if(!value)throw std::runtime_error(message); }
}

struct WindowsTunDeviceTest {
    static void run()
    {
        MIB_IF_TABLE2 *table=nullptr;
        check(GetIfTable2(&table)==NO_ERROR,"read native interface identities");
        struct Free { MIB_IF_TABLE2 *table; ~Free(){FreeMibTable(table);} } free{table};
        auto device=std::unique_ptr<WindowsTunDevice>(new WindowsTunDevice);
        for(ULONG i=0;i<table->NumEntries;++i)if(table->Table[i].Type==IF_TYPE_SOFTWARE_LOOPBACK){
            const auto &row=table->Table[i];device->owned={row.Alias,row.InterfaceGuid,row.InterfaceLuid,row.InterfaceIndex};break;
        }
        check(device->owned.index!=0,"find native loopback identity");
        device->source.S_un.S_addr=htonl(0xc0000201);device->peer.S_un.S_addr=htonl(0xc0000202);device->mtu=1400;
        device->stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        entered=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        check(device->stop && entered,"create concurrency test events");
        struct Close { ~Close(){CloseHandle(entered);entered=nullptr;} } close;
        device->allocate=fullRing;
        // No adapter/session is created and no routes are installed: the only native query reads loopback identity.
        std::exception_ptr writeFailure;
        const unsigned char packet[]{0x45,0,0,20,0,0,0,0,64,253,0xf5,0xe9,192,0,2,2,192,0,2,1};
        std::thread writer([&]{try{device->write(packet,sizeof(packet));}catch(...){writeFailure=std::current_exception();}});
        const bool writing=WaitForSingleObject(entered,2000)==WAIT_OBJECT_0;
        auto routes=std::async(std::launch::async,[&]{device->reconcile({});});
        const bool responsive=routes.wait_for(std::chrono::seconds(2))==std::future_status::ready;
        std::exception_ptr routeFailure;
        if(responsive)try{routes.get();}catch(...){routeFailure=std::current_exception();}
        device->close();writer.join();
        if(!responsive)try{routes.get();}catch(...){}
        check(writing,"data writer did not reach ring backpressure");
        check(responsive && !routeFailure,"capture withdrawal waits on blocked packet writes");
        check(writeFailure!=nullptr,"close did not interrupt the blocked data writer");
        try{std::rethrow_exception(writeFailure);}catch(const std::system_error &error){
            check(error.code().value()==ERROR_OPERATION_ABORTED,"blocked writer reported unexpected close failure");
        }
    }
};

int main() try
{
    WindowsTunDeviceTest::run();
    std::cout<<"PASS: route withdrawal remains responsive under packet backpressure; close cancels writer; host network unchanged\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
