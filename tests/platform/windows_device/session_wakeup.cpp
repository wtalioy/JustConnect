#include "infrastructure/tundevice/windows/sessionwakeup.h"
#include <objbase.h>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition,const char *message) { if (!condition) throw std::runtime_error(message); }
struct Event {
    HANDLE handle=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    Event() { require(handle!=nullptr,"create wakeup test event"); }
    ~Event() { CloseHandle(handle); }
};
void selfTest()
{
    Event outgoing,incoming;
    Wintun0141::Ring rings[2]{};
    Wintun0141::SessionLayout session{};
    session.capacity=WINTUN_MIN_RING_CAPACITY;
    const auto size=sizeof(Wintun0141::Ring)+session.capacity+65536;
    session.outgoing={static_cast<ULONG>(size),&rings[0],outgoing.handle};
    session.incoming={static_cast<ULONG>(size),&rings[1],incoming.handle};
    const auto wake=Wintun0141::sendWakeEvent(reinterpret_cast<WINTUN_SESSION_HANDLE>(&session),session.capacity,outgoing.handle);
    Wintun0141::notify(wake);
    require(WaitForSingleObject(incoming.handle,0)==WAIT_OBJECT_0,"owned incoming event was not signaled");
    require(WaitForSingleObject(outgoing.handle,0)==WAIT_TIMEOUT,"outgoing read event was signaled instead");
    for (unsigned int fault=0;fault<5;++fault) {
        auto invalid=session;
        if (fault==0) invalid.capacity/=2;
        if (fault==1) invalid.outgoing.moved=incoming.handle;
        if (fault==2) invalid.incoming.ring=invalid.outgoing.ring;
        if (fault==3) --invalid.incoming.size;
        if (fault==4) invalid.incoming.moved=INVALID_HANDLE_VALUE;
        bool refused=false;
        try { Wintun0141::sendWakeEvent(reinterpret_cast<WINTUN_SESSION_HANDLE>(&invalid),session.capacity,outgoing.handle); }
        catch (const std::system_error &) { refused=true; }
        require(refused,"incompatible SDK session layout accepted");
    }
    bool refused=false;
    try { Wintun0141::notify(INVALID_HANDLE_VALUE); }
    catch (const std::system_error &) { refused=true; }
    require(refused,"failed event signal was ignored");
}

template<typename F> F *procedure(HMODULE module,const char *name)
{
    const auto function=GetProcAddress(module,name);
    require(function!=nullptr,"missing SDK procedure");
    return reinterpret_cast<F *>(function);
}
void nativeTest(const wchar_t *dll)
{
    wchar_t guard[8]{};
    require(GetEnvironmentVariableW(L"GITHUB_ACTIONS",guard,8)==4 && std::wstring(guard)==L"true",
        "native SDK wakeup test requires a disposable runner");
    const auto module=LoadLibraryExW(dll,nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    require(module!=nullptr,"load pinned SDK");
    struct Unload { HMODULE module; ~Unload() { FreeLibrary(module); } } unload{module};
    const auto create=procedure<WINTUN_CREATE_ADAPTER_FUNC>(module,"WintunCreateAdapter");
    const auto close=procedure<WINTUN_CLOSE_ADAPTER_FUNC>(module,"WintunCloseAdapter");
    const auto start=procedure<WINTUN_START_SESSION_FUNC>(module,"WintunStartSession");
    const auto end=procedure<WINTUN_END_SESSION_FUNC>(module,"WintunEndSession");
    const auto ready=procedure<WINTUN_GET_READ_WAIT_EVENT_FUNC>(module,"WintunGetReadWaitEvent");
    const auto allocate=procedure<WINTUN_ALLOCATE_SEND_PACKET_FUNC>(module,"WintunAllocateSendPacket");
    const auto send=procedure<WINTUN_SEND_PACKET_FUNC>(module,"WintunSendPacket");
    GUID owner{};require(SUCCEEDED(CoCreateGuid(&owner)),"create probe identity");
    wchar_t id[39]{};require(StringFromGUID2(owner,id,39)!=0,"format probe identity");
    const auto adapter=create((std::wstring(L"JustConnect Wakeup ")+id).c_str(),L"JustConnect",&owner);
    require(adapter!=nullptr,"create owned wakeup adapter");
    struct Close { WINTUN_ADAPTER_HANDLE adapter; WINTUN_CLOSE_ADAPTER_FUNC *close; ~Close() { close(adapter); } } closed{adapter,close};
    const auto session=start(adapter,WINTUN_MIN_RING_CAPACITY);
    require(session!=nullptr,"start owned wakeup session");
    struct End { WINTUN_SESSION_HANDLE session; WINTUN_END_SESSION_FUNC *end; ~End() { end(session); } } ended{session,end};
    const auto event=Wintun0141::sendWakeEvent(session,WINTUN_MIN_RING_CAPACITY,ready(session));
    Wintun0141::SessionLayout layout{};std::memcpy(&layout,session,sizeof(layout));
    const auto ring=layout.incoming.ring;
    auto deadline=GetTickCount64()+5000;
    while (!ring->alertable && GetTickCount64()<deadline) Sleep(1);
    require(ring->alertable && ring->head==ring->tail,"driver did not enter an empty-ring wait");
    Sleep(50);
    require(ring->alertable && ring->head==ring->tail,"empty-ring wait was not stable");
    // Fault injection reproduces the SDK's stale FALSE read while the driver is already asleep.
    InterlockedExchange(&ring->alertable,FALSE);
    auto packet=allocate(session,20);require(packet!=nullptr,"allocate wakeup test IPv4 packet");
    const unsigned char ipv4[]{0x45,0,0,20,0,0,0,0,64,253,0xf5,0xe9,192,0,2,2,192,0,2,1};
    std::memcpy(packet,ipv4,sizeof(ipv4));send(session,packet);
    Sleep(50);
    const auto stalled=ring->head!=ring->tail;
    InterlockedExchange(&ring->alertable,TRUE);
    require(stalled,"fault injection did not retain the unnotified packet");
    Wintun0141::notify(event);
    deadline=GetTickCount64()+5000;
    while (ring->head!=ring->tail && GetTickCount64()<deadline) Sleep(1);
    require(ring->head==ring->tail,"owned wake event did not drain the original packet");
    std::cout<<"PASS: pinned SDK retained an unnotified packet; owned wakeup drained it without another packet\n";
}
}

int wmain(int argc,wchar_t **argv) try
{
    selfTest();
    if (argc==2) nativeTest(argv[1]);
    else require(argc==1,"session wakeup test takes an optional pinned SDK DLL");
    std::cout<<"PASS: session identity validation and event failure handling\n";
    return 0;
} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
