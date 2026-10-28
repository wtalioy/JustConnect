#pragma once

#include <wintun.h>
#include <cstring>
#include <system_error>

// Only for the hash-pinned 0.14.1 SDK; remove when a signed release includes ec0a6b98456f.
// Layout reference: https://git.zx2c4.com/wintun/tree/api/session.c?h=0.14.1
namespace Wintun0141 {
struct Ring { volatile ULONG head, tail; volatile LONG alertable; };
struct Cursor { ULONG position, released, pending; CRITICAL_SECTION lock; };
struct RingDescriptor { ULONG size; Ring *ring; HANDLE moved; };
struct SessionLayout {
    ULONG capacity;
    Cursor receive, send;
    RingDescriptor outgoing, incoming;
    HANDLE device;
};

inline HANDLE sendWakeEvent(WINTUN_SESSION_HANDLE session, DWORD capacity, HANDLE readEvent)
{
    if (!session || !readEvent)
        throw std::system_error(ERROR_INVALID_DATA,std::system_category(),"missing Wintun 0.14.1 session identity");
    SessionLayout layout{};
    std::memcpy(&layout,session,sizeof(layout));
    constexpr auto alignment=sizeof(ULONG);
    constexpr auto packetSize=(sizeof(ULONG)+WINTUN_MAX_IP_PACKET_SIZE+alignment-1)&~(alignment-1);
    const auto ringSize=sizeof(Ring)+capacity+packetSize-alignment;
    DWORD flags=0;
    if (layout.capacity!=capacity || layout.outgoing.moved!=readEvent
        || !layout.outgoing.ring || !layout.incoming.ring || layout.outgoing.ring==layout.incoming.ring
        || layout.outgoing.size!=ringSize || layout.incoming.size!=ringSize
        || !layout.incoming.moved || layout.incoming.moved==INVALID_HANDLE_VALUE || layout.incoming.moved==readEvent
        || !GetHandleInformation(layout.incoming.moved,&flags))
        throw std::system_error(ERROR_INVALID_DATA,std::system_category(),"Wintun 0.14.1 session layout differs");
    return layout.incoming.moved;
}

inline void notify(HANDLE event)
{
    // 0.14.1 can miss Alertable on both sides; an unconditional event also orders the published tail.
    if (!SetEvent(event))
        throw std::system_error(GetLastError(),std::system_category(),"wake owned Wintun receive ring");
}
}
