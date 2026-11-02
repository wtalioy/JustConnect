#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <stdexcept>

namespace WindowsDeviceCheck {
inline NET_LUID idle(const GUID &id)
{
    NET_LUID luid{};
    if(ConvertInterfaceGuidToLuid(&id,&luid)!=NO_ERROR)throw std::runtime_error("parked adapter disappeared");
    MIB_IF_ROW2 identity{};identity.InterfaceLuid=luid;
    if(GetIfEntry2Ex(MibIfEntryNormalWithoutStatistics,&identity)!=NO_ERROR || identity.InterfaceGuid!=id)
        throw std::runtime_error("parked adapter identity differs");
    MIB_UNICASTIPADDRESS_TABLE *addresses=nullptr;
    if(GetUnicastIpAddressTable(AF_INET,&addresses)!=NO_ERROR)throw std::runtime_error("read parked IPv4 addresses");
    bool occupied=false;
    for(ULONG i=0;i<addresses->NumEntries;++i)occupied|=addresses->Table[i].InterfaceLuid.Value==luid.Value;
    FreeMibTable(addresses);
    if(occupied)throw std::runtime_error("parked adapter retained an IPv4 address");
    MIB_IPFORWARD_TABLE2 *routes=nullptr;
    if(GetIpForwardTable2(AF_INET,&routes)!=NO_ERROR)throw std::runtime_error("read parked IPv4 routes");
    for(ULONG i=0;i<routes->NumEntries;++i){
        const auto &route=routes->Table[i];if(route.InterfaceLuid.Value!=luid.Value)continue;
        const auto network=ntohl(route.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
        const bool local=route.Protocol==MIB_IPPROTO_LOCAL && route.NextHop.Ipv4.sin_addr.S_un.S_addr==0;
        const bool multicast=network==0xe0000000u && route.DestinationPrefix.PrefixLength==4 && route.Origin==NlroWellKnown;
        const bool broadcast=network==INADDR_BROADCAST && route.DestinationPrefix.PrefixLength==32 && route.Origin==NlroManual;
        occupied|=!(local && (multicast || broadcast));
    }
    FreeMibTable(routes);
    if(occupied)throw std::runtime_error("parked adapter retained a nonautomatic IPv4 route");
    return luid;
}
}
