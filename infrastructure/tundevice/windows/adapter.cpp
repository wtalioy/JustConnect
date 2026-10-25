#include "infrastructure/tundevice/windows/adapter.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <system_error>

namespace {
[[noreturn]] void fail(const char *stage, DWORD error = GetLastError())
{
    throw std::system_error(static_cast<int>(error), std::system_category(), stage);
}
void checked(DWORD status, const char *stage) { if (status != NO_ERROR) fail(stage, status); }

template<typename T> T *procedure(HMODULE module, const char *name)
{
    const auto value = GetProcAddress(module, name);
    if (!value) fail(name);
    return reinterpret_cast<T *>(value);
}

bool unicast(IN_ADDR address)
{
    const auto first = ntohl(address.S_un.S_addr) >> 24;
    return first > 0 && first < 224 && first != 127;
}
SOCKADDR_INET ipv4(IN_ADDR address)
{
    SOCKADDR_INET result{};
    result.Ipv4.sin_family = AF_INET;
    result.Ipv4.sin_addr = address;
    return result;
}
}

std::unique_ptr<WindowsTunDevice> WindowsTunDevice::create(const std::wstring &dll, const GUID &owner,
    IN_ADDR source, IN_ADDR peer, unsigned int maximum, const std::vector<WindowsTunPrefix> &targets,
    const std::function<void(const WindowsTunIdentity &)> &allocated)
{
    if (!std::filesystem::path(dll).is_absolute() || owner == GUID{} || !allocated
        || !unicast(source) || !unicast(peer) || source.S_un.S_addr == peer.S_un.S_addr || maximum < 68 || maximum > 65535)
        fail("invalid owned adapter configuration", ERROR_INVALID_PARAMETER);
    for (const auto &target : targets) {
        const auto mask = target.bits <= 32 && target.bits > 0 ? 0xffffffffu << (32-target.bits) : 0;
        const auto network = ntohl(target.address.S_un.S_addr);
        if (target.bits < 2 || target.bits > 32 || (network & mask) != network || (ntohl(source.S_un.S_addr) & mask) == network)
            fail("invalid owned capture prefix", ERROR_INVALID_PARAMETER);
    }
    auto device = std::unique_ptr<WindowsTunDevice>(new WindowsTunDevice);
    device->module = LoadLibraryExW(dll.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!device->module) fail("load verified Wintun library");
    const auto createAdapter = procedure<WINTUN_CREATE_ADAPTER_FUNC>(device->module,"WintunCreateAdapter");
    const auto getLuid = procedure<WINTUN_GET_ADAPTER_LUID_FUNC>(device->module,"WintunGetAdapterLUID");
    const auto start = procedure<WINTUN_START_SESSION_FUNC>(device->module,"WintunStartSession");
    const auto getReady = procedure<WINTUN_GET_READ_WAIT_EVENT_FUNC>(device->module,"WintunGetReadWaitEvent");
    device->closeAdapter = procedure<WINTUN_CLOSE_ADAPTER_FUNC>(device->module,"WintunCloseAdapter");
    device->endSession = procedure<WINTUN_END_SESSION_FUNC>(device->module,"WintunEndSession");
    device->receive = procedure<WINTUN_RECEIVE_PACKET_FUNC>(device->module,"WintunReceivePacket");
    device->release = procedure<WINTUN_RELEASE_RECEIVE_PACKET_FUNC>(device->module,"WintunReleaseReceivePacket");
    device->allocate = procedure<WINTUN_ALLOCATE_SEND_PACKET_FUNC>(device->module,"WintunAllocateSendPacket");
    device->send = procedure<WINTUN_SEND_PACKET_FUNC>(device->module,"WintunSendPacket");
    wchar_t guid[39]{};
    if (!StringFromGUID2(owner, guid, static_cast<int>(std::size(guid)))) fail("format owned adapter identity",ERROR_INVALID_PARAMETER);
    device->owned.name = std::wstring(L"JustConnect ")+guid;
    device->owned.guid = owner;
    device->mtu = maximum;
    MIB_IF_TABLE2 *table = nullptr;
    checked(GetIfTable2Ex(MibIfTableNormalWithoutStatistics,&table),"read existing adapter identities");
    bool present = false;
    for (ULONG i=0; i<table->NumEntries; ++i)
        present = present || table->Table[i].InterfaceGuid == owner || device->owned.name == table->Table[i].Alias;
    FreeMibTable(table);
    if (present) fail("refuse existing adapter identity",ERROR_ALREADY_EXISTS);
    device->adapter = createAdapter(device->owned.name.c_str(),L"JustConnect",&owner);
    if (!device->adapter) fail("create owned adapter");
    getLuid(device->adapter,&device->owned.luid);
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = device->owned.luid;
    checked(GetIfEntry2Ex(MibIfTableNormalWithoutStatistics,&row),"confirm new adapter identity");
    if (row.InterfaceGuid != owner || device->owned.name != row.Alias)
        fail("new adapter identity differs",ERROR_INVALID_DATA);
    device->owned.index = row.InterfaceIndex;
    allocated(device->owned);
    device->session = start(device->adapter,WINTUN_MIN_RING_CAPACITY);
    if (!device->session) fail("start owned Wintun rings");
    device->ready = getReady(device->session);
    if (!device->ready) fail("read owned ring event");
    device->stop = CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if (!device->stop) fail("create owned adapter stop event");
    device->configure(source,peer,targets);
    return device;
}

void WindowsTunDevice::configure(IN_ADDR source, IN_ADDR peer, const std::vector<WindowsTunPrefix> &targets)
{
    MIB_IPINTERFACE_ROW row{};
    row.Family = AF_INET;
    row.InterfaceLuid = owned.luid;
    checked(GetIpInterfaceEntry(&row),"read owned IPv4 interface");
    row.SitePrefixLength = 0; // SetIpInterfaceEntry requires zero for IPv4.
    row.UseAutomaticMetric = FALSE;
    row.Metric = 1;
    row.NlMtu = mtu;
    row.DadTransmits = 0;
    row.DisableDefaultRoutes = TRUE;
    checked(SetIpInterfaceEntry(&row),"configure owned IPv4 interface");
    MIB_IPINTERFACE_ROW confirmed{};
    confirmed.Family = AF_INET;
    confirmed.InterfaceLuid = owned.luid;
    checked(GetIpInterfaceEntry(&confirmed),"confirm owned IPv4 interface");
    if (confirmed.NlMtu != mtu || confirmed.UseAutomaticMetric || confirmed.Metric != row.Metric
        || confirmed.DadTransmits != 0 || !confirmed.DisableDefaultRoutes)
        fail("owned IPv4 interface differs",ERROR_INVALID_DATA);
    MIB_UNICASTIPADDRESS_ROW address{};
    InitializeUnicastIpAddressEntry(&address);
    address.InterfaceLuid = owned.luid;
    address.Address = ipv4(source);
    address.OnLinkPrefixLength = 32;
    address.DadState = IpDadStatePreferred;
    checked(CreateUnicastIpAddressEntry(&address),"create owned IPv4 address");
    checked(GetUnicastIpAddressEntry(&address),"confirm owned IPv4 address");
    if (address.InterfaceLuid.Value != owned.luid.Value || address.OnLinkPrefixLength != 32 || address.DadState != IpDadStatePreferred)
        fail("owned IPv4 address differs",ERROR_INVALID_DATA);
    std::vector<WindowsTunPrefix> routes{{peer,32}};
    routes.insert(routes.end(),targets.begin(),targets.end());
    std::vector<WindowsTunPrefix> seen;
    for (const auto &target : routes) {
        if (std::any_of(seen.begin(),seen.end(),[&](const auto &item) { return item.address.S_un.S_addr == target.address.S_un.S_addr && item.bits == target.bits; })) continue;
        seen.push_back(target);
        MIB_IPFORWARD_ROW2 route{};
        InitializeIpForwardEntry(&route);
        route.InterfaceLuid = owned.luid;
        route.DestinationPrefix.Prefix = ipv4(target.address);
        route.DestinationPrefix.PrefixLength = target.bits;
        route.NextHop = ipv4(IN_ADDR{});
        route.Metric = 1;
        route.Protocol = MIB_IPPROTO_NETMGMT;
        checked(CreateIpForwardEntry2(&route),"create owned IPv4 capture");
        checked(GetIpForwardEntry2(&route),"confirm owned IPv4 capture");
        if (route.InterfaceLuid.Value != owned.luid.Value || route.Metric != 1 || route.Protocol != MIB_IPPROTO_NETMGMT)
            fail("owned IPv4 capture differs",ERROR_INVALID_DATA);
    }
}

size_t WindowsTunDevice::read(unsigned char *packet, size_t capacity)
{
    std::lock_guard<std::mutex> serial(readLock);
    std::shared_lock<std::shared_mutex> active(lifetime);
    if (closed || !packet || capacity == 0) fail("owned adapter read unavailable",ERROR_OPERATION_ABORTED);
    for (;;) {
        if (WaitForSingleObject(stop,0) == WAIT_OBJECT_0) fail("owned adapter stopped",ERROR_OPERATION_ABORTED);
        DWORD size = 0;
        BYTE *data = receive(session,&size);
        if (!data) {
            const auto error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS) fail("receive owned packet",error);
            const HANDLE waits[]{stop,ready};
            const auto state = WaitForMultipleObjects(2,waits,FALSE,INFINITE);
            if (state == WAIT_FAILED) fail("wait for owned packet");
            if (state == WAIT_OBJECT_0) fail("owned adapter stopped",ERROR_OPERATION_ABORTED);
            continue;
        }
        if (size == 0 || size > 65535) {
            release(session,data);
            fail("invalid owned ring packet size",ERROR_INVALID_DATA);
        }
        const bool ipv6 = (data[0] >> 4) == 6;
        const bool valid = size >= 20 && size <= mtu && size <= capacity && (data[0] >> 4) == 4;
        if (valid) std::memcpy(packet,data,size);
        release(session,data);
        if (ipv6) continue;
        if (!valid) fail("invalid owned IPv4 packet",ERROR_INVALID_DATA);
        return size;
    }
}

void WindowsTunDevice::write(const unsigned char *packet, size_t size)
{
    if (!packet || size < 20 || size > mtu || (packet[0] >> 4) != 4 || (size_t(packet[2]) << 8 | packet[3]) != size)
        fail("invalid owned IPv4 packet",ERROR_INVALID_DATA);
    std::lock_guard<std::mutex> serial(writeLock);
    std::shared_lock<std::shared_mutex> active(lifetime);
    if (closed) fail("owned adapter stopped",ERROR_OPERATION_ABORTED);
    BYTE *data = nullptr;
    while (!(data = allocate(session,static_cast<DWORD>(size)))) {
        const auto error = GetLastError();
        if (error != ERROR_BUFFER_OVERFLOW) fail("allocate owned packet",error);
        // Wintun has no write-ready event; preserve bounded, close-interruptible backpressure.
        const auto state = WaitForSingleObject(stop,1);
        if (state == WAIT_FAILED) fail("wait for owned ring capacity");
        if (state == WAIT_OBJECT_0) fail("owned adapter stopped",ERROR_OPERATION_ABORTED);
    }
    std::memcpy(data,packet,size);
    send(session,data);
}

void WindowsTunDevice::close()
{
    std::call_once(closedOnce,[&] {
        closed = true;
        if (stop) SetEvent(stop);
        std::unique_lock<std::shared_mutex> exclusive(lifetime);
        if (session && endSession) endSession(session);
        if (adapter && closeAdapter) closeAdapter(adapter);
        if (stop) CloseHandle(stop);
        if (module) FreeLibrary(module);
    });
}
WindowsTunDevice::~WindowsTunDevice() { close(); }
