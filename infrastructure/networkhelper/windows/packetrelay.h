#pragma once

#include <cstddef>
#include <span>
#include <vector>
class WindowsTunDevice;
class WindowsPacketPipe;

bool validWindowsIPv4Packet(const unsigned char *packet,std::size_t size,unsigned int mtu);

class WindowsIPv4PacketReader final {
public:
    explicit WindowsIPv4PacketReader(unsigned int mtu);
    // The returned packet remains valid until the next read.
    std::span<const unsigned char> read(WindowsPacketPipe &pipe);
private:
    void fill(WindowsPacketPipe &pipe,std::size_t needed);
    std::vector<unsigned char> frame;
    std::size_t offset=0,end=0;
};

// Stops I/O on exit; the owning session decides whether to park or remove the adapter.
void relayWindowsPackets(WindowsTunDevice &device,WindowsPacketPipe &pipe,unsigned int mtu);
