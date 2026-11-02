#pragma once

#include <cstddef>
class WindowsTunDevice;
class WindowsPacketPipe;

bool validWindowsIPv4Packet(const unsigned char *packet,std::size_t size,unsigned int mtu);
// Stops I/O on exit; the owning session decides whether to park or remove the adapter.
void relayWindowsPackets(WindowsTunDevice &device,WindowsPacketPipe &pipe,unsigned int mtu);
