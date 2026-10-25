#pragma once

#include <cstddef>
class WindowsTunDevice;
class WindowsPacketPipe;

bool validWindowsIPv4Packet(const unsigned char *packet,std::size_t size,unsigned int mtu);
void relayWindowsPackets(WindowsTunDevice &device,WindowsPacketPipe &pipe,unsigned int mtu);
