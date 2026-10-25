#include "infrastructure/networkhelper/windows/packetrelay.h"
#include <iostream>
#include <stdexcept>
#include <vector>

int main() try
{
    std::vector<unsigned char> packet(32);
    packet[0]=0x45;packet[3]=32;
    if (!validWindowsIPv4Packet(packet.data(),packet.size(),1400)) throw std::runtime_error("valid IPv4 frame refused");
    for (const auto size:{0u,19u,31u,33u}) {
        if (validWindowsIPv4Packet(packet.data(),size,1400)) throw std::runtime_error("invalid IPv4 length accepted");
    }
    for (const auto version:{0x44,0x4f,0x65}) {
        packet[0]=static_cast<unsigned char>(version);
        if (validWindowsIPv4Packet(packet.data(),packet.size(),1400)) throw std::runtime_error("invalid IPv4 header accepted");
    }
    packet[0]=0x45;
    if (validWindowsIPv4Packet(packet.data(),packet.size(),31)) throw std::runtime_error("MTU boundary bypassed");
    std::cout << "PASS: IPv4 framing rejects short, truncated, over-MTU and invalid header packets\n";
    return 0;
} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
