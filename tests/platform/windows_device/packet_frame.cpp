#include "infrastructure/networkhelper/windows/packetrelay.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "infrastructure/process/windows/identity.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace {
void bufferedPackets()
{
    constexpr unsigned int mtu=68;
    const WindowsProcess current(GetCurrentProcessId());
    const auto name=L"\\\\.\\pipe\\JustConnect-frame-test-"+std::to_wstring(current.identity().pid);
    auto input=WindowsPacketPipe::create(name,current);
    auto output=WindowsPacketPipe::connect(name,current.handle(),1000);
    input->accept(current,1000);
    std::vector<unsigned char> stream;
    const auto append=[&](unsigned char size) {
        stream.insert(stream.end(),{0,0,0,size});
        std::vector<unsigned char> packet(size,size);
        packet[0]=0x45;packet[2]=0;packet[3]=size;
        stream.insert(stream.end(),packet.begin(),packet.end());
        return packet;
    };
    // The second payload straddles the read buffer when both frames arrive in one write.
    const auto first=append(32),second=append(52);
    stream.insert(stream.end(),{0,0,0,mtu+1});
    output->write(stream.data(),static_cast<DWORD>(stream.size()),1000);
    WindowsIPv4PacketReader reader(mtu);
    if (!std::ranges::equal(reader.read(*input),first) || !std::ranges::equal(reader.read(*input),second))
        throw std::runtime_error("buffered input changed the packet boundaries or payload");
    const auto expectError=[&](int expected,const char *failure) {
        try { reader.read(*input); }
        catch (const std::system_error &error) {
            if (error.code().value()==expected) return;
            throw;
        }
        throw std::runtime_error(failure);
    };
    expectError(ERROR_INVALID_DATA,"buffered input accepted a frame larger than the MTU");
    input->close();
    expectError(ERROR_OPERATION_ABORTED,"closed pipe retained buffered input");
}
}

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
    bufferedPackets();
    std::cout << "PASS: IPv4 framing rejects short, truncated, over-MTU and invalid header packets\n";
    return 0;
} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
