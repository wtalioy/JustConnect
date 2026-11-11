#include "infrastructure/networkhelper/windows/packetrelay.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "infrastructure/tundevice/windows/adapter.h"
#include <cstdint>
#include <exception>
#include <cstring>
#include <system_error>
#include <thread>
#include <vector>

namespace {
constexpr auto PrefixSize=sizeof(std::uint32_t);
std::size_t frameCapacity(unsigned int mtu)
{
    if (mtu<68 || mtu>65535)
        throw std::system_error(ERROR_INVALID_PARAMETER,std::system_category(),"invalid packet relay MTU");
    return mtu+PrefixSize;
}
}

bool validWindowsIPv4Packet(const unsigned char *packet,std::size_t size,unsigned int mtu)
{
    return packet && size>=20 && size<=mtu && (packet[0]>>4)==4 && (packet[0]&15)*4>=20
        && (packet[0]&15)*4<=size && (std::size_t(packet[2])<<8|packet[3])==size;
}

WindowsIPv4PacketReader::WindowsIPv4PacketReader(unsigned int mtu):frame(frameCapacity(mtu)) {}

void WindowsIPv4PacketReader::fill(WindowsPacketPipe &pipe,std::size_t needed)
{
    if (end-offset>=needed) return;
    end-=offset;
    if (offset && end) std::memmove(frame.data(),frame.data()+offset,end);
    offset=0;
    while (end<needed)
        end+=pipe.readSome(frame.data()+end,static_cast<DWORD>(frame.size()-end));
}

std::span<const unsigned char> WindowsIPv4PacketReader::read(WindowsPacketPipe &pipe)
{
    if (pipe.isClosed())
        throw std::system_error(ERROR_OPERATION_ABORTED,std::system_category(),"packet pipe stopped");
    fill(pipe,PrefixSize);
    std::uint32_t length=0;
    std::memcpy(&length,frame.data()+offset,PrefixSize);
    const auto size=ntohl(length);
    const auto mtu=static_cast<unsigned int>(frame.size()-PrefixSize);
    if (size<20 || size>mtu)
        throw std::system_error(ERROR_INVALID_DATA,std::system_category(),"invalid helper packet length");
    fill(pipe,PrefixSize+size);
    const auto packet=frame.data()+offset+PrefixSize;
    if (!validWindowsIPv4Packet(packet,size,mtu))
        throw std::system_error(ERROR_INVALID_DATA,std::system_category(),"invalid helper IPv4 packet");
    offset+=PrefixSize+size;
    return {packet,size};
}

void relayWindowsPackets(WindowsTunDevice &device,WindowsPacketPipe &pipe,unsigned int mtu)
{
    WindowsIPv4PacketReader incoming(mtu);
    std::exception_ptr error;
    std::mutex lock;
    const auto stop=[&] {
        { std::lock_guard<std::mutex> guard(lock); if (!error) error=std::current_exception(); }
        pipe.close();device.interrupt();
    };
    std::thread outgoing([&] {
        try {
            std::vector<unsigned char> frame(mtu+PrefixSize);
            for (;;) {
                const auto size=device.read(frame.data()+PrefixSize,mtu);
                if (!validWindowsIPv4Packet(frame.data()+PrefixSize,size,mtu))
                    throw std::system_error(ERROR_INVALID_DATA,std::system_category(),"invalid device packet frame");
                const auto length=htonl(static_cast<u_long>(size));
                std::memcpy(frame.data(),&length,PrefixSize);
                pipe.write(frame.data(),static_cast<DWORD>(size+PrefixSize));
            }
        } catch (...) { stop(); }
    });
    try {
        for (;;) {
            const auto packet=incoming.read(pipe);
            device.write(packet.data(),packet.size());
        }
    } catch (...) { stop(); }
    outgoing.join();
    try { std::rethrow_exception(error); } catch (const std::system_error &failure) {
        if (failure.code().value()!=ERROR_BROKEN_PIPE && failure.code().value()!=ERROR_NO_DATA) throw;
    }
}
