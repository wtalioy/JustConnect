#include "infrastructure/networkhelper/windows/packetrelay.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "infrastructure/tundevice/windows/adapter.h"
#include <exception>
#include <cstring>
#include <system_error>
#include <thread>
#include <vector>

bool validWindowsIPv4Packet(const unsigned char *packet,std::size_t size,unsigned int mtu)
{
    return packet && size>=20 && size<=mtu && (packet[0]>>4)==4 && (packet[0]&15)*4>=20
        && (packet[0]&15)*4<=size && (std::size_t(packet[2])<<8|packet[3])==size;
}

void relayWindowsPackets(WindowsTunDevice &device,WindowsPacketPipe &pipe,unsigned int mtu)
{
    if (mtu<68 || mtu>65535) throw std::system_error(ERROR_INVALID_PARAMETER,std::system_category(),"invalid packet relay MTU");
    std::exception_ptr error;
    std::mutex lock;
    const auto stop=[&] {
        { std::lock_guard<std::mutex> guard(lock); if (!error) error=std::current_exception(); }
        pipe.close();device.close();
    };
    std::thread outgoing([&] {
        try {
            std::vector<unsigned char> frame(mtu+4);
            for (;;) {
                const auto size=device.read(frame.data()+4,mtu);
                if (!validWindowsIPv4Packet(frame.data()+4,size,mtu))
                    throw std::system_error(ERROR_INVALID_DATA,std::system_category(),"invalid device packet frame");
                const auto length=htonl(static_cast<u_long>(size));
                std::memcpy(frame.data(),&length,4);
                pipe.write(frame.data(),static_cast<DWORD>(size+4));
            }
        } catch (...) { stop(); }
    });
    try {
        std::vector<unsigned char> packet(mtu);
        for (;;) {
            u_long length=0;
            pipe.read(&length,4);
            const auto size=ntohl(length);
            if (size<20 || size>mtu) throw std::system_error(ERROR_INVALID_DATA,std::system_category(),"invalid helper packet length");
            pipe.read(packet.data(),size);
            if (!validWindowsIPv4Packet(packet.data(),size,mtu))
                throw std::system_error(ERROR_INVALID_DATA,std::system_category(),"invalid helper IPv4 packet");
            device.write(packet.data(),size);
        }
    } catch (...) { stop(); }
    outgoing.join();
    try { std::rethrow_exception(error); } catch (const std::system_error &failure) {
        if (failure.code().value()!=ERROR_BROKEN_PIPE && failure.code().value()!=ERROR_NO_DATA) throw;
    }
}
