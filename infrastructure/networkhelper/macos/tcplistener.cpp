#include "infrastructure/networkhelper/macos/networkhelper.h"
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <vector>

bool macOwnsLoopbackTCPListener(int pid, quint16 port, quint32 ipv4)
{
    if (pid <= 0 || port == 0 || (ipv4 && (ipv4 >> 24) != 127)) return false;
    constexpr int maxBytes = 1024*1024;
    const auto length = proc_pidinfo(pid,PROC_PIDLISTFDS,0,nullptr,0);
    if (length <= 0 || length > maxBytes) return false;
    std::vector<proc_fdinfo> descriptors(size_t(length)/sizeof(proc_fdinfo)+1);
    const auto capacity = int(descriptors.size()*sizeof(proc_fdinfo));
    const auto bytes = proc_pidinfo(pid,PROC_PIDLISTFDS,0,descriptors.data(),capacity);
    if (bytes <= 0 || bytes >= capacity || bytes%sizeof(proc_fdinfo) != 0) return false;
    descriptors.resize(size_t(bytes)/sizeof(proc_fdinfo));
    for (const auto &fd : descriptors) {
        if (fd.proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        socket_fdinfo socket{};
        if (proc_pidfdinfo(pid,fd.proc_fd,PROC_PIDFDSOCKETINFO,&socket,sizeof(socket)) != sizeof(socket)
            || socket.psi.soi_kind != SOCKINFO_TCP) continue;
        const auto &tcp = socket.psi.soi_proto.pri_tcp;
        const auto &ip = tcp.tcpsi_ini;
        if (tcp.tcpsi_state != TSI_S_LISTEN || ntohs(uint16_t(ip.insi_lport)) != port) continue;
        if (!ipv4) {
            const auto &address = ip.insi_laddr.ina_6;
            if ((ip.insi_vflag&INI_IPV6) && (IN6_IS_ADDR_LOOPBACK(&address) || IN6_IS_ADDR_UNSPECIFIED(&address))) return true;
        } else {
            const auto address = ip.insi_laddr.ina_46.i46a_addr4.s_addr;
            if ((ip.insi_vflag&INI_IPV4) && (address == htonl(ipv4) || address == INADDR_ANY)) return true;
        }
    }
    return false;
}
