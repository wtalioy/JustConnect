#include "infrastructure/networkhelper/macos/networkhelper.h"
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <vector>

namespace {
bool matchesListener(int pid, int fd, quint16 port, quint32 ipv4)
{
    socket_fdinfo socket{};
    if (proc_pidfdinfo(pid,fd,PROC_PIDFDSOCKETINFO,&socket,sizeof(socket)) != sizeof(socket)
        || socket.psi.soi_kind != SOCKINFO_TCP) return false;
    const auto &tcp = socket.psi.soi_proto.pri_tcp;
    const auto &ip = tcp.tcpsi_ini;
    if (tcp.tcpsi_state != TSI_S_LISTEN || ntohs(uint16_t(ip.insi_lport)) != port) return false;
    if (!ipv4) {
        const auto &address = ip.insi_laddr.ina_6;
        return (ip.insi_vflag&INI_IPV6) && (IN6_IS_ADDR_LOOPBACK(&address) || IN6_IS_ADDR_UNSPECIFIED(&address));
    }
    const auto address = ip.insi_laddr.ina_46.i46a_addr4.s_addr;
    return (ip.insi_vflag&INI_IPV4) && (address == htonl(ipv4) || address == INADDR_ANY);
}
}

bool macOwnsLoopbackTCPListener(int pid, quint16 port, quint32 ipv4)
{
    if (pid <= 0 || port == 0 || (ipv4 && (ipv4 >> 24) != 127)) return false;
    // Re-read the last descriptor from the kernel on every query. Never cache a positive verdict.
    struct Candidate { int pid = 0, fd = -1; };
    thread_local Candidate last;
    if (last.pid == pid && matchesListener(pid,last.fd,port,ipv4)) return true;
    constexpr int maxBytes = 1024*1024;
    const auto length = proc_pidinfo(pid,PROC_PIDLISTFDS,0,nullptr,0);
    if (length <= 0 || length > maxBytes) return false;
    std::vector<proc_fdinfo> descriptors(size_t(length)/sizeof(proc_fdinfo)+1);
    const auto capacity = int(descriptors.size()*sizeof(proc_fdinfo));
    const auto bytes = proc_pidinfo(pid,PROC_PIDLISTFDS,0,descriptors.data(),capacity);
    if (bytes <= 0 || bytes >= capacity || bytes%sizeof(proc_fdinfo) != 0) return false;
    descriptors.resize(size_t(bytes)/sizeof(proc_fdinfo));
    for (const auto &fd : descriptors)
        if (fd.proc_fdtype == PROX_FDTYPE_SOCKET && matchesListener(pid,fd.proc_fd,port,ipv4)) {
            last = {pid,fd.proc_fd};
            return true;
        }
    return false;
}
