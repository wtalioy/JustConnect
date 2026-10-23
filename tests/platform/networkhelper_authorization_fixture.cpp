// Installed setuid only inside the test's private /usr and network namespaces.
#include "networkhelperpaths.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <grp.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const auto uid = ::getuid();
    struct stat current{}, initial{};
    if (::geteuid() != 0 || uid == 0 || argc != 5 || std::strcmp(argv[1], "--disable-internal-agent")
        || std::strcmp(argv[2], LinuxNetworkHelperPath)) return 1;
    for (const char *name : {"net", "mnt"}) {
        const auto here = std::string("/proc/thread-self/ns/") + name, host = std::string("/proc/1/ns/") + name;
        if (::stat(here.c_str(), &current) || ::stat(host.c_str(), &initial)
            || (current.st_dev == initial.st_dev && current.st_ino == initial.st_ino)) return 1;
    }
    const std::string mode = ::getenv("JC_AUTH_TEST_MODE") ? ::getenv("JC_AUTH_TEST_MODE") : "";
    if (mode == "deny") return 127;
    if (mode == "cancel") return 126;
    if (mode == "wait") { ::sleep(30); return 1; }
    if (::setgroups(0, nullptr) || ::setresgid(0, 0, 0) || ::setresuid(0, 0, 0)) return 1;
    if (mode == "malformed") {
        const int channel = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        const auto name = std::string("JustConnect.network.") + std::to_string(uid) + '.' + argv[3];
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        if (channel < 0 || name.size() >= sizeof(address.sun_path)) return 1;
        std::memcpy(address.sun_path + 1, name.c_str(), name.size());
        if (::connect(channel, reinterpret_cast<sockaddr *>(&address), offsetof(sockaddr_un, sun_path) + 1 + name.size())) return 1;
        char request[65536];
        if (::recv(channel, request, sizeof(request), 0) <= 0 || ::send(channel, "{}", 2, MSG_NOSIGNAL) != 2) return 1;
        ::close(channel); return 1;
    }
    if (mode != "allow") return 1;
    const auto original = std::to_string(uid);
    if (::setenv("PKEXEC_UID", original.c_str(), 1)) return 1;
    ::execl(LinuxNetworkHelperPath, LinuxNetworkHelperPath, argv[3], argv[4], nullptr);
    return 1;
}
