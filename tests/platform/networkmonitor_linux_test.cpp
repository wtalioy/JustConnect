#include "infrastructure/networkaccess/linux/networkmonitor.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QTemporaryDir>
#include <QTimer>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

// The monitor's test seam is a connected datagram socket that stands in for the
// netlink route socket, so the coalescing behavior is verifiable without any
// kernel network activity.
namespace {
void check(bool okay, const char *message) { if (!okay) throw std::runtime_error(message); }

void pump(QEventLoop &loop, int milliseconds)
{
    QTimer::singleShot(milliseconds, &loop, &QEventLoop::quit);
    loop.exec();
}

void writeFile(const std::filesystem::path &path, const char *content)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << content;
    if (!file) throw std::runtime_error("resolver write failed");
}

// Replaces the file exactly like a resolver swap does: write a sibling and
// rename it over the watched path, deleting the watched inode.
void replaceFile(const std::filesystem::path &path, const char *content)
{
    const auto temporary = path.parent_path() / (path.filename().string() + ".swap");
    writeFile(temporary, content);
    std::filesystem::rename(temporary, path);
}
}

int main(int argc, char **argv) try {
    QCoreApplication app(argc, argv);
    QTemporaryDir directory;
    check(directory.isValid(), "Cannot create a temporary resolver directory");
    const QString resolverPath = directory.filePath("resolv.conf");
    const std::filesystem::path resolver{resolverPath.toStdString()};
    writeFile(resolver, "nameserver 192.0.2.1\n");
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) throw std::runtime_error("socketpair failed");

    LinuxNetworkMonitor monitor(fds[0], nullptr, {resolverPath});
    QEventLoop loop;
    int changes = 0;
    QObject::connect(&monitor, &LinuxNetworkMonitor::networkChanged, [&] { ++changes; });
    pump(loop, 600);
    check(changes == 0, "Idle monitor requested a network refresh");

    // Each burst should request one refresh, even after the first report.
    for (int burst = 1; burst <= 2; ++burst) {
        for (int event = 0; event < 8; ++event) {
            if (::write(fds[1], "x", 1) != 1) throw std::runtime_error("event write failed");
        }
        pump(loop, 700);
        check(changes == burst, "Event burst did not coalesce into one refresh request");
    }

    changes = 0;
    writeFile(resolver, "nameserver 192.0.2.2\n");
    pump(loop, 700);
    check(changes == 1, "An edited resolver file did not request a refresh");

    replaceFile(resolver, "nameserver 192.0.2.3\n");
    pump(loop, 700);
    check(changes == 2, "A replaced resolver file did not request a refresh");

    // An edit to the replacement proves the file watch was re-armed.
    writeFile(resolver, "nameserver 192.0.2.4\n");
    pump(loop, 700);
    check(changes == 3, "The watch was lost after the resolver swap");

    ::close(fds[1]);
    std::cout << "networkmonitor_linux_test passed" << std::endl;
    return 0;
} catch (const std::exception &error) {
    std::cerr << "FAILED: " << error.what() << std::endl;
    return 1;
}
