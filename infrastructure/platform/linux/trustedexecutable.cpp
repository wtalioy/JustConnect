#include "trustedexecutable.h"
#include <QByteArray>
#include <QList>
#include <QScopeGuard>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

bool trustedLinuxExecutable(const char *path, bool setuidAllowed)
{
    const auto parts = QByteArray(path).split('/');
    int directory = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return false;
    const auto close = qScopeGuard([&] { ::close(directory); });
    struct stat root{};
    if (::fstat(directory, &root) != 0 || root.st_uid != 0 || (root.st_mode & 07022)) return false;
    for (int index = 1; index < parts.size(); ++index) {
        const bool last = index == parts.size() - 1;
        if (parts[index].isEmpty() || parts[index] == "." || parts[index] == "..") return false;
        const int fd = ::openat(directory, parts[index].constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (last ? 0 : O_DIRECTORY));
        if (fd < 0) return false;
        struct stat value{};
        const bool valid = ::fstat(fd, &value) == 0 && value.st_uid == 0
            && !(value.st_mode & (setuidAllowed && last ? 03022 : 07022))
            && (last ? S_ISREG(value.st_mode) && (value.st_mode & S_IXUSR) : S_ISDIR(value.st_mode));
        if (valid && last) {
            char magic[4]{};
            const bool elf = ::read(fd, magic, sizeof(magic)) == sizeof(magic) && std::memcmp(magic, "\177ELF", 4) == 0;
            ::close(fd); return elf;
        }
        if (!valid) { ::close(fd); return false; }
        ::close(directory); directory = fd;
    }
    return false;
}

