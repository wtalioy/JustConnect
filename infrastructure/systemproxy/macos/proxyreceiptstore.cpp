#include "infrastructure/systemproxy/macos/proxyreceiptstore.h"
#include <QFile>
#include <QSaveFile>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using Status = CredentialStatus;
}

MacProxyReceiptStore::MacProxyReceiptStore(const QString &directory)
{
    struct stat info{};
    const auto base = QFile::encodeName(directory);
    if (::lstat(base.constData(),&info)!=0 || !S_ISDIR(info.st_mode)
        || info.st_uid!=geteuid() || (info.st_mode&0022)) return;
    const auto parent = directory + "/proxy-recovery";
    const auto name = QFile::encodeName(parent);
    if (::mkdir(name.constData(),0700)!=0 && errno!=EEXIST) return;
    if (::lstat(name.constData(),&info)==0 && S_ISDIR(info.st_mode)
        && info.st_uid==geteuid() && (info.st_mode&07777)==0700)
        path = parent + "/receipt";
}

CredentialResult MacProxyReceiptStore::read(const QString &key)
{
    if (!validKey(key)) return {Status::InvalidArgument,{}};
    if (path.isEmpty()) return {Status::Unavailable,{}};
    const auto fd = ::open(QFile::encodeName(path).constData(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if (fd<0) return {errno==ENOENT ? Status::NotFound : Status::Failed,{},errno};
    QFile file;
    if (!file.open(fd,QIODevice::ReadOnly,QFileDevice::AutoCloseHandle)) {
        ::close(fd);
        return {Status::Failed,{}};
    }
    struct stat info{};
    if (::fstat(fd,&info)!=0 || !S_ISREG(info.st_mode) || info.st_uid!=geteuid()
        || info.st_nlink!=1 || (info.st_mode&07777)!=0600 || info.st_size<0)
        return {Status::Failed,{}};
    if (info.st_size>MaxBytes) return {Status::Limit,{}};
    const auto bytes = file.read(MaxBytes+1);
    if (bytes.size()!=info.st_size || file.error()!=QFileDevice::NoError) return {Status::Failed,{}};
    return {Status::Success,bytes};
}

CredentialResult MacProxyReceiptStore::write(const QString &key, const QByteArray &value)
{
    if (!validKey(key)) return {Status::InvalidArgument,{}};
    if (path.isEmpty()) return {Status::Unavailable,{}};
    if (value.size()>MaxBytes) return {Status::Limit,{}};
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || !file.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner)
        || file.write(value)!=value.size() || !file.commit())
        return {Status::Failed,{}};
    return {Status::Success,{}};
}

CredentialResult MacProxyReceiptStore::remove(const QString &key)
{
    if (!validKey(key)) return {Status::InvalidArgument,{}};
    if (path.isEmpty()) return {Status::Unavailable,{}};
    if (::unlink(QFile::encodeName(path).constData())==0) return {Status::Success,{}};
    return {errno==ENOENT ? Status::NotFound : Status::Failed,{},errno};
}
