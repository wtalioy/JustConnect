#include "infrastructure/networkjournal/networkjournal.h"
#include <QJsonDocument>
#include <QScopeGuard>
#include <cerrno>
#include <fcntl.h>
#ifdef Q_OS_LINUX
#include <linux/fs.h>
#endif
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using Status = PlatformOperationResult::Status;
// Preserve the fixed filename used by existing Linux recovery records.
constexpr auto filename = "source.json";
PlatformOperationResult failed(const char *detail, bool changed = false)
{
    return {errno==EACCES || errno==EPERM ? Status::PermissionDenied : Status::Failed,QString::fromLatin1(detail),changed};
}
bool privateFile(const struct stat &value)
{
    return S_ISREG(value.st_mode) && value.st_uid==0 && (value.st_mode&07777)==0600 && value.st_nlink==1;
}
}

int openPrivateNetworkDirectory(int parent, const QByteArray &component, bool create)
{
    if (::geteuid() != 0) { errno = EPERM; return -1; }
    struct stat base{};
    if (parent < 0 || component.isEmpty() || component == "." || component == ".." || component.contains('/') || component.contains('\0')
        || ::fstat(parent,&base) != 0 || !S_ISDIR(base.st_mode) || base.st_uid != 0 || (base.st_mode & 0022)) { errno = EINVAL; return -1; }
    if (create && ::mkdirat(parent,component.constData(),0700) != 0 && errno != EEXIST) return -1;
    const int child = ::openat(parent,component.constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (child < 0) return -1;
    struct stat info{};
    if (::fstat(child,&info) != 0 || !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 07777) != 0700 || ::fsync(parent) != 0) {
        ::close(child); errno = EINVAL; return -1;
    }
    return child;
}

UnixNetworkJournal::~UnixNetworkJournal() { close(); }
void UnixNetworkJournal::close()
{
    if (directory>=0) ::close(directory);
    directory = -1;owner = {};known = {};bound = false;
}
PlatformOperationResult UnixNetworkJournal::open(int trustedDirectory, const QUuid &id, bool *alreadyOwned)
{
    if (alreadyOwned) *alreadyOwned = false;
    if (::geteuid()!=0) return {Status::PermissionDenied,"Source ownership journals require the privileged owner."};
    if (directory>=0 || trustedDirectory<0 || id.isNull()) return {Status::Failed,"A private directory descriptor and inactive journal owner are required."};
    // A new open description gives each guardian an independent lock, even for the same supplied fd.
    const int fd = ::openat(trustedDirectory,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return failed("Cannot open the source journal directory.");
    struct stat info{};
    if (::fstat(fd,&info)!=0 || !S_ISDIR(info.st_mode) || info.st_uid!=0 || (info.st_mode&07777)!=0700) {
        ::close(fd);return {Status::Failed,"Source journal directory must be root-owned and private."};
    }
    if (::flock(fd,LOCK_EX|LOCK_NB)!=0) {
        if (alreadyOwned) *alreadyOwned = errno == EWOULDBLOCK || errno == EAGAIN;
        const auto result=failed("Source journal is already owned or cannot be locked.");::close(fd);return result;
    }
    directory = fd;owner = id;
    return {};
}
PlatformOperationResult UnixNetworkJournal::read(SavedFile &file) const
{
    if (directory<0) return {Status::Failed,"Source journal is not open."};
    const int fd = ::openat(directory,filename,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if (fd<0) return errno==ENOENT ? PlatformOperationResult{} : failed("Cannot open the saved source ownership.");
    const auto release = qScopeGuard([&] { ::close(fd); });
    struct stat info{};
    if (::fstat(fd,&info)!=0 || !privateFile(info) || info.st_size<0 || info.st_size>NetworkJournalMaxBytes)
        return {Status::Failed,"Saved source ownership has unsafe metadata or exceeds its budget."};
    QByteArray bytes;
    char buffer[16384];
    while (bytes.size()<=NetworkJournalMaxBytes) {
        const auto count = ::read(fd,buffer,sizeof(buffer));
        if (count<0) { if (errno==EINTR) continue;return failed("Cannot read saved source ownership."); }
        if (count==0) break;
        bytes.append(buffer,qsizetype(count));
    }
    struct stat after{}, named{};
    if (::fstat(fd,&after)!=0 || ::fstatat(directory,filename,&named,AT_SYMLINK_NOFOLLOW)!=0
        || !privateFile(after) || !privateFile(named) || named.st_dev!=info.st_dev || named.st_ino!=info.st_ino
        || bytes.size()>NetworkJournalMaxBytes
        || after.st_size!=bytes.size() || after.st_size!=info.st_size
        ||
#ifdef Q_OS_MACOS
        after.st_mtimespec.tv_sec!=info.st_mtimespec.tv_sec || after.st_mtimespec.tv_nsec!=info.st_mtimespec.tv_nsec
        || after.st_ctimespec.tv_sec!=info.st_ctimespec.tv_sec || after.st_ctimespec.tv_nsec!=info.st_ctimespec.tv_nsec
#else
        after.st_mtim.tv_sec!=info.st_mtim.tv_sec || after.st_mtim.tv_nsec!=info.st_mtim.tv_nsec
        || after.st_ctim.tv_sec!=info.st_ctim.tv_sec || after.st_ctim.tv_nsec!=info.st_ctim.tv_nsec
#endif
        )
        return {Status::Failed,"Saved source ownership changed during the read."};
    file = {bytes,quint64(info.st_dev),quint64(info.st_ino),true};
    return {};
}
bool UnixNetworkJournal::unchanged(const SavedFile &file) const
{
    return file.present==known.present && (!file.present || (file.device==known.device && file.inode==known.inode && file.bytes==known.bytes));
}
PlatformOperationResult UnixNetworkJournal::load(QJsonObject &record)
{
    record = {};
    SavedFile current;
    const auto result = read(current);
    if (!result.succeeded()) return result;
    if (!current.present || (bound && !unchanged(current))) return {Status::Failed,"Saved source ownership is absent or was externally replaced."};
    const auto parsed = QJsonDocument::fromJson(current.bytes);
    if (!parsed.isObject() || parsed.object()["owner"]!=owner.toString(QUuid::WithoutBraces))
        return {Status::Failed,"Saved source ownership does not match the privileged connection."};
    known = current;bound = true;record = parsed.object();
    return {};
}
PlatformOperationResult UnixNetworkJournal::store(const QJsonObject &record)
{
    if (record["owner"]!=owner.toString(QUuid::WithoutBraces) || owner.isNull()) return {Status::Failed,"Source journal owner does not match the record."};
    const auto bytes = QJsonDocument(record).toJson(QJsonDocument::Compact);
    if (bytes.size()>NetworkJournalMaxBytes) return {Status::Failed,"Source ownership record exceeds its budget."};
    SavedFile current;
    const auto result = read(current);
    if (!result.succeeded()) return result;
    if (!unchanged(current)) return {Status::Failed,"Existing or externally changed source ownership cannot be overwritten."};
    const auto temporary = ("source-"+QUuid::createUuid().toString(QUuid::WithoutBraces)+".tmp").toLatin1();
    const int fd = ::openat(directory,temporary.constData(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (fd<0) return failed("Cannot create a private source ownership checkpoint.");
    struct stat info{};
    bool verified = false, published = false;
    const auto release = qScopeGuard([&] {
        struct stat leftover{};
        if (!published && verified && ::fstatat(directory,temporary.constData(),&leftover,AT_SYMLINK_NOFOLLOW)==0
            && privateFile(leftover) && leftover.st_dev==info.st_dev && leftover.st_ino==info.st_ino)
            ::unlinkat(directory,temporary.constData(),0);
        ::close(fd);
    });
    if (::fstat(fd,&info)!=0 || !privateFile(info)) return {Status::Failed,"Cannot verify the private source checkpoint.",true};
    verified = true;
    qsizetype offset = 0;
    while (offset<bytes.size()) {
        const auto count = ::write(fd,bytes.constData()+offset,size_t(bytes.size()-offset));
        if (count<0 && errno==EINTR) continue;
        if (count<=0) return failed("Cannot write the complete source checkpoint.",true);
        offset += qsizetype(count);
    }
    if (::fsync(fd)!=0) return failed("Cannot synchronize the source checkpoint.",true);
    SavedFile beforeRename;
    const auto checked = read(beforeRename);
    if (!checked.succeeded()) return checked;
    if (!unchanged(beforeRename)) return {Status::Failed,"Source ownership changed before checkpoint publication.",true};
    int renamed;
    if (known.present) renamed = ::renameat(directory,temporary.constData(),directory,filename);
#ifdef Q_OS_MACOS
    else renamed = ::renameatx_np(directory,temporary.constData(),directory,filename,RENAME_EXCL);
#else
    else renamed = ::renameat2(directory,temporary.constData(),directory,filename,RENAME_NOREPLACE);
#endif
    if (renamed!=0) return failed("Cannot publish the source checkpoint.",true);
    published = true;
    known = {bytes,quint64(info.st_dev),quint64(info.st_ino),true};
    bound = true;
    if (::fsync(directory)!=0) return failed("Cannot synchronize the published source ownership.",true);
    return {Status::Success,{},true};
}
PlatformOperationResult UnixNetworkJournal::remove()
{
    SavedFile current;
    const auto result = read(current);
    if (!result.succeeded()) return result;
    if (!unchanged(current)) return {Status::Failed,"Externally changed source ownership cannot be removed."};
    if (current.present && ::unlinkat(directory,filename,0)!=0) return failed("Cannot remove restored source ownership.",true);
    known = {};
    bound = true;
    if (::fsync(directory)!=0) return failed("Cannot synchronize source ownership removal.",true);
    return {Status::Success,{},current.present};
}
