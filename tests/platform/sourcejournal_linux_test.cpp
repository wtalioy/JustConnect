#include "infrastructure/platform/linux/sourcejournal.h"
#include "infrastructure/platform/linux/ownedroutetable.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static int failSync = -1;
static bool createBeforePublish = false;
static const QByteArray publicationConflict("external-before-publish");
extern "C" int __real_renameat2(int oldDirectory, const char *oldName, int newDirectory, const char *newName, unsigned flags);
extern "C" int __wrap_renameat2(int oldDirectory, const char *oldName, int newDirectory, const char *newName, unsigned flags)
{
    if (createBeforePublish) {
        createBeforePublish = false;
        const int fd = ::openat(newDirectory,newName,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0600);
        check(fd>=0 && ::write(fd,publicationConflict.constData(),size_t(publicationConflict.size()))==publicationConflict.size(),
              "Insert actual concurrent publication conflict");
        ::close(fd);
    }
    return __real_renameat2(oldDirectory,oldName,newDirectory,newName,flags);
}
extern "C" int __real_fsync(int fd);
extern "C" int __wrap_fsync(int fd)
{
    if (failSync==0) { failSync=-1;errno=EIO;return -1; }
    if (failSync>0) --failSync;
    return __real_fsync(fd);
}
static QByteArray bytes(const QString &path)
{
    QFile file(path);check(file.open(QIODevice::ReadOnly),"Read real journal bytes");return file.readAll();
}
static void put(const QString &path, const QByteArray &value)
{
    QFile file(path);check(file.open(QIODevice::WriteOnly|QIODevice::Truncate),"Write owned external-change fixture");
    check(file.write(value)==value.size(),"Write complete external-change fixture");file.close();
    check(::chmod(QFile::encodeName(path).constData(),0600)==0,"Keep the fixture private");
}
int main(int argc, char **argv) try
{
    QCoreApplication app(argc,argv);
    QTemporaryDir temporary;check(temporary.isValid(),"Create private journal fixture directory");
    const auto directoryName = QFile::encodeName(temporary.path());
    const int directory = ::open(directoryName.constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    check(directory>=0,"Open the private directory descriptor");
    const auto owner = QUuid::createUuid();
    const auto file = temporary.filePath("source.json");
    LinuxSourceJournal journal;
    if (argc==1) {
        check(::geteuid()!=0 && journal.open(directory,owner).status==PlatformOperationResult::Status::PermissionDenied
              && !QFile::exists(file),"Ordinary caller gained privileged journal authority or created a file");
        ::close(directory);return 0;
    }
    struct stat current{}, initial{};
    check(argc==2 && app.arguments()[1]=="--isolated" && ::geteuid()==0 && ::stat("/proc/self/ns/net",&current)==0
          && ::stat("/proc/1/ns/net",&initial)==0 && (current.st_dev!=initial.st_dev || current.st_ino!=initial.st_ino),
          "Refusing the host namespace or unguarded journal mode");
    bool alreadyOwned = true;
    check(::chmod(directoryName.constData(),0755)==0 && !journal.open(directory,owner,&alreadyOwned).succeeded() && !alreadyOwned,
          "An unsafe directory was accepted or misclassified as a live guardian");
    check(::chmod(directoryName.constData(),0700)==0,"Restore private directory permissions");
    const int workingDirectory = ::open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    check(workingDirectory>=0 && ::fchdir(directory)==0 && !journal.open(AT_FDCWD,owner).succeeded(),
          "Implicit current-directory authority replaced an explicit directory descriptor");
    check(::fchdir(workingDirectory)==0,"Restore the fixture working directory");::close(workingDirectory);
    check(journal.open(directory,owner).succeeded(),"Open root-owned private journal");
    LinuxSourceJournal other;
    check(!other.open(directory,owner,&alreadyOwned).succeeded() && alreadyOwned,"Independent guardians acquired the same directory lock or lost contention classification");
    const QJsonObject first{{"owner",owner.toString(QUuid::WithoutBraces)},{"state",1}};
    auto second = first;second["state"] = 2;
    createBeforePublish = true;
    check(!journal.store(first).succeeded() && bytes(file)==publicationConflict
          && !journal.remove().succeeded() && QDir(temporary.path()).entryList({"*.tmp"},QDir::Files).isEmpty(),
          "First publication overwrote a concurrently created foreign record or left its temporary");
    check(QFile::remove(file),"Remove the owned conflict fixture");
    check(journal.store(first).succeeded(),"Publish the first source checkpoint");
    const auto original = bytes(file);
    struct stat info{};
    check(::lstat(QFile::encodeName(file).constData(),&info)==0 && info.st_uid==0 && (info.st_mode&07777)==0600 && info.st_nlink==1,
          "Published journal has unsafe ownership, permissions or links");
    QJsonObject loaded;
    check(journal.load(loaded).succeeded() && loaded==first,"Load complete real ownership record");
    journal.close();
    const auto wrongOwner = QUuid::createUuid();auto foreign = second;foreign["owner"] = wrongOwner.toString(QUuid::WithoutBraces);
    check(other.open(directory,wrongOwner).succeeded() && !other.load(loaded).succeeded() && loaded.isEmpty()
          && !other.store(foreign).succeeded() && !other.remove().succeeded() && bytes(file)==original,
          "Another connection adopted, replaced or removed the root-private record");
    other.close();
    check(journal.open(directory,owner).succeeded() && journal.load(loaded).succeeded(),"Reload the original connection's checkpoint");
    failSync = 0;
    check(!journal.store(second).succeeded() && bytes(file)==original
          && QDir(temporary.path()).entryList({"*.tmp"},QDir::Files).isEmpty(),"Checkpoint fsync failure replaced the old record or leaked its temporary");
    failSync = 1;
    const auto published = journal.store(second);
    check(!published.succeeded() && published.mayHaveChanged && QJsonDocument::fromJson(bytes(file)).object()==second,
          "Post-publication sync failure hid the possibly installed record");
    check(journal.store(second).succeeded(),"Retry synchronization of the installed checkpoint");
    put(file,QJsonDocument(first).toJson(QJsonDocument::Compact));
    const auto external = bytes(file);
    check(!journal.load(loaded).succeeded() && loaded.isEmpty() && !journal.store(second).succeeded()
          && !journal.remove().succeeded() && bytes(file)==external,"External journal bytes were adopted, overwritten or removed");
    journal.close();
    check(journal.open(directory,owner).succeeded() && journal.load(loaded).succeeded() && loaded==first,"Explicit fresh journal owner cannot load its authenticated file");
    const auto replacement = temporary.filePath("replacement");
    put(replacement,external);
    check(::rename(QFile::encodeName(replacement).constData(),QFile::encodeName(file).constData())==0,"Replace fixture inode with identical bytes");
    check(!journal.remove().succeeded() && !journal.store(second).succeeded() && bytes(file)==external,
          "Same-value external inode replacement was adopted");
    journal.close();
    check(journal.open(directory,owner).succeeded() && journal.load(loaded).succeeded(),"Reload the explicitly accepted replacement fixture");
    check(::chmod(QFile::encodeName(file).constData(),0644)==0 && !journal.load(loaded).succeeded() && loaded.isEmpty()
          && !journal.remove().succeeded(),"Nonprivate journal file was read or removed");
    check(::chmod(QFile::encodeName(file).constData(),0600)==0,"Restore fixture permissions");
    const auto link = temporary.filePath("linked");
    check(::link(QFile::encodeName(file).constData(),QFile::encodeName(link).constData())==0
          && !journal.load(loaded).succeeded() && !journal.remove().succeeded(),"Multiply linked record was accepted");
    check(QFile::remove(link) && journal.remove().succeeded(),"Remove only the accepted fixture record");
    put(replacement,external);
    check(::symlink(QFile::encodeName(replacement).constData(),QFile::encodeName(file).constData())==0
          && !journal.load(loaded).succeeded() && !journal.store(second).succeeded() && !journal.remove().succeeded()
          && bytes(replacement)==external,"Symlink journal redirected reading, replacement or removal");
    check(QFile::remove(file) && QFile::remove(replacement),"Remove owned symlink fixtures");
    const auto corrupt = QByteArray("{\"owner\":\"")+owner.toString(QUuid::WithoutBraces).toLatin1()+"\",\"state\":\""+QByteArray(1,char(0xff))+"\"}";
    put(file,corrupt);journal.close();
    check(journal.open(directory,owner).succeeded() && !journal.load(loaded).succeeded() && loaded.isEmpty()
          && !journal.store(second).succeeded() && !journal.remove().succeeded() && bytes(file)==corrupt,
          "Corrupt UTF-8 ownership was accepted, overwritten or removed during a fresh load");
    check(QFile::remove(file),"Remove the owned corrupt-input fixture");
    put(file,QByteArray(LinuxOwnedRouteTable::MaxSnapshotBytes+1,'x'));
    check(!journal.load(loaded).succeeded() && loaded.isEmpty() && !journal.store(second).succeeded()
          && !journal.remove().succeeded(),"Oversized journal was loaded, replaced or removed");
    check(QFile::remove(file),"Remove the owned oversized fixture");
    check(journal.store(second).succeeded(),"Store final cleanup checkpoint");
    failSync = 0;
    check(!journal.remove().succeeded() && !QFile::exists(file),"Removal sync failure was hidden");
    put(file,QJsonDocument(second).toJson(QJsonDocument::Compact));
    check(!journal.load(loaded).succeeded() && !journal.remove().succeeded() && !journal.store(first).succeeded(),
          "A same-value record recreated after confirmed unlink was adopted");
    check(QFile::remove(file),"Remove the owned recreation fixture");
    check(journal.remove().succeeded() && journal.remove().succeeded(),"Removal sync failure could not be retried idempotently");
    journal.close();
    check(other.open(directory,owner).succeeded(),"Closing the journal retained its guardian lock");other.close();
    ::close(directory);
    std::cout << "PASS: root-private source journal, exclusive ownership, atomic checkpoints, sync failures/retries and external file preservation\n";
    return 0;
} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
