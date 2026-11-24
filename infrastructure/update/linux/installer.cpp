#include "infrastructure/update/updateinstaller.h"
#include "infrastructure/update/updatepackage.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QScopeGuard>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <unistd.h>

namespace UpdateInstaller {
QString assetSuffix()
{
#if defined(Q_PROCESSOR_X86_64)
    if (QCoreApplication::applicationFilePath()=="/usr/bin/JustConnect"
        && QFileInfo("/usr/bin/pkexec").isExecutable() && QFileInfo("/usr/bin/dpkg").isExecutable())
        return "linux-x64.deb";
#endif
    return {};
}

int sealPackage(const UpdatePackage &package,const QString &path)
{
    QFile source(path);
    if (!source.open(QIODevice::ReadOnly)) return -1;
    const auto descriptor=memfd_create("justconnect-update.deb",MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_NOEXEC_SEAL);
    if (descriptor<0) return -1;
    auto closeStage=qScopeGuard([descriptor] { close(descriptor); });
    QFile stage;
    if (!stage.open(descriptor,QIODevice::WriteOnly)) return -1;
    QCryptographicHash digest(QCryptographicHash::Sha256);
    qint64 copied=0;
    while (!source.atEnd()) {
        const auto block=source.read(128*1024);
        if (block.isEmpty() || block.size()>package.size-copied || stage.write(block)!=block.size()) return -1;
        digest.addData(block);
        copied+=block.size();
    }
    if (!stage.flush() || !package.matches(copied,digest.result())
        || fcntl(descriptor,F_ADD_SEALS,F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)<0) return -1;
    closeStage.dismiss();
    return descriptor;
}

bool installPackage(const UpdatePackage &package,const QString &path)
{
    const auto descriptor=sealPackage(package,path);
    if (descriptor<0) return false;
    const auto closeStage=qScopeGuard([descriptor] { close(descriptor); });
    // The elevated package manager opens these exact immutable bytes after authorization.
    const auto sealedPath="/proc/"+QString::number(QCoreApplication::applicationPid())+"/fd/"+QString::number(descriptor);
    return QProcess::execute("/usr/bin/pkexec",{"/usr/bin/dpkg","--install",sealedPath})==0;
}

bool reopen(bool updateSucceeded)
{
    return QProcess::startDetached(QCoreApplication::applicationFilePath(),
        updateSucceeded ? QStringList{} : QStringList{FailedOption});
}
}
