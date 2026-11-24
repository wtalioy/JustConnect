#include "infrastructure/update/updateinstaller.h"
#include "infrastructure/update/updatepackage.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QScopeGuard>
#include <QSettings>
#include <QTemporaryDir>
#include <stdio.h>

namespace {
QFileInfo installedBundle()
{
    QDir macos(QCoreApplication::applicationDirPath());
    if (macos.dirName()!="MacOS" || !macos.cdUp() || macos.dirName()!="Contents" || !macos.cdUp()) return {};
    const QFileInfo bundle(macos.absolutePath());
    if (!bundle.isDir() || bundle.suffix()!="app" || bundle.isSymLink() || !QFileInfo(macos.absolutePath()+"/..").isWritable())
        return {};
    return bundle;
}

QString bundleIdentity(const QString &bundle)
{
    return QSettings(bundle+"/Contents/Info.plist",QSettings::NativeFormat).value("CFBundleIdentifier").toString();
}
}

namespace UpdateInstaller {
QString assetSuffix()
{
    if (!installedBundle().exists()) return {};
#if defined(Q_PROCESSOR_ARM_64)
    return "macos-arm64.dmg";
#elif defined(Q_PROCESSOR_X86_64)
    return "macos-x64.dmg";
#else
    return {};
#endif
}

bool installPackage(const UpdatePackage &package,const QString &path)
{
    const auto bundle=installedBundle();
    if (!bundle.exists()) return false;
    QFile image(path);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!image.open(QIODevice::ReadOnly) || image.size()!=package.size
        || !hash.addData(&image) || !package.matches(image.pos(),hash.result())) return false;
    image.close();

    QTemporaryDir mount;
    if (!mount.isValid() || QProcess::execute("/usr/bin/hdiutil",
            {"attach","-readonly","-nobrowse","-mountpoint",mount.path(),path})!=0) return false;
    const auto detach=qScopeGuard([&] { QProcess::execute("/usr/bin/hdiutil",{"detach",mount.path()}); });
    const auto source=mount.filePath("JustConnect.app");
    if (!QFileInfo(source).isDir() || QFileInfo(source).isSymLink()) return false;
    QSettings metadata(source+"/Contents/Info.plist",QSettings::NativeFormat);
    const auto identity=bundleIdentity(bundle.absoluteFilePath());
    if (identity.isEmpty() || metadata.value("CFBundleIdentifier").toString()!=identity
        || metadata.value("CFBundleShortVersionString").toString()!=package.version) return false;

    QTemporaryDir replacement(bundle.dir().filePath(".justconnect-update-XXXXXX"));
    if (!replacement.isValid()) return false;
    const auto staged=replacement.filePath("JustConnect.app");
    if (QProcess::execute("/usr/bin/ditto",{source,staged})!=0 || QProcess::execute("/usr/bin/codesign",
            {"--verify","--deep","--strict","--all-architectures",staged})!=0) return false;
    // Staging beside the installed bundle keeps the exchange on the same volume.
    return renamex_np(QFile::encodeName(staged).constData(),QFile::encodeName(bundle.absoluteFilePath()).constData(),
        RENAME_SWAP)==0;
}

bool reopen(bool updateSucceeded)
{
    const auto bundle=installedBundle();
    if (!bundle.exists()) return false;
    QStringList arguments{"-n",bundle.absoluteFilePath()};
    if (!updateSucceeded) arguments.append({"--args",FailedOption});
    return QProcess::startDetached("/usr/bin/open",arguments);
}
}
