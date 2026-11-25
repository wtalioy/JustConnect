#include "infrastructure/update/updateinstaller.h"
#include "infrastructure/update/updatepackage.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QScopeGuard>
#include <QSettings>
#include <windows.h>

QString UpdateInstaller::assetSuffix()
{
    const QSettings uninstall("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\JustConnect_is1",
        QSettings::Registry32Format);
    const auto location=uninstall.value("Inno Setup: App Path").toString();
    if (location.isEmpty()) return {};
    const auto installed=QDir(location).canonicalPath();
    const auto running=QDir(QCoreApplication::applicationDirPath()).canonicalPath();
    if (installed.isEmpty() || installed.compare(running,Qt::CaseInsensitive)!=0) return {};
#if defined(Q_PROCESSOR_ARM_64)
    return "windows-arm64-setup.exe";
#elif defined(Q_PROCESSOR_X86_64)
    return "windows-x64-setup.exe";
#else
    return {};
#endif
}

bool UpdateInstaller::launch(const UpdatePackage &package,const QString &path)
{
    if (assetSuffix().isEmpty()) return false;
    const auto nativePath=QDir::toNativeSeparators(path).toStdWString();
    // Deny writes and replacement between the final checksum and CreateProcess.
    const auto handle=CreateFileW(nativePath.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if (handle==INVALID_HANDLE_VALUE) return false;
    const auto closeArchive=qScopeGuard([handle] { CloseHandle(handle); });
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 size=0;
    QByteArray buffer(128*1024,Qt::Uninitialized);
    for (;;) {
        DWORD count=0;
        if (!ReadFile(handle,buffer.data(),DWORD(buffer.size()),&count,nullptr) || count>package.size-size) return false;
        if (!count) break;
        size+=count;
        hash.addData(QByteArrayView(buffer.constData(),count));
    }
    if (!package.matches(size,hash.result())) return false;
    return QProcess::startDetached(path,{
        "/SILENT","/NORESTART","/NOCLOSEAPPLICATIONS",
        "/DIR="+QCoreApplication::applicationDirPath(),
        "/JCUPDATEPID="+QString::number(QCoreApplication::applicationPid())
    },QDir::tempPath());
}

void UpdateInstaller::removeStagedInstaller(const QString &path)
{
    const QFileInfo file(path);
    const QFileInfo directory(file.absolutePath());
    static const QRegularExpression stagingName(QStringLiteral("\\AJustConnect-update-[a-zA-Z0-9]{6}\\z"));
    static const QRegularExpression packageName(QStringLiteral("\\AJustConnect-v[0-9.]+-windows-(x64|arm64)-setup\\.exe\\z"));
    if (!file.isFile() || file.isSymLink() || directory.isSymLink() || directory.isJunction()
        || directory.dir().canonicalPath().compare(QDir::temp().canonicalPath(),Qt::CaseInsensitive)!=0
        || !stagingName.match(directory.fileName()).hasMatch() || !packageName.match(file.fileName()).hasMatch()) return;
    if (QFile::remove(file.absoluteFilePath())) QDir().rmdir(directory.absoluteFilePath());
}
