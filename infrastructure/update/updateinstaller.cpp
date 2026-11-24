#include "updateinstaller.h"

#include "application/applicationconstants.h"
#include "infrastructure/process/applicationinstancelock.h"
#include "updatechecker.h"
#include "updatepackage.h"
#include <QCoreApplication>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QProcess>
#include <QRegularExpression>
#include <QTimer>

namespace UpdateInstaller {
bool installPackage(const UpdatePackage &package,const QString &path);
bool reopen(bool updateSucceeded);
}

namespace {
std::optional<UpdatePackage> officialPackage(const QString &version,const QString &suffix)
{
    QNetworkAccessManager network;
    QNetworkRequest request(QUrl("https://api.github.com/repos/" + ApplicationConstants::RepositoryName
        + "/releases/tags/v" + version));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,QNetworkRequest::SameOriginRedirectPolicy);
    QEventLoop loop;
    auto *reply=network.get(request);
    QTimer::singleShot(15000,reply,&QNetworkReply::abort);
    QByteArray payload;
    const auto read=[&] {
        payload+=reply->readAll();
        if (payload.size()>1024*1024 && !reply->isFinished()) reply->abort();
    };
    reply->setReadBufferSize(64*1024);
    QObject::connect(reply,&QIODevice::readyRead,&loop,read);
    QObject::connect(reply,&QNetworkReply::finished,&loop,&QEventLoop::quit);
    loop.exec();
    read();
    if (reply->error()!=QNetworkReply::NoError || payload.size()>1024*1024
        || reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()!=200) return {};
    const auto package=UpdatePackage::fromRelease(QJsonDocument::fromJson(payload).object(),suffix);
    return package && package->version==version ? package : std::nullopt;
}
}

bool UpdateInstaller::launch(const UpdatePackage &package,const QString &path)
{
    if (assetSuffix().isEmpty()) return false;
    return QProcess::startDetached(QCoreApplication::applicationFilePath(),
        {WorkerOption,QFileInfo(path).absolutePath(),package.version},QDir::tempPath());
}

int UpdateInstaller::installAfterExit(const QStringList &arguments)
{
    if (arguments.size()!=4 || arguments[1]!=WorkerOption || !UpdatePackage::isReleaseVersion(arguments[3])
        || !UpdatePackage::isReleaseVersion(QCoreApplication::applicationVersion())
        || UpdateChecker::compareVersions(QCoreApplication::applicationVersion(),arguments[3])
            != UpdateChecker::CheckResult::UpdateAvailable) return 1;
    const auto suffix=assetSuffix();
    if (suffix.isEmpty()) return 1;
    const QFileInfo directory(arguments[2]);
    static const QRegularExpression stagingName(QStringLiteral("\\AJustConnect-update-[a-zA-Z0-9]{6}\\z"));
    if (!directory.isDir() || directory.isSymLink() || !stagingName.match(directory.fileName()).hasMatch()
        || directory.dir().canonicalPath()!=QDir::temp().canonicalPath()) return 1;
    bool installed=false;
    {
        const ApplicationInstanceLock lock(30000);
        if (lock.error()!=QLockFile::NoError) return 1;
        const auto package=officialPackage(arguments[3],suffix);
        // The stage owns a single expected asset. Never recursively remove a path supplied on the command line.
        const auto path=QDir(directory.absoluteFilePath()).filePath("JustConnect-v"+arguments[3]+'-'+suffix);
        const QFileInfo file(path);
        if (package && file.isFile() && !file.isSymLink() && file.size()==package->size) installed=installPackage(*package,path);
        QFile::remove(path);
        QDir().rmdir(directory.absoluteFilePath());
    }
    return reopen(installed) && installed ? 0 : 1;
}
