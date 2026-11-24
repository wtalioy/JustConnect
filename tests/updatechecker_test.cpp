#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDebug>
#include <QFile>
#include <QNetworkReply>
#include <QJsonArray>
#include <QJsonObject>

#include "infrastructure/update/updatechecker.h"
#include "application/applicationconstants.h"

#ifdef Q_OS_MACOS
namespace UpdateInstaller { bool installPackage(const UpdatePackage &,const QString &path); }
#elif defined(Q_OS_LINUX)
#include <QTemporaryFile>
#include <fcntl.h>
#include <unistd.h>
namespace UpdateInstaller { int sealPackage(const UpdatePackage &,const QString &path); }
#endif

namespace
{
bool coalescesChecksAndAllowsRetry()
{
    UpdateChecker checker;
    using State = VersionInfo::UpdateState;
    if (checker.versionInfo().updateState != State::Disabled)
        return false;

    int checks = 0;
    QObject::connect(&checker, &UpdateChecker::versionInfoChanged, &checker, [&](const VersionInfo &info) {
        if (info.updateState == State::Checking && ++checks == 1)
            checker.check();
    });
    for (int attempt = 1; attempt <= 2; ++attempt)
    {
        checker.check();
        checker.check();
        if (checks != attempt)
            return false;
        // Abort immediately; no server response is required.
        auto *reply = checker.findChild<QNetworkReply *>();
        if (!reply)
            return false;
        reply->abort();
        if (checker.versionInfo().updateState != State::Failed)
            return false;
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }
    return true;
}

bool validatesReleaseResponses()
{
    const std::optional<QString> version =
        UpdateChecker::parseReleaseVersion(R"({"tag_name":"v1.2.3"})");
    const bool passed =
        version == std::optional<QString>("1.2.3")
        && UpdateChecker::parseReleaseVersion(R"({"tag_name":"1.2.3"})") == version
        && !UpdateChecker::parseReleaseVersion("not json").has_value()
        && !UpdateChecker::parseReleaseVersion("{}").has_value()
        && !UpdateChecker::parseReleaseVersion(
            R"({"tag_name":""})"
        ).has_value()
        && !UpdateChecker::parseReleaseVersion(
            R"({"tag_name":42})"
        ).has_value();
    if (!passed)
    {
        qCritical() << "validatesReleaseResponses failed";
    }
    return passed;
}

bool comparesVersions()
{
    struct VersionComparison
    {
        QString current;
        QString latest;
        bool expected;
    };
    const QList<VersionComparison> comparisons{
        {"1.2.3", "1.2.4", true},
        {"1.2.3-beta", "1.2.3", true},
        {"1.2.3-pre.2", "1.2.3-pre.10", true},
        {"1.2.3", "1.2.3-hotfix", true},
        {"1.2.3-hotfix.2", "1.2.3-hotfix.10", true},
        {"1.2.3", "1.2.3", false},
        {"1.2.3", "1.2.3-beta", false},
        {"1.2.3-hotfix", "1.2.3", false},
        {"1.3.0", "1.2.9", false}
    };

    for (const VersionComparison &comparison : comparisons)
    {
        const bool actual = UpdateChecker::isNewerVersion(
            comparison.current,
            comparison.latest
        );
        if (actual != comparison.expected)
        {
            qCritical()
                << "comparesVersions failed:"
                << comparison.current
                << comparison.latest
                << "expected" << comparison.expected
                << "actual" << actual;
            return false;
        }
    }
    return true;
}

bool validatesInstallableAssets()
{
    const QByteArray contents("fixture bytes");
    const auto hash=QCryptographicHash::hash(contents,QCryptographicHash::Sha256);
    for (const QString suffix : {"windows-x64-setup.exe","windows-arm64-setup.exe","macos-x64.dmg","macos-arm64.dmg","linux-x64.deb"}) {
        const auto name="JustConnect-v1.2.3-"+suffix;
        const auto url="https://github.com/"+ApplicationConstants::RepositoryName+"/releases/download/v1.2.3/"+name;
        const QJsonObject asset{{"name",name},{"state","uploaded"},{"browser_download_url",url},
            {"digest","sha256:"+QString::fromLatin1(hash.toHex())},{"size",contents.size()}};
        const QJsonObject release{{"draft",false},{"prerelease",false},{"tag_name","v1.2.3"},{"assets",QJsonArray{asset}}};
        const auto package=UpdatePackage::fromRelease(release,suffix);
        if (!package || package->version!="1.2.3" || package->fileName!=name || !package->matches(contents.size(),hash)
            || package->matches(contents.size()-1,hash) || package->matches(contents.size(),QByteArray(32,'x'))) return false;
        for (const auto &invalid : {QJsonObject{{"digest",QString{}}}, QJsonObject{{"size",300*1024*1024}},
             QJsonObject{{"browser_download_url","https://example.invalid/file.exe"}}, QJsonObject{{"state","open"}}}) {
            auto invalidAsset=asset;
            for (auto it=invalid.begin();it!=invalid.end();++it) invalidAsset[it.key()]=it.value();
            auto response=release;
            response["assets"]=QJsonArray{invalidAsset};
            if (UpdatePackage::fromRelease(response,suffix)) return false;
        }
        auto ambiguous=release;
        ambiguous["assets"]=QJsonArray{asset,asset};
        if (UpdatePackage::fromRelease(ambiguous,suffix) || UpdatePackage::fromRelease(release,"wrong-package")) return false;
        auto draft=release;
        draft["draft"]=true;
        if (UpdatePackage::fromRelease(draft,suffix)) return false;
    }
    return UpdatePackage::isDownloadRedirect(QUrl("https://release-assets.githubusercontent.com/a?token=fixture"))
        && !UpdatePackage::isDownloadRedirect(QUrl("http://release-assets.githubusercontent.com/a"))
        && !UpdatePackage::isDownloadRedirect(QUrl("https://release-assets.githubusercontent.com.example.invalid/a"));
}

#ifdef Q_OS_LINUX
bool sealsVerifiedLinuxPackage()
{
    QTemporaryFile file;
    const QByteArray contents("package fixture");
    if (!file.open() || file.write(contents)!=contents.size() || !file.flush()) return false;
    UpdatePackage package{"1.2.3",{}, {},QCryptographicHash::hash(contents,QCryptographicHash::Sha256),contents.size()};
    const auto descriptor=UpdateInstaller::sealPackage(package,file.fileName());
    if (descriptor<0) return false;
    QFile sealed("/proc/self/fd/"+QString::number(descriptor));
    const int expectedSeals=F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;
    const int seals=fcntl(descriptor,F_GET_SEALS);
    const auto valid=sealed.open(QIODevice::ReadOnly) && sealed.readAll()==contents
        && seals>=0 && (seals & expectedSeals)==expectedSeals
        && pwrite(descriptor,"x",1,0)<0;
    close(descriptor);
    package.sha256[0]=char(package.sha256[0]^1);
    return valid && UpdateInstaller::sealPackage(package,file.fileName())<0;
}
#endif
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
#ifdef Q_OS_MACOS
    const auto arguments=app.arguments();
    if (arguments.size()==4 && arguments[1]=="--test-macos-dmg-update") {
        if (qEnvironmentVariable("GITHUB_ACTIONS")!="true") return 1;
        QFile image(arguments[2]);
        QCryptographicHash digest(QCryptographicHash::Sha256);
        if (!image.open(QIODevice::ReadOnly) || !digest.addData(&image)) return 1;
        const UpdatePackage package{arguments[3],{}, {},digest.result(),image.size()};
        return UpdateInstaller::installPackage(package,arguments[2]) ? 0 : 1;
    }
#endif
    if (!coalescesChecksAndAllowsRetry())
    {
        qCritical() << "Update checks did not coalesce or could not be retried after failure";
        return 1;
    }
    if (!validatesInstallableAssets()) {
        qCritical() << "Update package trust checks failed";
        return 1;
    }
#ifdef Q_OS_LINUX
    if (!sealsVerifiedLinuxPackage()) {
        qCritical() << "Verified Linux update bytes were not sealed";
        return 1;
    }
#endif
    return validatesReleaseResponses() && comparesVersions() ? 0 : 1;
}
