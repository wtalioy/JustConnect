#include "infrastructure/update/updatechecker.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSaveFile>
#include <QStringView>
#include <QTemporaryDir>
#include <QTimer>
#include <QVersionNumber>
#include <utility>

#include "application/applicationconstants.h"
#include "updateinstaller.h"

namespace
{
enum class VersionSuffixKind
{
    Prerelease,
    Stable,
    Hotfix
};

QString normalizedSuffix(const QString &version, qsizetype suffixIndex)
{
    QString suffix = version.mid(suffixIndex);
    while (!suffix.isEmpty() && QStringLiteral("-+_.").contains(suffix.front()))
    {
        suffix.removeFirst();
    }
    return suffix;
}

VersionSuffixKind suffixKind(const QString &suffix)
{
    if (suffix.isEmpty())
    {
        return VersionSuffixKind::Stable;
    }
    if (suffix.startsWith(QStringLiteral("hotfix"), Qt::CaseInsensitive))
    {
        return VersionSuffixKind::Hotfix;
    }
    return VersionSuffixKind::Prerelease;
}

int compareSuffixes(const QString &currentSuffix, const QString &latestSuffix)
{
    qsizetype currentIndex = 0;
    qsizetype latestIndex = 0;
    while (currentIndex < currentSuffix.size() &&
           latestIndex < latestSuffix.size())
    {
        const bool currentIsDigit = currentSuffix.at(currentIndex).isDigit();
        const bool latestIsDigit = latestSuffix.at(latestIndex).isDigit();
        if (currentIsDigit && latestIsDigit)
        {
            qsizetype currentEnd = currentIndex;
            qsizetype latestEnd = latestIndex;
            while (currentEnd < currentSuffix.size() &&
                   currentSuffix.at(currentEnd).isDigit())
            {
                ++currentEnd;
            }
            while (latestEnd < latestSuffix.size() &&
                   latestSuffix.at(latestEnd).isDigit())
            {
                ++latestEnd;
            }

            qsizetype currentNumberStart = currentIndex;
            qsizetype latestNumberStart = latestIndex;
            while (currentNumberStart < currentEnd - 1 &&
                   currentSuffix.at(currentNumberStart) == '0')
            {
                ++currentNumberStart;
            }
            while (latestNumberStart < latestEnd - 1 &&
                   latestSuffix.at(latestNumberStart) == '0')
            {
                ++latestNumberStart;
            }

            const qsizetype currentLength = currentEnd - currentNumberStart;
            const qsizetype latestLength = latestEnd - latestNumberStart;
            if (currentLength != latestLength)
            {
                return currentLength < latestLength ? -1 : 1;
            }

            const QStringView currentNumber(currentSuffix);
            const QStringView latestNumber(latestSuffix);
            const int numberComparison =
                currentNumber.mid(currentNumberStart, currentLength).compare(
                    latestNumber.mid(latestNumberStart, latestLength)
                );
            if (numberComparison != 0)
            {
                return numberComparison;
            }

            currentIndex = currentEnd;
            latestIndex = latestEnd;
            continue;
        }

        const QChar currentCharacter = currentSuffix.at(currentIndex).toLower();
        const QChar latestCharacter = latestSuffix.at(latestIndex).toLower();
        if (currentCharacter != latestCharacter)
        {
            return currentCharacter < latestCharacter ? -1 : 1;
        }
        ++currentIndex;
        ++latestIndex;
    }

    if (currentIndex == currentSuffix.size() &&
        latestIndex == latestSuffix.size())
    {
        return 0;
    }
    return currentIndex == currentSuffix.size() ? -1 : 1;
}

std::optional<QString> releaseVersion(const QJsonObject &release)
{
    auto version=release["tag_name"].toString().trimmed();
    if (version.startsWith('v')) version.removeFirst();
    return version.isEmpty() ? std::nullopt : std::optional<QString>(version);
}
}

struct UpdateChecker::Download {
    explicit Download(UpdatePackage selected)
        : package(std::move(selected)), directory(QDir::temp().filePath("JustConnect-update-XXXXXX")),
          file(directory.filePath(package.fileName)) {}
    UpdatePackage package;
    QTemporaryDir directory;
    QSaveFile file;
    QCryptographicHash hash{QCryptographicHash::Sha256};
    QNetworkReply *reply = nullptr;
    qint64 received = 0;
    bool cancelled = false;
    bool staged = false;
};

UpdateChecker::UpdateChecker(QObject *parent)
    : QObject(parent),
      versions{QCoreApplication::applicationVersion(), {}}
{
}

UpdateChecker::~UpdateChecker() = default;

const VersionInfo &UpdateChecker::versionInfo() const
{
    return versions;
}

void UpdateChecker::check(CheckMode mode)
{
    if (update)
        return;
    if (mode == CheckMode::Manual)
        checkMode = mode;
    if (versions.updateState == VersionInfo::UpdateState::Checking)
        return;
    if (!uiNetworkManager)
    {
        uiNetworkManager = new QNetworkAccessManager(this);
    }
    versions.uiLatest.clear();
    package.reset();
    versions.updateState = VersionInfo::UpdateState::Checking;
    emit versionInfoChanged(versions);
    QNetworkRequest request(QUrl("https://api.github.com/repos/" +
                                ApplicationConstants::RepositoryName + "/releases/latest"));
    request.setTransferTimeout();
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,QNetworkRequest::SameOriginRedirectPolicy);
    auto *reply=uiNetworkManager->get(request);
    connect(reply,&QNetworkReply::finished,this,[this,reply] { handleUiReply(reply); });
}

std::optional<QString> UpdateChecker::parseReleaseVersion(
    const QByteArray &payload
)
{
    return releaseVersion(QJsonDocument::fromJson(payload).object());
}

UpdateChecker::CheckResult UpdateChecker::compareVersions(const QString &currentVersion, const QString &latestVersion)
{
    qsizetype currentSuffix = 0;
    qsizetype latestSuffix = 0;
    const QVersionNumber current = QVersionNumber::fromString(currentVersion, &currentSuffix);
    const QVersionNumber latest = QVersionNumber::fromString(latestVersion, &latestSuffix);

    if (latest.segmentCount() != 3)
        return CheckResult::Failed;
    // A nightly build is identified by its Git revision, which has no release version ordering.
    if (current.segmentCount() != 3)
        return CheckResult::ReleaseInfo;

    if (latest != current)
    {
        return latest > current ? CheckResult::UpdateAvailable : CheckResult::UpToDate;
    }

    const QString currentSuffixText =
        normalizedSuffix(currentVersion, currentSuffix);
    const QString latestSuffixText =
        normalizedSuffix(latestVersion, latestSuffix);
    const VersionSuffixKind currentKind = suffixKind(currentSuffixText);
    const VersionSuffixKind latestKind = suffixKind(latestSuffixText);
    if (latestKind != currentKind)
    {
        return latestKind > currentKind ? CheckResult::UpdateAvailable : CheckResult::UpToDate;
    }
    return compareSuffixes(currentSuffixText, latestSuffixText) < 0
        ? CheckResult::UpdateAvailable : CheckResult::UpToDate;
}

void UpdateChecker::handleUiReply(QNetworkReply *reply)
{
    const bool received = reply->error() == QNetworkReply::NoError
        && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200;
    const auto release = received ? QJsonDocument::fromJson(reply->readAll()).object() : QJsonObject{};
    const auto latestVersion=releaseVersion(release);
    const auto result = latestVersion ? compareVersions(versions.uiVersion,*latestVersion) : CheckResult::Failed;
    if (result == CheckResult::Failed) {
        const auto reason = received ? QStringLiteral("The release response has no valid version tag.") : reply->errorString();
        qWarning().noquote() << "UI update check failed: " + reason;
        versions.uiLatest.clear();
        versions.updateState=VersionInfo::UpdateState::Failed;
    } else {
        qInfo().noquote() << "UI update check succeeded. Latest version: " + *latestVersion;
        versions.uiLatest = *latestVersion;
        versions.updateState=VersionInfo::UpdateState::Ready;
    }
    reply->deleteLater();
    if (result == CheckResult::UpdateAvailable && UpdatePackage::isReleaseVersion(versions.uiVersion))
        package=UpdatePackage::fromRelease(release,UpdateInstaller::assetSuffix());

    const auto mode = std::exchange(checkMode,CheckMode::Automatic);
    const auto latest = versions.uiLatest;
    emit versionInfoChanged(versions);
    emit checkFinished(result,mode,latest);
}

bool UpdateChecker::canInstall() const
{
    return package.has_value() && !update;
}

void UpdateChecker::download()
{
    if (!canInstall()) return;
    update=std::make_unique<Download>(*package);
    if (!update->directory.isValid() || !update->file.open(QIODevice::WriteOnly)) {
        update.reset();
        emit updateDownloadFailed();
        return;
    }
    QNetworkRequest request(update->package.url);
    request.setTransferTimeout();
    request.setMaximumRedirectsAllowed(3);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,QNetworkRequest::UserVerifiedRedirectPolicy);
    auto *reply=update->reply=uiNetworkManager->get(request);
    reply->setReadBufferSize(128*1024);
    QTimer::singleShot(10*60*1000,reply,&QNetworkReply::abort);
    connect(reply,&QNetworkReply::redirected,this,[reply](const QUrl &redirect) {
        if (UpdatePackage::isDownloadRedirect(redirect)) emit reply->redirectAllowed();
        else reply->abort();
    });
    connect(reply,&QIODevice::readyRead,this,&UpdateChecker::writeUpdateData);
    connect(reply,&QNetworkReply::finished,this,&UpdateChecker::finishDownload);
    emit updateProgress(0,update->package.size);
}

void UpdateChecker::cancelDownload()
{
    if (!update || !update->reply) return;
    update->cancelled=true;
    update->reply->abort();
}

void UpdateChecker::writeUpdateData()
{
    auto *reply=update->reply;
    const auto bytes=reply->readAll();
    if (bytes.isEmpty()) return;
    if (bytes.size()>update->package.size-update->received || update->file.write(bytes)!=bytes.size()) {
        update->file.cancelWriting();
        if (!reply->isFinished()) reply->abort();
        return;
    }
    update->hash.addData(bytes);
    update->received+=bytes.size();
    emit updateProgress(update->received,update->package.size);
}

void UpdateChecker::finishDownload()
{
    auto *reply=update->reply;
    if (reply->error()==QNetworkReply::NoError) writeUpdateData();
    update->reply=nullptr;
    const bool verified=reply->error()==QNetworkReply::NoError
        && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()==200
        && update->package.matches(update->received,update->hash.result())
        && update->file.commit();
    reply->deleteLater();
    if (verified) {
        update->staged=true;
        emit updateDownloaded();
        return;
    }
    const bool cancelled=update->cancelled;
    update.reset();
    if (!cancelled) emit updateDownloadFailed();
}

bool UpdateChecker::hasStagedUpdate() const
{
    return update && update->staged;
}

bool UpdateChecker::launchStagedUpdate()
{
    if (!hasStagedUpdate()) return false;
    const auto path=update->directory.filePath(update->package.fileName);
    if (!UpdateInstaller::launch(update->package,path)) return false;
    update->directory.setAutoRemove(false);
    update.reset();
    return true;
}
