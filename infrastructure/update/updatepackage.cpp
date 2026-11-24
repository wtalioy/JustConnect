#include "updatepackage.h"

#include "application/applicationconstants.h"
#include <QJsonArray>
#include <QJsonObject>
#include <QRegularExpression>

std::optional<UpdatePackage> UpdatePackage::fromRelease(const QJsonObject &release, const QString &assetSuffix)
{
    const auto tag = release["tag_name"].toString();
    const auto version = tag.mid(1);
    if (assetSuffix.isEmpty() || !tag.startsWith('v') || !isReleaseVersion(version)
        || release["draft"] != false || release["prerelease"] != false) return {};
    const auto fileName = "JustConnect-" + tag + '-' + assetSuffix;
    const auto expectedUrl = "https://github.com/" + ApplicationConstants::RepositoryName + "/releases/download/" + tag + '/' + fileName;
    constexpr qint64 maxPackageBytes = 256 * 1024 * 1024;
    static const QRegularExpression digestFormat(QStringLiteral("\\Asha256:[0-9a-f]{64}\\z"));
    std::optional<UpdatePackage> result;
    for (const auto &value : release["assets"].toArray()) {
        const auto asset = value.toObject();
        if (asset["name"].toString()!=fileName) continue;
        const auto digest = asset["digest"].toString();
        const auto size = asset["size"].toInteger();
        if (result || asset["state"] != "uploaded" || asset["browser_download_url"] != expectedUrl
            || size<1 || size>maxPackageBytes || !digestFormat.match(digest).hasMatch()) return {};
        result = UpdatePackage{version,fileName,QUrl(expectedUrl),QByteArray::fromHex(digest.mid(7).toLatin1()),size};
    }
    return result;
}

bool UpdatePackage::isReleaseVersion(const QString &version)
{
    static const QRegularExpression format(QStringLiteral("\\A[0-9]{1,8}\\.[0-9]{1,8}\\.[0-9]{1,8}\\z"));
    return format.match(version).hasMatch();
}

bool UpdatePackage::isDownloadRedirect(const QUrl &url)
{
    return url.isValid() && url.scheme()=="https" && url.port(443)==443 && url.userInfo().isEmpty()
        && (url.host()=="release-assets.githubusercontent.com" || url.host()=="objects.githubusercontent.com");
}
