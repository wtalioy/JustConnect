#pragma once

#include <QByteArray>
#include <QString>
#include <QUrl>
#include <optional>

class QJsonObject;

struct UpdatePackage {
    QString version;
    QString fileName;
    QUrl url;
    QByteArray sha256;
    qint64 size;

    bool matches(qint64 bytes,const QByteArray &digest) const { return bytes==size && digest==sha256; }
    static std::optional<UpdatePackage> fromRelease(const QJsonObject &release, const QString &assetSuffix);
    static bool isReleaseVersion(const QString &version);
    static bool isDownloadRedirect(const QUrl &url);
};
