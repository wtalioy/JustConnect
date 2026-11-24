#ifndef UPDATECHECKER_H
#define UPDATECHECKER_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <memory>

#include <optional>
#include "updatepackage.h"

class QNetworkAccessManager;
class QNetworkReply;

struct VersionInfo
{
    enum class UpdateState { Checking, Disabled, Failed, Ready };
    QString uiVersion;
    QString uiLatest;
    UpdateState updateState=UpdateState::Disabled;
};

class UpdateChecker : public QObject
{
    Q_OBJECT

public:
    explicit UpdateChecker(QObject *parent = nullptr);
    ~UpdateChecker() override;

    const VersionInfo &versionInfo() const;
    void check();
    bool canInstall() const;
    void download();
    void cancelDownload();
    bool hasStagedUpdate() const;
    bool launchStagedUpdate();

    static std::optional<QString> parseReleaseVersion(const QByteArray &payload);
    static bool isNewerVersion(const QString &currentVersion, const QString &latestVersion);

signals:
    void versionInfoChanged(const VersionInfo &versionInfo);
    void uiUpdateAvailable(const QString &version);
    void updateProgress(qint64 received,qint64 total);
    void updateDownloaded();
    void updateDownloadFailed();

private:
    void handleUiReply(QNetworkReply *reply);
    void writeUpdateData();
    void finishDownload();

    struct Download;
    VersionInfo versions;
    QNetworkAccessManager *uiNetworkManager = nullptr;
    std::optional<UpdatePackage> package;
    std::unique_ptr<Download> update;
};

#endif // UPDATECHECKER_H
