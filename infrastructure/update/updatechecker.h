#ifndef UPDATECHECKER_H
#define UPDATECHECKER_H

#include <QByteArray>
#include <QObject>
#include <QString>

#include <optional>

class QNetworkAccessManager;
class QNetworkReply;

struct VersionInfo
{
    enum class UpdateState { Checking, Disabled, Failed, Ready };
    QString uiVersion;
    QString uiLatest;
    QString coreVersion;
    UpdateState updateState=UpdateState::Checking;
};

class UpdateChecker : public QObject
{
    Q_OBJECT

public:
    explicit UpdateChecker(QObject *parent = nullptr);

    const VersionInfo &versionInfo() const;
    void markDisabled();
    void check();

    static QString normalizeVersionTag(const QString &tag);
    static std::optional<QString> parseReleaseVersion(const QByteArray &payload);
    static bool isNewerVersion(const QString &currentVersion, const QString &latestVersion);

signals:
    void versionInfoChanged(const VersionInfo &versionInfo);
    void uiUpdateAvailable(const QString &version);

private:
    void handleUiReply(QNetworkReply *reply);

    VersionInfo versions;
    QNetworkAccessManager *uiNetworkManager;
};

#endif // UPDATECHECKER_H
