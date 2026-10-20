#include "applicationpaths.h"

#include <QDir>
#include <QFile>
#include <QStandardPaths>

QString ApplicationPaths::clientDataFile(const QString &profileId)
{
    const QDir dataDirectory(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation));
    return QDir::cleanPath(dataDirectory.filePath("profiles/" + profileId + "/client-data.json"));
}

void ApplicationPaths::clearClientData(const QString &profileId)
{
    QFile::remove(clientDataFile(profileId));
}

QString ApplicationPaths::logDirectory()
{
    QDir logDirectory(
        QDir(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation))
            .filePath("logs")
    );
    if (!logDirectory.exists())
    {
        logDirectory.mkpath(".");
    }
    return logDirectory.absolutePath();
}

QString ApplicationPaths::logFile()
{
    return QDir(logDirectory()).filePath("justconnect.log");
}
