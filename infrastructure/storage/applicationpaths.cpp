#include "applicationpaths.h"

#include <QDir>
#include <QStandardPaths>

QString ApplicationPaths::clientDataFile(const QString &connectionId)
{
    const QDir dataDirectory(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation));
    return QDir::cleanPath(dataDirectory.filePath("profiles/" + connectionId + "/client-data.json"));
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
