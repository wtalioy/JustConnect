#pragma once

#include "application/platformoperationresult.h"
#include <QByteArray>
#include <QJsonObject>
#include <QUuid>

class LinuxSourceJournal
{
public:
    ~LinuxSourceJournal();
    LinuxSourceJournal() = default;
    LinuxSourceJournal(const LinuxSourceJournal &) = delete;
    LinuxSourceJournal &operator=(const LinuxSourceJournal &) = delete;
    PlatformOperationResult open(int trustedDirectory, const QUuid &owner);
    PlatformOperationResult store(const QJsonObject &record);
    PlatformOperationResult load(QJsonObject &record);
    PlatformOperationResult remove();
    void close();
private:
    struct SavedFile { QByteArray bytes; quint64 device = 0, inode = 0; bool present = false; };
    PlatformOperationResult read(SavedFile &file) const;
    bool unchanged(const SavedFile &file) const;
    int directory = -1;
    QUuid owner;
    SavedFile known;
    bool bound = false;
};
