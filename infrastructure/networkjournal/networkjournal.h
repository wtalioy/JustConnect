#pragma once

#include "application/platformoperationresult.h"
#include <QByteArray>
#include <QJsonObject>
#include <QUuid>

inline constexpr int NetworkJournalMaxBytes = 2 * 1024 * 1024;
// The parent descriptor must name a trusted root-owned directory; components never contain paths.
int openPrivateNetworkDirectory(int parent, const QByteArray &component, bool create = true);

class UnixNetworkJournal
{
public:
    ~UnixNetworkJournal();
    UnixNetworkJournal() = default;
    UnixNetworkJournal(const UnixNetworkJournal &) = delete;
    UnixNetworkJournal &operator=(const UnixNetworkJournal &) = delete;
    PlatformOperationResult open(int trustedDirectory, const QUuid &owner, bool *alreadyOwned = nullptr);
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
