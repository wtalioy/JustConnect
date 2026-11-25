#include "infrastructure/process/running.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>

namespace {
// comm truncates to 15 characters; the executable link keeps the full basename.
bool sameName(const QString &value, const QString &name)
{
    return value.compare(name, Qt::CaseInsensitive) == 0;
}
}

std::optional<bool> isProcessRunning(const QString &name)
{
    if (name.isEmpty()) return std::nullopt;
    const QDir proc(QStringLiteral("/proc"));
    const auto entries = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Unsorted);
    if (entries.isEmpty()) return std::nullopt; // /proc always lists this process; empty means no listing.
    bool scanned = false;
    for (const auto &entry : entries) {
        bool numeric = false;
        const auto pid = entry.toLongLong(&numeric);
        if (!numeric || pid <= 0) continue;
        QFile comm("/proc/" + entry + "/comm");
        if (!comm.open(QIODevice::ReadOnly)) continue; // The process may exit mid-scan; races skip cleanly.
        auto text = QString::fromUtf8(comm.readAll());
        while (text.endsWith('\n')) text.chop(1);
        scanned = true;
        if (sameName(text, name)) return true;
        const QString executable = QFileInfo(QFile::symLinkTarget("/proc/" + entry + "/exe")).fileName();
        if (!executable.isEmpty() && sameName(executable, name)) return true;
    }
    return scanned ? std::optional<bool>(false) : std::nullopt;
}
