#include "infrastructure/systemproxy/proxychanges.h"
#include <QDir>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QStandardPaths>

struct ProxyChanges::Watch {
    QFileSystemWatcher files;
    QStringList targets;
    QStringList present;
    bool arm() {
        QStringList next, paths;
        for (const auto &target : targets) {
            if (QFileInfo::exists(target)) { next.append(target); paths.append(target); }
            auto parent = QFileInfo(target).dir();
            while (!parent.exists() && parent.cdUp()) {}
            if (parent.exists()) paths.append(parent.absolutePath());
        }
        paths.removeDuplicates();
        const bool changed = next != present;
        present = next;
        const auto old = files.files() + files.directories();
        QStringList added, removed;
        for (const auto &path : paths) if (!old.contains(path)) added.append(path);
        for (const auto &path : old) if (!paths.contains(path)) removed.append(path);
        if (!removed.isEmpty()) files.removePaths(removed);
        if (!added.isEmpty()) files.addPaths(added);
        return changed;
    }
};
ProxyChanges::ProxyChanges(QObject *parent) : QObject(parent), watch(std::make_unique<Watch>()) {
#ifdef Q_OS_MACOS
    watch->targets = {"/Library/Preferences/SystemConfiguration/preferences.plist"};
#else
    const auto config = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation);
    watch->targets = {config + "/kioslaverc", config + "/dconf/user", config + "/glib-2.0/settings/keyfile"};
#endif
    watch->arm();
    connect(&watch->files, &QFileSystemWatcher::fileChanged, this, [this] {
        watch->arm();
        emit changed();
    });
    connect(&watch->files, &QFileSystemWatcher::directoryChanged, this, [this] {
        if (watch->arm()) emit changed();
    });
}
ProxyChanges::~ProxyChanges() = default;
