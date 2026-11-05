#pragma once

#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/settings/profilemanager.h"
#include <QFutureWatcher>
#include <QPointer>
#include <functional>
#include <optional>

class QDialog;
class QWidget;

// Owns one cancellable discovery/choice; the core still proves actual endpoint ownership.
class ControllerSelectionCoordinator final : public QObject {
    Q_OBJECT
public:
    using Completion = std::function<void(std::optional<QString>)>;
    using Reader = std::function<EmbeddedCoreEngine::ControllerDiscovery()>;
    ControllerSelectionCoordinator(QWidget *window, QObject *parent,
        const QString &storageRoot = {}, Reader reader = {});
    ~ControllerSelectionCoordinator() override;
    void choose(Completion completion, bool showSettings = false);
    void cancel();
    bool isReading() const { return watcher.isRunning(); }
private:
    void read();
    void showChoice(const EmbeddedCoreEngine::ControllerDiscovery &result);
    void closeDialog();
    void finish(std::optional<QString> address);
    QWidget *window;
    ProfileManager preferences;
    Reader reader;
    QFutureWatcher<EmbeddedCoreEngine::ControllerDiscovery> watcher;
    QPointer<QDialog> dialog;
    Completion completion;
    quint64 request = 0, reading = 0;
    bool settings = false;
};
