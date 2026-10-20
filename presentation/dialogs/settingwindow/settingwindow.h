#pragma once
#include <QDialog>
#include "core/connectionprofile.h"
class QSettings;
class ServerSettingsWidget;
namespace Ui { class SettingWindow; }

class SettingWindow : public QDialog {
    Q_OBJECT
public:
    explicit SettingWindow(QWidget *parent = nullptr, QSettings *settings = nullptr, const QString &profileId = {});
    ~SettingWindow() override;
private:
    void loadSettings(const QSettings &source);
    bool applySettings();
    ConnectionProfile currentProfile() const;
    Ui::SettingWindow *ui;
    QSettings *settings;
    QString profileId;
    ServerSettingsWidget *serverEditor;
};
