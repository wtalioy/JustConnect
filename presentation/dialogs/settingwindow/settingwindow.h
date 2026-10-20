#pragma once
#include <QDialog>
#include "infrastructure/settings/credentialaccess.h"
class QSettings;
class QLabel;
class QPushButton;
class ServerSettingsWidget;
namespace Ui { class SettingWindow; }

class SettingWindow : public QDialog {
    Q_OBJECT
public:
    SettingWindow(QWidget *parent,QSettings *settings,CredentialAccess *credentials,const CredentialSource &source);
    ~SettingWindow() override;
    bool isSaving() const {return saving;}
private:
    void loadSettings(const QSettings &source);
    void readCredentials();
    void clearCredentials();
    void updateBusy();
    void clearDraftCredentials();
    void applySettings(bool closeAfter);
    ConnectionProfile currentProfile() const;
    Ui::SettingWindow *ui;
    QSettings *settings;
    CredentialAccess *credentials;
    CredentialSource credentialSource;
    ConnectionCredentials loadedCredentials;
    QLabel *credentialStatus;
    QPushButton *clearCredentialButton;
    bool loading=false,saving=false,closed=false;
    quint64 loadGeneration=0;
    ServerSettingsWidget *serverEditor;
    QString selectedAuthId, selectedAuthSubType;
};
