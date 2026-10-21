#pragma once
#include <QDialog>
#include <QSettings>
#include "infrastructure/settings/credentialaccess.h"
class QLabel;
class QCheckBox;
class QPushButton;
class ServerSettingsWidget;
namespace Ui { class SettingWindow; }

class SettingWindow : public QDialog {
    Q_OBJECT
public:
    SettingWindow(QWidget *parent,CredentialAccess *credentials,const CredentialSource &source);
    ~SettingWindow() override;
    bool isSaving() const {return saving;}
private:
    void loadSettings(const QSettings &source);
    void readCredentials();
    void clearCredentials();
    void updateBusy();
    void clearDraftCredentials();
    void applySettings(bool closeAfter);
    QVariantMap publicChanges() const;
    ConnectionProfile currentProfile() const;
    Ui::SettingWindow *ui;
    QSettings settings;
    CredentialAccess *credentials;
    CredentialSource credentialSource;
    ConnectionCredentials loadedCredentials;
    QLabel *credentialStatus;
    QPushButton *clearCredentialButton;
    QCheckBox *rememberAuthentication;
    bool loading=false,saving=false,closed=false;
    quint64 loadGeneration=0;
    ServerSettingsWidget *serverEditor;
    QString selectedAuthId, selectedAuthSubType;
};
