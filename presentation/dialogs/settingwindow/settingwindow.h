#pragma once
#include <QDialog>
#include <QSettings>
#include "infrastructure/settings/credentialaccess.h"
class QLabel;
class QCheckBox;
class QPushButton;
class ServerSettingsWidget;
class CoreEngine;
class AuthMethodsQuery;
class ControllerSelectionCoordinator;
namespace Ui { class SettingWindow; }

class SettingWindow : public QDialog {
    Q_OBJECT
public:
    SettingWindow(QWidget *parent,CredentialAccess *credentials,const CredentialSource &source,CoreEngine *queryEngine=nullptr);
    void setProfileEditable(bool editable);
    void setConnectAfterSave(bool connect);
    ~SettingWindow() override;
    bool isSaving() const {return saving;}
signals:
    void connectRequested();
protected:
    void changeEvent(QEvent *event) override;
    void showEvent(QShowEvent *event) override;
    void done(int result) override;
private:
    void retranslate();
    void updateAuthFields();
    void resetAuthChoices();
    void loadSettings(const QSettings &source);
    void readCredentials();
    void clearCredentials();
    void updateBusy();
    void clearDraftCredentials();
    void saveSettings();
    void queryMethods();
    void cancelQuery();
    QVariantMap publicChanges() const;
    ConnectionOptions currentOptions() const;
    Ui::SettingWindow *ui;
    QSettings settings;
    CredentialAccess *credentials;
    CredentialSource credentialSource;
    ConnectionCredentials loadedCredentials;
    QLabel *credentialStatus;
    const char *credentialStatusText=nullptr;
    CredentialStatus credentialLoadStatus=CredentialStatus::NotFound;
    QPushButton *clearCredentialButton,*saveButton,*dismissButton;
    QCheckBox *rememberAuthentication;
    bool loading=false,saving=false,closed=false,profileEditable=true,querying=false,connectAfterSave=false;
    bool opened=false;
    quint64 loadGeneration=0;
    ServerSettingsWidget *serverEditor;
    QString selectedAuthId, selectedAuthSubType, selectedAuthDomain, selectedAuthType;
    QVariantMap draftValues;
    AuthMethodsQuery *authQuery;
    ControllerSelectionCoordinator *controllerSelection;
    QLabel *queryStatus,*profileHint;
    const char *queryStatusText=nullptr;
    quint64 queryGeneration=0;
};
