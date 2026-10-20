#ifndef CONFIGURATIONGUIDEDIALOG_H
#define CONFIGURATIONGUIDEDIALOG_H

#include <QDialog>
#include <QString>
#include <QJsonObject>
#include "infrastructure/settings/credentialaccess.h"

class QLabel;
class QLineEdit;
class QPushButton;
class QSettings;
class ServerSettingsWidget;
class QStackedWidget;
class QWidget;

class ConfigurationGuideDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ConfigurationGuideDialog(
        QWidget *parent,
        QSettings *settings,
        CredentialAccess *credentials,
        const CredentialSource &source
    );

    bool applyTo();
    bool isSaving() const {return saving;}

private slots:
    void goBack();

    void goNext();

    void fetchAuthenticationMethods();

private:
    ConnectionProfile currentProfile() const;
    void readCredentials();
    void clearDraftCredentials();
    QWidget *createServerPage();

    QWidget *createAuthenticationPage();

    QWidget *createCredentialsPage();

    bool validateCurrentPage();

    void updateNavigation();

    void updateCredentialsPage();

    void selectAuthenticationMethod(const QJsonObject &method);

    QString authenticationMethodName(const QString &authType) const;

    QSettings *sourceSettings;
    CredentialAccess *credentials;
    CredentialSource credentialSource;
    ConnectionCredentials loadedCredentials;
    QLabel *credentialStatus;
    bool loading=false,saving=false,closed=false;
    quint64 loadGeneration=0;

    QLabel *stepLabel;
    QLabel *titleLabel;
    QLabel *descriptionLabel;
    QStackedWidget *pages;
    QPushButton *backButton;
    QPushButton *nextButton;

    ServerSettingsWidget *serverEditor;

    QLabel *selectedAuthenticationLabel;
    QPushButton *fetchAuthenticationButton;

    QStackedWidget *credentialPages = nullptr;
    QLineEdit *usernameLineEdit;
    QLineEdit *passwordLineEdit;
    QLineEdit *totpSecretLineEdit;
    QLineEdit *countryCodeLineEdit;
    QLineEdit *phoneNumberLineEdit;

    QString selectedAuthType;
    QString selectedLoginDomain;
    QString selectedAuthId, selectedAuthSubType;
};

#endif // CONFIGURATIONGUIDEDIALOG_H
