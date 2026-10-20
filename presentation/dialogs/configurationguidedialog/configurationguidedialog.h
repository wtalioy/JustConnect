#ifndef CONFIGURATIONGUIDEDIALOG_H
#define CONFIGURATIONGUIDEDIALOG_H

#include <QDialog>
#include <QString>
#include <QJsonObject>

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
        QSettings *settings
    );

    bool applyTo(QSettings &settings);

private slots:
    void goBack();

    void goNext();

    void fetchAuthenticationMethods();

private:
    QWidget *createServerPage();

    QWidget *createAuthenticationPage();

    QWidget *createCredentialsPage();

    bool validateCurrentPage();

    void updateNavigation();

    void updateCredentialsPage();

    void selectAuthenticationMethod(const QJsonObject &method);

    QString authenticationMethodName(const QString &authType) const;

    QSettings *sourceSettings;

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
    QString selectedLoginUrl;
    QString selectedAuthId, selectedAuthSubType;
};

#endif // CONFIGURATIONGUIDEDIALOG_H
