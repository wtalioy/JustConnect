#include <QApplication>
#include <QAbstractButton>
#include <QDebug>
#include <QLineEdit>
#include <QDir>
#include <QMessageBox>
#include <QTimer>
#include <cstdlib>
#include "application/defaultsettings.h"
#include <QSettings>
#include <QStackedWidget>
#include <QTemporaryDir>

#include "presentation/dialogs/configurationguidedialog/configurationguidedialog.h"

namespace
{
QLineEdit *lineEdit(ConfigurationGuideDialog &dialog, const char *name)
{
    QLineEdit *field = dialog.findChild<QLineEdit *>(name);
    if (field == nullptr)
    {
        qCritical() << "Missing guide field" << name;
    }
    return field;
}

QStackedWidget *credentialPages(ConfigurationGuideDialog &dialog)
{
    QStackedWidget *pages = dialog.findChild<QStackedWidget *>(
        "credentialPages"
    );
    if (pages == nullptr)
    {
        qCritical() << "Missing credential pages";
    }
    return pages;
}

QString expectedMessage;
bool messageShown=false;

bool savesPasswordCredentials(const QString &settingsPath)
{
    QSettings settings(settingsPath, QSettings::IniFormat);
    DefaultSettings::reset(settings);
    settings.setValue("JustConnect/ServerAddress","vpn.example.edu");
    settings.setValue("Credential/Username", "old-user");
    settings.setValue(
        "Credential/Password",
        QString(QStringLiteral("old-password").toUtf8().toBase64())
    );
    settings.setValue("Credential/TOTPSecret", "old-totp");

    ConfigurationGuideDialog dialog(nullptr, &settings);
    QStackedWidget *pages = credentialPages(dialog);
    QLineEdit *username = lineEdit(dialog, "guideUsernameLineEdit");
    QLineEdit *password = lineEdit(dialog, "guidePasswordLineEdit");
    QLineEdit *totp = lineEdit(dialog, "guideTotpSecretLineEdit");
    if (pages == nullptr || username == nullptr || password == nullptr
        || totp == nullptr)
    {
        return false;
    }
    if (pages->currentIndex() != 0 || username->text() != "old-user"
        || password->text() != "old-password" || totp->text() != "old-totp")
    {
        qCritical() << "Password credentials were not loaded into the guide";
        return false;
    }

    username->setText("alice");
    password->setText("secret");
    totp->setText("totp-key");
    if (!dialog.applyTo(settings)) return false;

    const QString savedPassword = QByteArray::fromBase64(
        settings.value("Credential/Password").toByteArray()
    );
    const bool passed = settings.value("Credential/Username") == "alice"
        && savedPassword == "secret"
        && settings.value("Credential/TOTPSecret") == "totp-key"
        && settings.value("JustConnect/ProfileKind") == "Custom"
        && !settings.contains("JustConnect/Protocol");
    if (!passed)
    {
        qCritical() << "Password credentials were not saved by the guide";
    }
    return passed;
}

bool savesSmsCredentials(const QString &settingsPath)
{
    QSettings settings(settingsPath, QSettings::IniFormat);
    DefaultSettings::reset(settings);
    settings.setValue("JustConnect/ServerAddress","vpn.example.edu");
    settings.setValue("JustConnect/AuthType", "smsCheckCode");
    settings.setValue("JustConnect/PhoneCountryCode", "86");
    settings.setValue("JustConnect/PhoneNumber", "123456");

    ConfigurationGuideDialog dialog(nullptr, &settings);
    QStackedWidget *pages = credentialPages(dialog);
    QLineEdit *countryCode = lineEdit(dialog, "guideCountryCodeLineEdit");
    QLineEdit *phoneNumber = lineEdit(dialog, "guidePhoneNumberLineEdit");
    if (pages == nullptr || countryCode == nullptr || phoneNumber == nullptr)
    {
        return false;
    }
    if (pages->currentIndex() != 1 || countryCode->text() != "86"
        || phoneNumber->text() != "123456")
    {
        qCritical() << "SMS credentials were not loaded into the guide";
        return false;
    }

    countryCode->setText("852");
    phoneNumber->setText("98765432");
    if (!dialog.applyTo(settings)) return false;

    const bool passed = settings.value("JustConnect/PhoneCountryCode") == "852"
        && settings.value("JustConnect/PhoneNumber") == "98765432";
    if (!passed)
    {
        qCritical() << "SMS credentials were not saved by the guide";
    }
    return passed;
}

bool showsSsoWithoutCredentialFields(const QString &settingsPath)
{
    QSettings settings(settingsPath, QSettings::IniFormat);
    DefaultSettings::reset(settings);
    settings.setValue("JustConnect/ServerAddress","vpn.example.edu");
    settings.setValue("JustConnect/AuthType", "cas");

    ConfigurationGuideDialog dialog(nullptr, &settings);
    QStackedWidget *pages = credentialPages(dialog);
    const bool passed = pages != nullptr && pages->currentIndex() == 2;
    if (!passed)
    {
        qCritical() << "CAS did not select the credential-free guide page";
    }
    return passed;
}
bool rejectsInvalidCoreSettingsAndFailedSaves(const QString &root)
{
    QSettings settings(root+"/invalid.ini",QSettings::IniFormat);
    DefaultSettings::reset(settings);
    settings.setValue("JustConnect/ServerAddress","vpn.example.edu");
    settings.setValue("JustConnect/SecondaryDNS","not-an-address");
    settings.setValue("Credential/Username","retained-user");
    settings.setValue("OtherAccount/Ticket","retained-ticket");
    ConfigurationGuideDialog invalid(nullptr,&settings);
    lineEdit(invalid,"guideUsernameLineEdit")->setText("draft-user");
    expectedMessage="请检查服务器、认证方式及连接设置。配置未保存。"; messageShown=false;
    if (invalid.applyTo(settings) || !messageShown || settings.value("Credential/Username")!="retained-user"
        || settings.value("OtherAccount/Ticket")!="retained-ticket") return false;
    const auto blocked=root+"/blocked.ini";
    if (!QDir().mkdir(blocked)) return false;
    QSettings failed(blocked,QSettings::IniFormat);
    DefaultSettings::reset(failed);
    failed.setValue("Common/ConfigVersion",8);
    failed.setValue("JustConnect/ServerAddress","vpn.example.edu");
    failed.setValue("Credential/Username","fixture-user");
    failed.setValue("Credential/Password",QString::fromLatin1(QByteArray("fixture-password").toBase64()));
    ConfigurationGuideDialog dialog(nullptr,&failed); dialog.show();
    QMetaObject::invokeMethod(&dialog,"goNext"); QMetaObject::invokeMethod(&dialog,"goNext");
    expectedMessage="部分设置可能已保存，请检查后重试。"; messageShown=false;
    QMetaObject::invokeMethod(&dialog,"goNext");
    const bool passed=messageShown && dialog.isVisible() && dialog.result()!=QDialog::Accepted
        && failed.value("Common/ConfigVersion").toInt()==8;
    expectedMessage.clear(); return passed;
}

}

int main(int argc, char *argv[])
{
    QApplication application(argc, argv);
    QTimer dismiss;
    QObject::connect(&dismiss,&QTimer::timeout,[] {
        for (auto *widget:QApplication::topLevelWidgets()) if (auto *message=qobject_cast<QMessageBox *>(widget)) {
            if (expectedMessage.isEmpty() || message->text()!=expectedMessage
                || message->icon()!=QMessageBox::Warning || message->standardButtons()!=QMessageBox::Ok) {
                qCritical()<<"Unexpected guide warning"<<message->text(); std::exit(1);
            }
            messageShown=true; message->button(QMessageBox::Ok)->click();
        }
    }); dismiss.start(1);
    QTemporaryDir directory;
    if (!directory.isValid())
    {
        qCritical() << "Unable to create temporary directory";
        return 1;
    }

    const bool passed =
        savesPasswordCredentials(directory.filePath("password.ini"))
        && savesSmsCredentials(directory.filePath("sms.ini"))
        && showsSsoWithoutCredentialFields(directory.filePath("sso.ini"))
        && rejectsInvalidCoreSettingsAndFailedSaves(directory.path());
    return passed ? 0 : 1;
}
