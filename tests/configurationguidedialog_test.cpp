#include <QApplication>
#include <QAbstractButton>
#include <QDebug>
#include <QLineEdit>
#include <QDir>
#include <QMessageBox>
#include <QTimer>
#include <QElapsedTimer>
#include <QFile>
#include <QSemaphore>
#include <atomic>
#include "tests/credentialstorefixture.h"
#include "application/profileservice.h"
#include <cstdlib>
#include "application/defaultsettings.h"
#include <QSettings>
#include <QStackedWidget>
#include <QTemporaryDir>

#include "presentation/dialogs/configurationguidedialog/configurationguidedialog.h"

namespace
{
template<class P> void until(P done) {
    QElapsedTimer timer;timer.start();
    while (!done() && timer.elapsed()<6000) QApplication::processEvents(QEventLoop::AllEvents,10);
    if (!done()) {qCritical()<<"Guide operation timed out";std::exit(1);}
}
void ready(CredentialAccess &access,QSettings &settings) {until([&]{return !access.isBusy(settings.fileName());});QApplication::processEvents();}

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
    settings.setValue("JustConnect/AuthID","opaque-selection");
    settings.setValue("JustConnect/AuthSubType","password");
    settings.setValue("JustConnect/SOCKS5Port",0);
    settings.setValue("JustConnect/HTTPPort",19443);
    settings.setValue("JustConnect/DNSTTL",61);
    settings.setValue("JustConnect/SecondaryDNS","10.0.0.2");

    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();
    CredentialAccess access(std::move(backend));
    const auto source=CredentialAccess::source(settings,{});
    ConfigurationGuideDialog dialog(nullptr,&access,source);
    ready(access,settings);
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
    if (!dialog.applyTo()) return false;
    until([&]{return dialog.result()==QDialog::Accepted;});

    ConnectionCredentials saved;ProfileCredentials vault(*store);
    if (!vault.load(source.scope,ProfileService::load(settings),saved).succeeded()) return false;
    const auto reloaded=ProfileService::load(settings);
    const bool passed = reloaded.proxy.socksBind.isEmpty() && reloaded.proxy.httpBind=="127.0.0.1:19443"
        && reloaded.dns.ttl==61 && reloaded.dns.secondary=="10.0.0.2"
        && settings.value("Credential/Username") == "alice"
        && saved.password == "secret" && saved.totpSecret == "totp-key"
        && !settings.contains("Credential/Password") && !settings.contains("Credential/TOTPSecret")
        && settings.value("JustConnect/AuthID")=="opaque-selection"
        && settings.value("JustConnect/AuthSubType")=="password"
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

    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();
    CredentialAccess access(std::move(backend));
    const auto source=CredentialAccess::source(settings,{});
    ConfigurationGuideDialog dialog(nullptr,&access,source);
    ready(access,settings);
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
    if (!dialog.applyTo()) return false;
    until([&]{return dialog.result()==QDialog::Accepted;});

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

    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();
    CredentialAccess access(std::move(backend));
    const auto source=CredentialAccess::source(settings,{});
    ConfigurationGuideDialog dialog(nullptr,&access,source);
    ready(access,settings);
    QStackedWidget *pages = credentialPages(dialog);
    const bool passed = pages != nullptr && pages->currentIndex() == 2;
    if (!passed)
    {
        qCritical() << "CAS did not select the credential-free guide page";
    }
    return passed;
}
bool ownsConfigurationAndRejectsClosedResults(const QString &root)
{
    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();
    CredentialAccess access(std::move(backend));ProfileCredentials vault(*store);
    const auto seed=[&](const QString &name,const QString &password) {
        QSettings origin(root+"/late-"+name+".ini",QSettings::IniFormat);
        DefaultSettings::reset(origin);
        origin.setValue("JustConnect/ServerAddress","vpn.example.edu");
        origin.setValue("Credential/Username",name);
        const auto source=CredentialAccess::source(origin,{});
        auto secured=source.profile;secured.credentials.password=password;
        if (!vault.save(source.scope,secured).succeeded()) std::exit(1);
        return source;
    };
    const auto alice=seed("alice","alice-secret"),bob=seed("bob","bob-secret");
    QSemaphore entered,resume;std::atomic_bool gated=false;
    store->beforeRead=[&] {
        if (!gated.exchange(true)) {
            entered.release();
            if (!resume.tryAcquire(1,6000)) std::exit(1);
        }
    };
    ConfigurationGuideDialog old(nullptr,&access,alice);
    if (!entered.tryAcquire(1,1000)) {qCritical()<<"Delayed guide read did not start";std::exit(1);}
    old.reject();
    ConfigurationGuideDialog current(nullptr,&access,bob);
    lineEdit(current,"guidePasswordLineEdit")->setText("manual-draft");
    resume.release();
    until([&]{return !access.isBusy(alice.path) && !access.isBusy(bob.path);});
    QApplication::processEvents();store->beforeRead={};
    if (!lineEdit(old,"guidePasswordLineEdit")->text().isEmpty() || old.applyTo()
        || lineEdit(current,"guideUsernameLineEdit")->text()!="bob"
        || lineEdit(current,"guidePasswordLineEdit")->text()!="manual-draft") return false;
    if (!current.applyTo()) return false;
    until([&]{return current.result()==QDialog::Accepted;});
    ConnectionCredentials saved;
    if (!vault.load(alice.scope,alice.profile,saved).succeeded() || saved.password!="alice-secret"
        || !vault.load(bob.scope,bob.profile,saved).succeeded() || saved.password!="manual-draft") return false;
    QSettings reopened(alice.path,QSettings::IniFormat);
    return reopened.value("Credential/Username")=="alice" && !reopened.contains("Credential/Password");
}

bool rejectsInvalidCoreSettingsAndFailedSaves(const QString &root)
{
    QSettings settings(root+"/invalid.ini",QSettings::IniFormat);
    DefaultSettings::reset(settings);
    settings.setValue("JustConnect/ServerAddress","vpn.example.edu");
    settings.setValue("JustConnect/SecondaryDNS","not-an-address");
    settings.setValue("Credential/Username","retained-user");
    settings.setValue("OtherAccount/Ticket","retained-ticket");
    CredentialAccess access(std::make_unique<MemoryCredentialStore>());
    ConfigurationGuideDialog invalid(nullptr,&access,CredentialAccess::source(settings,{}));
    ready(access,settings);
    lineEdit(invalid,"guideUsernameLineEdit")->setText("draft-user");
    expectedMessage="请检查服务器、认证方式及连接设置。配置未保存。"; messageShown=false;
    if (invalid.applyTo() || !messageShown || settings.value("Credential/Username")!="retained-user"
        || settings.value("OtherAccount/Ticket")!="retained-ticket") return false;
    const auto path=root+"/write-failure.ini";
    QSettings failed(path,QSettings::IniFormat);DefaultSettings::reset(failed);
    failed.setValue("JustConnect/ServerAddress","vpn.example.edu");failed.setValue("Credential/Username","fixture-user");
    ConfigurationGuideDialog dialog(nullptr,&access,CredentialAccess::source(failed,{}));dialog.show();ready(access,failed);
    if (!QFile::rename(path,path+".backup") || !QDir().mkdir(path)) return false;
    QMetaObject::invokeMethod(&dialog,"goNext");QMetaObject::invokeMethod(&dialog,"goNext");
    expectedMessage="安全存储或配置操作未完成，请检查后重试。";messageShown=false;
    if (!dialog.applyTo()) return false;
    until([&]{return !dialog.isSaving();});QApplication::processEvents();
    const bool passed=messageShown && dialog.isVisible() && dialog.result()!=QDialog::Accepted;
    QDir().rmdir(path);QFile::rename(path+".backup",path);
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
        && rejectsInvalidCoreSettingsAndFailedSaves(directory.path())
        && ownsConfigurationAndRejectsClosedResults(directory.path());
    return passed ? 0 : 1;
}
