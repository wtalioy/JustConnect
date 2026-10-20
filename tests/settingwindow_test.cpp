#include <QApplication>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <cstdlib>
#include <QFileDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QTimer>
#include <iostream>
#include "presentation/dialogs/settingwindow/settingwindow.h"
#include "infrastructure/settings/profilemanager.h"
#include "infrastructure/storage/applicationpaths.h"
#include "application/defaultsettings.h"
static void check(bool ok,const char *message) { if (!ok) { std::cerr<<message<<'\n'; std::exit(1); } }
static void write(const QString &path,const QByteArray &data) { check(QDir().mkpath(QFileInfo(path).absolutePath()),"create fixture directory"); QFile f(path); check(f.open(QIODevice::WriteOnly) && f.write(data)==data.size(),"write fixture"); }
static QByteArray read(const QString &path) { QFile f(path); check(f.open(QIODevice::ReadOnly),"read fixture"); return f.readAll(); }
int main(int argc,char **argv) {
    QTemporaryDir directory; check(directory.isValid(),"isolated settings");
    qputenv("XDG_CONFIG_HOME",directory.path().toUtf8()); qputenv("XDG_DATA_HOME",directory.path().toUtf8());
    qputenv("APPIMAGE",directory.filePath("missing.AppImage").toUtf8());
    QApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
    QApplication app(argc,argv); app.setApplicationName("JustConnect-settings-test"); app.setOrganizationName("JustConnect-test");
    QSettings settings(directory.filePath("profile.ini"),QSettings::IniFormat); DefaultSettings::reset(settings);
    settings.setValue("Credential/Username","fixture-user");
    settings.setValue("Credential/Password",QString::fromLatin1(QByteArray("fixture-password").toBase64()));
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");
    settings.setValue("JustConnect/AuthID","persisted-id"); settings.setValue("JustConnect/AuthSubType","password");
    settings.setValue("Credential/OtherAccount/Ticket","retained-ticket");
    settings.setValue("OtherApplication/Value","retained-value"); settings.sync();
    // Saving an unrelated change must preserve the selected opaque identity.
    { auto *initial=new SettingWindow(nullptr,&settings,"fixture"); initial->show();
      initial->findChild<QCheckBox *>("tlsVerifyCheckBox")->setChecked(false);
      initial->findChild<QDialogButtonBox *>("buttonBox")->button(QDialogButtonBox::Ok)->click(); app.processEvents();
      check(settings.value("JustConnect/AuthID")=="persisted-id" && settings.value("JustConnect/AuthSubType")=="password","selected authentication identity survives settings reload/apply");
      check(!settings.value("JustConnect/TLSVerify").toBool(),"explicit TLS policy saved through the shared server editor"); }
    const auto cache=ApplicationPaths::clientDataFile("fixture"),otherCache=ApplicationPaths::clientDataFile("other");
    check(!QFileInfo::exists(cache) && !QFileInfo::exists(otherCache),"locating legacy cache creates no plaintext files");
    write(cache,"current authentication"); write(otherCache,"other authentication");
    QString expectedMessage,fileSelection; bool shown=false;
    int messageResult=QMessageBox::Ok;
    QTimer dismiss;
    QObject::connect(&dismiss,&QTimer::timeout,[&] {
        for (auto *widget:QApplication::topLevelWidgets()) {
            if (auto *message=qobject_cast<QMessageBox *>(widget)) {
                check(!expectedMessage.isEmpty() && message->windowTitle()==expectedMessage,"only expected operation failure is shown");
                shown=true; auto *choice=message->button(QMessageBox::StandardButton(messageResult));
                check(choice!=nullptr,"expected dialog choice exists"); choice->click();
            } else if (auto *dialog=qobject_cast<QFileDialog *>(widget); dialog && dialog->isVisible() && !fileSelection.isEmpty()) {
                const auto path=fileSelection; fileSelection.clear();
                dialog->setDirectory(QFileInfo(path).absolutePath()); dialog->selectFile(QFileInfo(path).fileName());
                check(QMetaObject::invokeMethod(dialog,"accept"),"accept selected test file");
            }
        }
    }); dismiss.start(1);
    auto open=[&] { auto *window=new SettingWindow(nullptr,&settings,"fixture"); window->show(); return window; };
    auto buttons=[](SettingWindow *w) { return w->findChild<QDialogButtonBox *>("buttonBox"); };
    QPointer<SettingWindow> window=open();
    window->findChild<QLineEdit *>("secondaryDnsLineEdit")->setText("not-an-address");
    expectedMessage="配置无效"; buttons(window)->button(QDialogButtonBox::Ok)->click();
    check(shown && window->isVisible() && settings.value("JustConnect/SecondaryDNS").toString().isEmpty() && read(cache)=="current authentication","core validation rejects bad DNS before persistence or cache changes");
    window->findChild<QLineEdit *>("secondaryDnsLineEdit")->clear();
    window->findChild<QCheckBox *>("autoStartCheckBox")->setChecked(true);
    window->findChild<QLineEdit *>("serverAddressLineEdit")->setText("changed.example.invalid");
    expectedMessage="自启动操作未完成"; shown=false; buttons(window)->button(QDialogButtonBox::Ok)->click();
    check(shown && window->isVisible() && !ProfileManager().autoStartEnabled(),"autostart failure leaves settings open without enabling preference");
    check(settings.value("JustConnect/ServerAddress")=="vpn.example.invalid" && read(cache)=="current authentication","failed apply preserves settings and authentication");
    expectedMessage.clear(); window->findChild<QCheckBox *>("autoStartCheckBox")->setChecked(false);
    buttons(window)->button(QDialogButtonBox::Ok)->click(); app.processEvents();
    check(settings.value("JustConnect/ServerAddress")=="changed.example.invalid" && !QFileInfo::exists(cache) && read(otherCache)=="other authentication","explicit authentication change clears only current profile after saving");
    write(cache,"preserved authentication"); settings.setValue("JustConnect/ExtraArguments","obsolete-argument");
    window=open(); window->findChild<QSpinBox *>("dnsTTLSpinBox")->setValue(123);
    window->findChild<QLineEdit *>("loginUrlLineEdit")->setText("https://returned.example.invalid/?nonce=changed");
    buttons(window)->button(QDialogButtonBox::Ok)->click(); app.processEvents();
    check(!settings.contains("JustConnect/ExtraArguments") && settings.value("JustConnect/DNSTTL")==123 && read(cache)=="preserved authentication","obsolete-field cleanup, network edits and refreshed URL previews retain valid authentication");
    window=open(); expectedMessage="恢复默认值"; messageResult=QMessageBox::Yes;
    window->findChild<QPushButton *>("resetDefaultPushButton")->click(); expectedMessage.clear(); messageResult=QMessageBox::Ok;
    check(window->findChild<QLineEdit *>("serverAddressLineEdit")->text().isEmpty(),"reset changes the window draft");
    buttons(window)->button(QDialogButtonBox::Cancel)->click(); app.processEvents();
    check(settings.value("JustConnect/ServerAddress")=="changed.example.invalid" && read(cache)=="preserved authentication","cancelled reset preserves configuration and authentication");
    const auto imported=directory.filePath("import.ini");
    { QSettings source(imported,QSettings::IniFormat); DefaultSettings::reset(source); source.setValue("Credential/Username","imported-user"); source.setValue("JustConnect/ServerAddress","imported.example.invalid"); source.sync(); }
    const auto originalImport=read(imported);
    window=open(); fileSelection=imported; window->findChild<QPushButton *>("importPushButton")->click();
    check(fileSelection.isEmpty() && window->findChild<QLineEdit *>("usernameLineEdit")->text()=="imported-user","file import populates the window draft");
    buttons(window)->button(QDialogButtonBox::Cancel)->click(); app.processEvents();
    check(settings.value("Credential/Username")=="fixture-user" && read(imported)==originalImport && read(cache)=="preserved authentication","cancelled import changes neither source file nor saved profile/cache");
    window=open(); const auto exported=directory.filePath("export.ini"); fileSelection=exported;
    window->findChild<QPushButton *>("exportPushButton")->click();
    QSettings publicExport(exported,QSettings::IniFormat);
    check(fileSelection.isEmpty() && publicExport.value("JustConnect/ServerAddress")==settings.value("JustConnect/ServerAddress")
        && publicExport.value("Credential/Username")=="fixture-user" && !publicExport.contains("Credential/Password")
        && !publicExport.contains("Credential/TOTPSecret") && !publicExport.contains("Credential/OtherAccount/Ticket")
        && !publicExport.contains("OtherApplication/Value") && !publicExport.contains("JustConnect/LoginURL"),"export saves public configuration without credentials, private unknown fields or session URLs");
    window->reject(); app.processEvents();
    check(settings.value("Credential/OtherAccount/Ticket")=="retained-ticket" && settings.value("OtherApplication/Value")=="retained-value" && read(otherCache)=="other authentication","other accounts and application data survive all operations");
    std::cout<<"PASS: real settings validation, failures, scoped cache cleanup, import/reset cancellation and export\n";
}
