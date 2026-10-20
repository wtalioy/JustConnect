#include <QApplication>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QFile>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSettings>
#include <QTemporaryDir>
#include <QTimer>
#include <iostream>
#include "presentation/dialogs/settingwindow/settingwindow.h"
#include "infrastructure/settings/profilemanager.h"
#include "infrastructure/storage/applicationpaths.h"
#include "application/defaultsettings.h"

static void check(bool ok,const char *message) { if (!ok) { std::cerr<<message<<'\n'; std::exit(1); } }
int main(int argc,char **argv) {
    QTemporaryDir directory;
    check(directory.isValid(),"isolated settings");
    qputenv("XDG_CONFIG_HOME",directory.path().toUtf8()); qputenv("XDG_DATA_HOME",directory.path().toUtf8());
    qputenv("APPIMAGE",directory.filePath("missing.AppImage").toUtf8());
    QApplication app(argc,argv);
    app.setApplicationName("JustConnect-settings-test"); app.setOrganizationName("JustConnect-test");
    QSettings settings(directory.filePath("profile.ini"),QSettings::IniFormat);
    DefaultSettings::reset(settings);
    settings.setValue("Credential/Username","fixture-user");
    settings.setValue("Credential/Password",QString::fromLatin1(QByteArray("fixture-password").toBase64()));
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid"); settings.sync();
    const auto cache = ApplicationPaths::clientDataFile("fixture");
    QFile cacheFile(cache); check(cacheFile.open(QIODevice::WriteOnly),"auth cache fixture"); cacheFile.write("retained authentication"); cacheFile.close();
    QPointer<SettingWindow> window = new SettingWindow(nullptr,&settings,"fixture"); window->show();
    window->findChild<QCheckBox *>("autoStartCheckBox")->setChecked(true);
    window->findChild<QLineEdit *>("serverAddressLineEdit")->setText("changed.example.invalid");
    bool shown = false;
    QTimer dismiss;
    QObject::connect(&dismiss,&QTimer::timeout,[&] {
        for (auto *widget : QApplication::topLevelWidgets()) if (auto *message=qobject_cast<QMessageBox *>(widget)) {
            check(message->windowTitle()=="自启动操作未完成","only actual autostart failure shown"); shown=true; message->accept();
        }
    }); dismiss.start(1);
    auto *buttons=window->findChild<QDialogButtonBox *>("buttonBox");
    buttons->button(QDialogButtonBox::Ok)->click();
    check(shown && window && window->isVisible(),"failed autostart leaves settings open");
    check(!ProfileManager().autoStartEnabled(),"failed autostart is not persisted as enabled");
    check(settings.value("JustConnect/ServerAddress")=="vpn.example.invalid" && QFileInfo::exists(cache),"failed apply preserves settings and authentication material");
    dismiss.stop(); window->findChild<QCheckBox *>("autoStartCheckBox")->setChecked(false);
    buttons->button(QDialogButtonBox::Ok)->click();
    check(settings.value("JustConnect/ServerAddress")=="changed.example.invalid" && !QFileInfo::exists(cache),"successful apply saves settings before removing obsolete authentication");
    app.processEvents();
    std::cout<<"PASS: real settings window failure propagation, state and auth preservation\n";
}
