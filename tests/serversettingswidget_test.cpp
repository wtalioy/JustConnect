#include "presentation/widgets/serversettingswidget.h"
#include "application/applicationconstants.h"
#include <QApplication>
#include <QComboBox>
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QLabel>
#include <QLineEdit>
#include <QSettings>
#include <QSpinBox>
#include <QTemporaryDir>
#include <cstdlib>
#include <iostream>
static void check(bool ok,const char *message) { if (!ok) { std::cerr<<message<<'\n'; std::exit(1); } }
int main(int argc,char **argv) {
    QApplication app(argc,argv);
    QTemporaryDir directory;
    check(directory.isValid(),"isolated server settings");
    const auto path=directory.filePath("profile.ini");
    QSettings settings(path,QSettings::IniFormat);
    settings.setValue("JustConnect/ServerAddress","custom.example.edu");
    settings.setValue("JustConnect/ServerPort",8443); settings.sync();
    ServerSettingsWidget editor;
    editor.load(settings);
    auto *preset=editor.findChild<QComboBox *>("profileKindComboBox");
    auto *address=editor.findChild<QLineEdit *>("serverAddressLineEdit");
    auto *port=editor.findChild<QSpinBox *>("serverPortSpinBox");
    auto *verify=editor.findChild<QCheckBox *>("tlsVerifyCheckBox");
    auto *ca=editor.findChild<QPlainTextEdit *>("tlsCaPemEdit");
    auto *warning=editor.findChild<QLabel *>("tlsWarningLabel");
    check(editor.tlsOptions().verify && warning->isHidden(),"legacy server settings enable certificate verification");
    verify->setChecked(false); ca->setPlainText("explicit private CA");
    check(!warning->isHidden(),"explicit unsafe choice shows an identity-protection warning");
    address->setText("draft.example.edu"); port->setValue(9443);
    preset->setCurrentIndex(preset->findData("Fudan"));
    check(editor.isFudan() && editor.serverAddress()==ApplicationConstants::FudanServer && editor.serverPort()==443,"Fudan selects its server");
    check(address->isReadOnly() && !port->isEnabled(),"Fudan cannot retain a conflicting manual endpoint");
    preset->setCurrentIndex(preset->findData("Custom"));
    check(editor.serverAddress()=="draft.example.edu" && editor.serverPort()==9443,"Custom draft survives preset switching");
    QSettings unchanged(path,QSettings::IniFormat);
    check(unchanged.value("JustConnect/ServerAddress")=="custom.example.edu" && unchanged.value("JustConnect/ServerPort")==8443,"editing and cancelling do not save");
    editor.applyTo(settings); settings.sync();
    QSettings saved(path,QSettings::IniFormat);
    editor.load(saved);
    check(!editor.tlsOptions().verify && editor.tlsOptions().caPem=="explicit private CA" && !warning->isHidden(),"explicit TLS policy survives save and reload");
    check(saved.value("JustConnect/ServerAddress")=="draft.example.edu" && saved.value("JustConnect/ProfileKind")=="Custom","explicit apply saves selected endpoint");
    settings.setValue("Common/NeedsConfiguration",true);
    editor.load(settings);
    check(editor.serverAddress().isEmpty(),"legacy protocol requires an explicit new selection");
    preset->setCurrentIndex(preset->findData("Custom"));
    check(editor.serverAddress()=="draft.example.edu","legacy endpoint remains available for manual confirmation");
    settings.setValue("Common/NeedsConfiguration",false);
    settings.setValue("JustConnect/ProfileKind","Fudan");
    editor.load(settings);
    check(!editor.isFudan() && editor.serverAddress()=="draft.example.edu","inconsistent saved preset never overwrites a valid custom endpoint");
    std::cout<<"PASS: Fudan/Custom switching, draft preservation and explicit apply\n";
}
