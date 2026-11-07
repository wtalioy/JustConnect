#include "application/profileservice.h"
#include "presentation/widgets/serversettingswidget.h"
#include "application/defaultsettings.h"
#include <QApplication>
#include <QComboBox>
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QLabel>
#include <QFile>
#include <QFormLayout>
#include <QLineEdit>
#include <QSettings>
#include <QSpinBox>
#include <QToolButton>
#include <QTemporaryDir>
#include <cstdlib>
#include <iostream>
static void check(bool ok,const char *message) { if (!ok) { std::cerr<<message<<'\n'; std::exit(1); } }
int main(int argc,char **argv) {
    QApplication app(argc,argv);
    QFile style(":/resource/appearance.qss");check(style.open(QIODevice::ReadOnly),"load the real shared input styles");
    app.setStyleSheet(QString::fromUtf8(style.readAll()));
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
    auto *rules=editor.findChild<QPlainTextEdit *>("domainDnsRulesEdit");
    auto *warning=editor.findChild<QLabel *>("tlsWarningLabel");
    auto *allowNodes=editor.findChild<QCheckBox *>("allowUnverifiedNodesCheckBox");
    auto *nodeWarning=editor.findChild<QLabel *>("nodeTlsWarningLabel");
    check(editor.settingsValues().value("JustConnect/TLSVerify").toBool() && warning->isHidden(),"legacy server settings enable certificate verification");
    check(!allowNodes->isChecked() && nodeWarning->isHidden(),"node verification remains enabled by default");
    editor.resize(540,560);editor.show();app.processEvents();
    auto *form=editor.findChild<QFormLayout *>();
    for(auto *field:QList<QWidget *>{preset,address,port}) {
        auto *label=qobject_cast<QLabel *>(form->labelForField(field));
        check(label && label->buddy()==field && std::abs(label->geometry().center().y()-field->geometry().center().y())<=1,
            "preset, server and port labels are centered beside their styled fields");
    }
    check(rules->isVisibleTo(&editor),"domain DNS is directly editable without another settings layer");
    allowNodes->setChecked(true);
    const auto nodePolicy=ProfileService::load(editor.settingsValues());
    check(nodePolicy.tls.verify && nodePolicy.tls.allowUnverifiedNodes && !nodeWarning->isHidden() && warning->isHidden(),"node exception is explicit and leaves authentication verification enabled");
    verify->setChecked(false); ca->setPlainText("explicit private CA");
    check(!warning->isHidden(),"explicit unsafe choice shows an identity-protection warning");
    address->setText("draft.example.edu"); port->setValue(9443);
    rules->setPlainText("service.custom.example 192.0.2.53");
    preset->setCurrentIndex(preset->findData("Fudan"));
    check(editor.prefersOAuth() && editor.serverAddress()=="vpn.fudan.edu.cn" && editor.serverPort()==443,"Fudan selects its server");
    check(rules->toPlainText()=="zb.fudan.edu.cn","preset supplies a name and uses the gateway DNS");
    rules->clear();
    check(address->isReadOnly() && !port->isEnabled(),"Fudan cannot retain a conflicting manual endpoint");
    preset->setCurrentIndex(preset->findData("Custom"));
    check(editor.serverAddress()=="draft.example.edu" && editor.serverPort()==9443,"Custom draft survives preset switching");
    check(rules->toPlainText()=="service.custom.example 192.0.2.53","preset DNS rules do not leak into Custom");
    QSettings unchanged(path,QSettings::IniFormat);
    check(unchanged.value("JustConnect/ServerAddress")=="custom.example.edu" && unchanged.value("JustConnect/ServerPort")==8443,"editing and cancelling do not save");
    if (!ProfileService::writePublic(settings,editor.settingsValues())) return 1;
    QSettings saved(path,QSettings::IniFormat);
    editor.load(saved);
    check(ProfileService::load(saved).dns.domainDnsRules=="service.custom.example 192.0.2.53","custom DNS rules survive save and reload");
    check(allowNodes->isChecked() && !nodeWarning->isHidden(),"explicit node policy and warning survive save and reload");
    check(!editor.settingsValues().value("JustConnect/TLSVerify").toBool() && editor.settingsValues().value("JustConnect/TLSCAPEM").toString()=="explicit private CA" && !warning->isHidden(),"explicit TLS policy survives save and reload");
    auto *caToggle=editor.findChild<QToolButton *>("serverCaToggle");
    app.processEvents();auto *caLabel=editor.findChild<QLabel *>("serverCaLabel");
    check(caLabel && caLabel->buddy()==caToggle && caLabel->x()==ca->x() && ca->x()==rules->x()
        && std::abs(caLabel->geometry().center().y()-caToggle->geometry().center().y())<=1,
        "CA disclosure title, trailing action and expanded editor align with the DNS section");
    check(caToggle->isChecked() && ca->isVisibleTo(&editor),"a saved private CA is immediately visible for review");
    caToggle->click();
    check(ca->isHidden() && editor.settingsValues().value("JustConnect/TLSCAPEM")=="explicit private CA",
        "collapsing optional CA settings never changes the saved trust draft");
    caToggle->click();
    check(ca->isVisibleTo(&editor) && ca->toPlainText()=="explicit private CA","reopening optional CA preserves the draft");
    check(saved.value("JustConnect/ServerAddress")=="draft.example.edu" && saved.value("JustConnect/ProfileKind")=="Custom","explicit apply saves selected endpoint");
    settings.setValue("Common/NeedsConfiguration",true);
    editor.load(settings);
    check(preset->count()==2 && preset->findData("Fudan")>=0 && preset->findData("Custom")>=0,
        "the server popup lists only real choices");
    check(preset->currentIndex()==-1 && !preset->placeholderText().isEmpty() && editor.serverAddress().isEmpty(),
        "legacy protocol requires an explicit new selection with an inline prompt");
    preset->setCurrentIndex(preset->findData("Custom"));
    check(editor.serverAddress()=="draft.example.edu","legacy endpoint remains available for manual confirmation");
    settings.setValue("Common/NeedsConfiguration",false);
    settings.setValue("JustConnect/ProfileKind","Fudan");
    editor.load(settings);
    check(!editor.prefersOAuth() && editor.serverAddress()=="draft.example.edu","inconsistent saved preset never overwrites a valid custom endpoint");
    settings.setValue("JustConnect/ServerAddress","vpn.fudan.edu.cn");
    settings.setValue("JustConnect/ServerPort",443);
    settings.setValue(DefaultSettings::DomainDnsRules,"");
    editor.load(settings);
    check(rules->toPlainText().isEmpty() && ProfileService::load(settings).dns.domainDnsRules.isEmpty(),
        "an explicitly removed preset rule stays removed");
    std::cout<<"PASS: Fudan/Custom switching, draft preservation and explicit apply\n";
}
