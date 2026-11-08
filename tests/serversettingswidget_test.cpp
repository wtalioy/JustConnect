#include "application/profileservice.h"
#include "presentation/widgets/serversettingswidget.h"
#include "application/defaultsettings.h"
#include <QApplication>
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
    for(auto *field:QList<QWidget *>{address,port}) {
        auto *label=qobject_cast<QLabel *>(form->labelForField(field));
        check(label && label->buddy()==field && std::abs(label->geometry().center().y()-field->geometry().center().y())<=1,
            "server address and port labels are centered beside their styled fields");
    }
    check(rules->isVisibleTo(&editor),"domain DNS is directly editable without another settings layer");
    allowNodes->setChecked(true);
    const auto nodePolicy=ProfileService::load(editor.settingsValues());
    check(nodePolicy.tls.verify && nodePolicy.tls.allowUnverifiedNodes && !nodeWarning->isHidden() && warning->isHidden(),"node exception is explicit and leaves authentication verification enabled");
    verify->setChecked(false); ca->setPlainText("explicit private CA");
    check(!warning->isHidden(),"explicit unsafe choice shows an identity-protection warning");
    int endpointChanges = 0;
    QObject::connect(&editor, &ServerSettingsWidget::serverChanged, &editor, [&] { ++endpointChanges; });
    address->setText("draft.example.edu");
    port->setValue(9443);
    rules->setPlainText("service.custom.example 192.0.2.53");
    check(endpointChanges == 2 && editor.serverAddress() == "draft.example.edu" && editor.serverPort() == 9443,
        "custom endpoint changes notify and preserve the edited values");
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
        && caToggle->x()-caLabel->geometry().right()==9
        && std::abs(caLabel->geometry().center().y()-caToggle->geometry().center().y())<=1,
        "the CA arrow stays beside its label and the editor aligns with the DNS section");
    check(caToggle->isChecked() && ca->isVisibleTo(&editor),"a saved private CA is immediately visible for review");
    caToggle->click();
    check(ca->isHidden() && editor.settingsValues().value("JustConnect/TLSCAPEM")=="explicit private CA",
        "collapsing optional CA settings never changes the saved trust draft");
    caToggle->click();
    check(ca->isVisibleTo(&editor) && ca->toPlainText()=="explicit private CA","reopening optional CA preserves the draft");
    check(saved.value("JustConnect/ServerAddress")=="draft.example.edu" && saved.value("JustConnect/ProfileKind")=="Custom","explicit apply saves selected endpoint");
    settings.setValue("Common/NeedsConfiguration",true);
    editor.load(settings);
    check(!address->isReadOnly() && !port->isReadOnly() && editor.serverAddress() == "draft.example.edu",
        "an older server remains editable for explicit confirmation");
    settings.setValue("Common/NeedsConfiguration",false);
    settings.setValue("JustConnect/ProfileKind","Fudan");
    editor.load(settings);
    check(!editor.isBuiltIn() && editor.serverAddress()=="draft.example.edu","inconsistent saved preset never overwrites a valid custom endpoint");
    settings.setValue("JustConnect/ServerAddress","vpn.fudan.edu.cn");
    settings.setValue("JustConnect/ServerPort",443);
    settings.remove(DefaultSettings::DomainDnsRules);
    editor.load(settings);
    check(editor.isBuiltIn() && address->isReadOnly() && port->isReadOnly()
        && editor.serverAddress() == "vpn.fudan.edu.cn" && rules->toPlainText() == "zb.fudan.edu.cn",
        "Fudan displays its fixed endpoint and retains its default DNS");
    settings.setValue(DefaultSettings::DomainDnsRules,"");
    editor.load(settings);
    check(rules->toPlainText().isEmpty() && ProfileService::load(settings).dns.domainDnsRules.isEmpty(),
        "an explicitly removed preset rule stays removed");
    std::cout<<"PASS: fixed Fudan endpoint, independent custom draft and explicit apply\n";
}
