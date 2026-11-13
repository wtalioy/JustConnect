#include "application/savedconnectionservice.h"
#include "presentation/widgets/serversettingswidget.h"
#include "application/defaultsettings.h"
#include "application/clashextension.h"
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QPlainTextEdit>
#include <QLabel>
#include <QFile>
#include <QFormLayout>
#include <QLineEdit>
#include <QSettings>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QProcess>
#include <QStandardPaths>
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
    auto *dnsHelp=editor.findChild<QLabel *>("domainDnsHelp");
    auto *warning=editor.findChild<QLabel *>("tlsWarningLabel");
    auto *allowNodes=editor.findChild<QCheckBox *>("allowUnverifiedNodesCheckBox");
    auto *nodeWarning=editor.findChild<QLabel *>("nodeTlsWarningLabel");
    check(editor.settingsValues().value("JustConnect/TLSVerify").toBool() && warning->isHidden(),"legacy server settings enable certificate verification");
    check(!allowNodes->isChecked() && nodeWarning->isHidden(),"node verification remains enabled by default");
    editor.resize(540,560);editor.show();app.processEvents();
    auto *form=editor.findChild<QFormLayout *>();
    auto *mode=editor.findChild<QComboBox *>("routingModeComboBox");
    auto *localPort=editor.findChild<QSpinBox *>("localSocksPortSpinBox");
    auto *campusTargets=editor.findChild<QPlainTextEdit *>("campusTargetsEdit");
    for(auto *field:QList<QWidget *>{address,port,mode}) {
        auto *label=qobject_cast<QLabel *>(form->labelForField(field));
        check(label && label->buddy()==field && std::abs(label->geometry().center().y()-field->geometry().center().y())<=1,
            "server address and port labels are centered beside their styled fields");
    }
    check(mode->currentIndex()==0 && mode->y()>port->y() && mode->y()<verify->y()
        && localPort->isHidden() && campusTargets->isHidden(),"mode is near the top and only local mode shows proxy fields");
    mode->setCurrentIndex(1);
    localPort->setValue(32081);
    campusTargets->setPlainText("Campus.Example.Edu.\n192.0.2.18\ncampus.example.edu");
    auto local=SavedConnectionService::load(editor.settingsValues());
    check(local.routingMode==RoutingMode::LocalProxy && local.proxy.socksBind=="127.0.0.1:32081",
        "local settings share one port");
    check(!localPort->isHidden() && !campusTargets->isHidden(),"local settings are visible");
    check(rules->isVisibleTo(&editor) && dnsHelp && dnsHelp->text().contains("Clash"),
        "local mode explains that DNS does not add Clash routes");
    app.processEvents();
    auto *campusLabel=editor.findChild<QLabel *>("clashCampusRoutesLabel");
    check(campusLabel && campusLabel->buddy()==campusTargets && campusLabel->x()==ca->x()
        && campusTargets->x()==ca->x() && campusTargets->width()==ca->width()
        && campusTargets->maximumHeight()==ca->maximumHeight() && campusLabel->y()<campusTargets->y(),
        "Clash routes use the same full-width text section as Server CA");
    const auto script=ClashExtension::script(local);
    check(!script.isEmpty(),"valid exact targets can be exported offline");
    const auto node=QStandardPaths::findExecutable("node");
    if (!node.isEmpty()) {
        QProcess js;
        js.start(node,{"-"});
        check(js.waitForStarted(),"start JavaScript runtime");
        js.write(script.toUtf8());
        js.write(R"JS(
const assert = require("node:assert/strict");
const original = {name:"校园网", type:"http", server:"example.net", port:80};
const groups = [{name:"校园网 2", type:"select", proxies:["DIRECT"]}];
const rules = ["DOMAIN-SUFFIX,example.edu,DIRECT", "MATCH,DIRECT"];
const dns = {enable:true};
const config = main({proxies:[original], "proxy-groups":groups, rules, dns});
assert.deepEqual(config.proxies,[original,{name:"校园网 3",type:"socks5",server:"127.0.0.1",port:32081,udp:true}]);
assert.deepEqual(config.rules,[
  "DOMAIN,campus.example.edu,校园网 3",
  "IP-CIDR,192.0.2.18/32,校园网 3,no-resolve", ...rules]);
assert.equal(config["proxy-groups"],groups);
assert.equal(config.dns,dns);
const once = JSON.stringify(config);
assert.equal(JSON.stringify(main(config)),once);
)JS");
        js.closeWriteChannel();
        check(js.waitForFinished(),"Clash script test finished");
        check(js.exitStatus()==QProcess::NormalExit && js.exitCode()==0,js.readAllStandardError().constData());
    }
    local.campusTargets="campus.example.edu\n*.example.edu";
    check(ClashExtension::invalidTargetLine(local)==2 && ClashExtension::script(local).isEmpty(),"wildcards are rejected with their line number");
    local.campusTargets=local.endpoint.server;
    check(ClashExtension::invalidTargetLine(local)==1,"the gateway cannot be routed back to the listener");
    local.campusTargets="2001:db8::18";
    check(ClashExtension::invalidTargetLine(local)==1,"IPv6 targets are unavailable on the aTrust data path");
    mode->setCurrentIndex(0);
    check(rules->isVisibleTo(&editor) && !dnsHelp->text().contains("Clash"),
        "automatic routing keeps domain DNS editable without Clash guidance");
    allowNodes->setChecked(true);
    const auto nodePolicy=SavedConnectionService::load(editor.settingsValues());
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
    if (!SavedConnectionService::writePublic(settings,editor.settingsValues())) return 1;
    QSettings saved(path,QSettings::IniFormat);
    editor.load(saved);
    check(SavedConnectionService::load(saved).campusTargets==campusTargets->toPlainText()
        && campusTargets->toPlainText().contains("192.0.2.18") && campusTargets->isHidden(),
        "switching modes preserves saved campus targets");
    check(SavedConnectionService::load(saved).dns.domainDnsRules=="service.custom.example 192.0.2.53","custom DNS rules survive save and reload");
    check(allowNodes->isChecked() && !nodeWarning->isHidden(),"explicit node policy and warning survive save and reload");
    check(!editor.settingsValues().value("JustConnect/TLSVerify").toBool() && editor.settingsValues().value("JustConnect/TLSCAPEM").toString()=="explicit private CA" && !warning->isHidden(),"explicit TLS policy survives save and reload");
    app.processEvents();
    auto *caLabel=editor.findChild<QLabel *>("serverCaLabel");
    check(caLabel && caLabel->buddy()==ca && caLabel->x()==ca->x() && ca->x()==rules->x()
        && ca->width()==rules->width() && ca->maximumHeight()==rules->maximumHeight(),
        "the CA and DNS editors use aligned labels and matching field sizes");
    check(ca->isVisibleTo(&editor) && ca->toPlainText()=="explicit private CA",
        "the CA editor is visible and preserves the stored certificate");
    check(saved.value("JustConnect/ServerAddress")=="draft.example.edu" && saved.value("JustConnect/ConnectionKind")=="Custom","explicit apply saves selected endpoint");
    settings.setValue("Common/NeedsConfiguration",true);
    editor.load(settings);
    check(!address->isReadOnly() && !port->isReadOnly() && editor.serverAddress() == "draft.example.edu",
        "an older server remains editable for explicit confirmation");
    settings.setValue("Common/NeedsConfiguration",false);
    settings.setValue("JustConnect/ConnectionKind","Fudan");
    editor.load(settings);
    check(!editor.isBuiltIn() && editor.serverAddress()=="draft.example.edu","inconsistent saved preset never overwrites a valid custom endpoint");
    DefaultSettings::applyBuiltInConnection(settings);
    editor.load(settings);
    check(editor.isBuiltIn() && address->isReadOnly() && port->isReadOnly()
        && editor.serverAddress() == "vpn.fudan.edu.cn" && rules->toPlainText() == "zb.fudan.edu.cn"
        && campusTargets->toPlainText()=="zb.fudan.edu.cn\nicourse.fudan.edu.cn\nlibrary.fudan.edu.cn",
        "Fudan displays its fixed endpoint and has distinct defaults for DNS and Clash routes");
    settings.remove("JustConnect/TLSVerify");
    editor.load(settings);
    check(verify->isChecked() && allowNodes->isChecked() && SavedConnectionService::load(settings).tls.allowUnverifiedNodes,
        "Fudan skips tunnel verification by default while verifying the sign-in server");
    settings.setValue("JustConnect/AllowUnverifiedNodes",false);
    DefaultSettings::initialize(settings);
    editor.load(settings);
    check(!allowNodes->isChecked() && !SavedConnectionService::load(settings).tls.allowUnverifiedNodes,
        "initialization preserves a saved choice to verify the tunnel");
    settings.setValue(DefaultSettings::DomainDnsRules,"");
    editor.load(settings);
    check(ca->isVisibleTo(&editor) && !ca->placeholderText().isEmpty(),
        "the CA editor stays visible with its existing PEM hint");
    check(rules->toPlainText().isEmpty() && SavedConnectionService::load(settings).dns.domainDnsRules.isEmpty(),
        "an explicitly removed preset rule stays removed");
    std::cout<<"PASS: fixed Fudan endpoint, independent custom draft and explicit apply\n";
}
