#include "serversettingswidget.h"
#include <QComboBox>
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QLabel>
#include <QFormLayout>
#include <QLineEdit>
#include <QSettings>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QVBoxLayout>
#include "application/defaultsettings.h"
#include "core/connectionprofile.h"

ServerSettingsWidget::ServerSettingsWidget(QWidget *parent) : QWidget(parent) {
    auto *form = new QFormLayout(this);
    form->setContentsMargins(0,0,0,0);
    form->setFormAlignment(Qt::AlignLeft|Qt::AlignTop);
    preset = new QComboBox(this);
    preset->setObjectName("profileKindComboBox");
    preset->addItem("请选择入口", "");
    const auto builtInKind=DefaultSettings::builtInProfile().value("JustConnect/ProfileKind").toString();
    preset->addItem(builtInKind,builtInKind);
    preset->addItem("Custom", "Custom");
    address = new QLineEdit(this);
    address->setObjectName("serverAddressLineEdit");
    address->setPlaceholderText("vpn.example.edu.cn");
    port = new QSpinBox(this);
    port->setObjectName("serverPortSpinBox");
    port->setRange(1,65535); port->setValue(443);
    form->addRow("入口",preset); form->addRow("服务器地址",address); form->addRow("服务器端口",port);
    verify=new QCheckBox("验证服务器证书（推荐）",this);
    verify->setObjectName("tlsVerifyCheckBox"); verify->setChecked(TlsOptions{}.verify);
    auto *warning=new QLabel("关闭验证会失去服务器身份保护；不会因连接失败自动关闭。",this);
    warning->setObjectName("tlsWarningLabel"); warning->setWordWrap(true); warning->setVisible(false);
    allowUnverifiedNodes=new QCheckBox("跳过隧道证书校验",this);
    allowUnverifiedNodes->setObjectName("allowUnverifiedNodesCheckBox");
    auto *nodeWarning=new QLabel("隧道仍加密，但不验证对端身份。登录与资源请求的校验设置保持不变。",this);
    nodeWarning->setObjectName("nodeTlsWarningLabel"); nodeWarning->setWordWrap(true); nodeWarning->hide();
    auto *tlsOptions=new QVBoxLayout;
    tlsOptions->setAlignment(Qt::AlignTop);
    tlsOptions->addWidget(verify); tlsOptions->addWidget(warning);
    auto *nodeException=new QVBoxLayout;
    nodeException->setAlignment(Qt::AlignTop);
    nodeException->setContentsMargins(20,0,0,0);
    nodeException->addWidget(allowUnverifiedNodes); nodeException->addWidget(nodeWarning);
    tlsOptions->addLayout(nodeException);
    form->addRow("TLS",tlsOptions);
    caPem=new QPlainTextEdit(this); caPem->setObjectName("tlsCaPemEdit"); caPem->setMaximumHeight(72);
    caPem->setPlaceholderText("可选：学校提供的 PEM 格式 CA 证书；留空使用系统信任。");
    form->addRow("附加 CA",caPem);
    domainDnsRules=new QPlainTextEdit(this);
    domainDnsRules->setObjectName("domainDnsRulesEdit");
    domainDnsRules->setMaximumHeight(90);
    domainDnsRules->setPlaceholderText("host.example.edu\nother.example.edu 192.0.2.53");
    QString help="每行一个完整域名。用空格追加 DNS 服务器的 IPv4 地址，或留空使用当前网关 DNS。";
#ifndef Q_OS_WIN
    help+=" 对网关未发布的域名，请通过应用的本地代理访问。";
#endif
    auto *rulesHelp=new QLabel(help,this);
    rulesHelp->setWordWrap(true);
    auto *rulesLayout=new QVBoxLayout;
    rulesLayout->addWidget(domainDnsRules);
    rulesLayout->addWidget(rulesHelp);
    form->addRow("域名专用 DNS",rulesLayout);
    connect(verify,&QCheckBox::toggled,warning,[warning](bool checked){warning->setVisible(!checked);});
    connect(allowUnverifiedNodes,&QCheckBox::toggled,nodeWarning,&QLabel::setVisible);
    connect(preset,&QComboBox::currentIndexChanged,this,&ServerSettingsWidget::selectPreset);
    connect(address,&QLineEdit::textChanged,this,&ServerSettingsWidget::serverChanged);
    connect(port,&QSpinBox::valueChanged,this,&ServerSettingsWidget::serverChanged);
    selectPreset();
}
void ServerSettingsWidget::load(const QSettings &settings) {
    QSignalBlocker blocker(this), presetBlocker(preset);
    verify->setChecked(settings.value("JustConnect/TLSVerify",TlsOptions{}.verify).toBool());
    caPem->setPlainText(settings.value("JustConnect/TLSCAPEM").toString());
    allowUnverifiedNodes->setChecked(settings.value("JustConnect/AllowUnverifiedNodes",TlsOptions{}.allowUnverifiedNodes).toBool());
    customAddress = settings.value("JustConnect/ServerAddress").toString();
    customPort = settings.value("JustConnect/ServerPort",443).toInt();
    QString kind = settings.value("JustConnect/ProfileKind","Custom").toString();
    if (settings.value("Common/NeedsConfiguration",false).toBool()) kind.clear();
    if (!kind.isEmpty() && kind!="Custom" && kind!=DefaultSettings::profileKindForEndpoint(customAddress,customPort)) kind="Custom";
    const auto saved = DefaultSettings::publicValues(settings);
    domainDnsDrafts.clear();
    if (!kind.isEmpty()) domainDnsDrafts[kind]=DefaultSettings::domainDnsRules(saved);
    preset->setCurrentIndex(preset->findData(kind));
    previousPreset.clear();
    selectPreset();
}
void ServerSettingsWidget::selectPreset() {
    const auto kind = preset->currentData().toString();
    if (previousPreset == "Custom") { customAddress = address->text(); customPort = port->value(); }
    if (!previousPreset.isEmpty()) domainDnsDrafts[previousPreset]=domainDnsRules->toPlainText();
    const auto &defaults=DefaultSettings::builtInProfile();
    const bool builtIn=defaults.value("JustConnect/ProfileKind")==kind;
    address->setText(builtIn ? defaults.value("JustConnect/ServerAddress").toString() : customAddress);
    port->setValue(builtIn ? defaults.value("JustConnect/ServerPort").toInt() : customPort);
    address->setReadOnly(kind != "Custom"); port->setEnabled(kind == "Custom");
    domainDnsRules->setPlainText(domainDnsDrafts.value(kind,builtIn ? defaults.value(DefaultSettings::DomainDnsRules).toString() : QString()));
    domainDnsRules->setEnabled(!kind.isEmpty());
    previousPreset = kind;
    emit serverChanged();
}
QString ServerSettingsWidget::serverAddress() const { return preset->currentData().toString().isEmpty() ? QString() : address->text().trimmed(); }
int ServerSettingsWidget::serverPort() const { return port->value(); }
bool ServerSettingsWidget::prefersOAuth() const {
    const auto &defaults=DefaultSettings::builtInProfile();
    return preset->currentData()==defaults.value("JustConnect/ProfileKind") && defaults.value("JustConnect/AuthType")=="httpsOauth2";
}
QVariantMap ServerSettingsWidget::settingsValues() const {
    return {{"JustConnect/TLSVerify",verify->isChecked()},{"JustConnect/TLSCAPEM",caPem->toPlainText()},
        {"JustConnect/AllowUnverifiedNodes",allowUnverifiedNodes->isChecked()},
        {"JustConnect/ProfileKind",preset->currentData()},{"JustConnect/ServerAddress",serverAddress()},
        {"JustConnect/ServerPort",serverPort()},{DefaultSettings::DomainDnsRules,domainDnsRules->toPlainText().trimmed()},
        {"Common/NeedsConfiguration",false}};
}
