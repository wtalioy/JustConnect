#include "serversettingswidget.h"
#include <QComboBox>
#include <QEvent>
#include <QToolButton>
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
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0,0,0,0);
    layout->setSpacing(16);
    form = new QFormLayout;
    form->setRowWrapPolicy(QFormLayout::WrapAllRows);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setVerticalSpacing(8);
    preset = new QComboBox(this);
    preset->setObjectName("profileKindComboBox");
    preset->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    preset->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Fixed);
    preset->addItem(QString(), "");
    const auto builtInKind=DefaultSettings::builtInProfile().value("JustConnect/ProfileKind").toString();
    preset->addItem(builtInKind,builtInKind);
    preset->addItem(QString(), "Custom");
    address = new QLineEdit(this);
    address->setObjectName("serverAddressLineEdit");
    address->setPlaceholderText("vpn.example.edu.cn");
    port = new QSpinBox(this);
    port->setObjectName("serverPortSpinBox");
    port->setRange(1,65535); port->setValue(443);
    form->addRow(new QLabel(this),preset); form->addRow(new QLabel(this),address); form->addRow(new QLabel(this),port);
    layout->addLayout(form);

    securitySummary = new QLabel(this);
    securitySummary->setObjectName("securitySummaryLabel");
    securitySummary->setWordWrap(true);
    layout->addWidget(securitySummary);
    advancedButton = new QToolButton(this);
    advancedButton->setObjectName("advancedServerButton");
    advancedButton->setCheckable(true);
    advancedButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    advancedButton->setArrowType(Qt::RightArrow);
    layout->addWidget(advancedButton,0,Qt::AlignLeft);
    auto *advanced = new QWidget(this);
    advanced->hide();
    advancedForm = new QFormLayout(advanced);
    advancedForm->setContentsMargins(0,0,0,0);
    advancedForm->setRowWrapPolicy(QFormLayout::WrapAllRows);
    advancedForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    advancedForm->setVerticalSpacing(8);
    layout->addWidget(advanced);
    connect(advancedButton,&QToolButton::toggled,advanced,[this,advanced](bool expanded){
        advanced->setVisible(expanded);
        advancedButton->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
    });
    verify=new QCheckBox(this);
    verify->setObjectName("tlsVerifyCheckBox"); verify->setChecked(TlsOptions{}.verify);
    warning=new QLabel(this);
    warning->setObjectName("tlsWarningLabel"); warning->setWordWrap(true); warning->hide();
    allowUnverifiedNodes=new QCheckBox(this);
    allowUnverifiedNodes->setObjectName("allowUnverifiedNodesCheckBox");
    nodeWarning=new QLabel(this);
    nodeWarning->setObjectName("nodeTlsWarningLabel"); nodeWarning->setWordWrap(true); nodeWarning->hide();
    auto *tlsOptions=new QVBoxLayout;
    tlsOptions->addWidget(verify); tlsOptions->addWidget(warning);
    tlsOptions->addWidget(allowUnverifiedNodes); tlsOptions->addWidget(nodeWarning);
    advancedForm->addRow("TLS",tlsOptions);
    caPem=new QPlainTextEdit(this); caPem->setObjectName("tlsCaPemEdit"); caPem->setMaximumHeight(96);
    advancedForm->addRow(new QLabel(this),caPem);
    domainDnsRules=new QPlainTextEdit(this);
    domainDnsRules->setObjectName("domainDnsRulesEdit");
    domainDnsRules->setMaximumHeight(112);
    domainDnsRules->setPlaceholderText("host.example.edu\nother.example.edu 192.0.2.53");
    rulesHelp=new QLabel(this);
    rulesHelp->setWordWrap(true);
    auto *rulesLayout=new QVBoxLayout;
    rulesLayout->addWidget(domainDnsRules);
    rulesLayout->addWidget(rulesHelp);
    domainDnsLabel=new QLabel(this);
    advancedForm->addRow(domainDnsLabel,rulesLayout);
    connect(verify,&QCheckBox::toggled,this,[this](bool checked){warning->setVisible(!checked);updateSecuritySummary();});
    connect(allowUnverifiedNodes,&QCheckBox::toggled,this,[this](bool checked){nodeWarning->setVisible(checked);updateSecuritySummary();});
    connect(preset,&QComboBox::currentIndexChanged,this,&ServerSettingsWidget::selectPreset);
    connect(address,&QLineEdit::textChanged,this,&ServerSettingsWidget::serverChanged);
    connect(port,&QSpinBox::valueChanged,this,&ServerSettingsWidget::serverChanged);
    retranslate();
    selectPreset();
}
void ServerSettingsWidget::changeEvent(QEvent *event) {
    QWidget::changeEvent(event);
    if(event->type()==QEvent::LanguageChange) retranslate();
}
void ServerSettingsWidget::retranslate() {
    QSignalBlocker blocker(preset);
    preset->setItemText(0,tr("Choose a school or server"));
    preset->setItemText(preset->findData("Custom"),tr("Custom"));
    qobject_cast<QLabel *>(form->labelForField(preset))->setText(tr("School"));
    qobject_cast<QLabel *>(form->labelForField(address))->setText(tr("Server"));
    qobject_cast<QLabel *>(form->labelForField(port))->setText(tr("Port"));
    advancedButton->setText(tr("Advanced"));
    verify->setText(tr("Verify server certificate"));
    warning->setText(tr("Disabling verification removes server identity protection. A connection failure never disables it automatically."));
    allowUnverifiedNodes->setText(tr("Skip tunnel verification"));
    nodeWarning->setText(tr("The tunnel stays encrypted, but its peer is not verified. Sign-in and resource verification stay unchanged."));
    qobject_cast<QLabel *>(advancedForm->labelForField(caPem))->setText(tr("Additional CA"));
    caPem->setPlaceholderText(tr("Optional school CA in PEM format. Leave empty to use system trust."));
    domainDnsLabel->setText(tr("Domain DNS"));
    QString help=tr("One full domain per line. Append IPv4 DNS servers separated by spaces, or leave them out to use gateway DNS.");
#ifndef Q_OS_WIN
    help+=" "+tr("Use the local application proxy for domains not published by the gateway.");
#endif
    rulesHelp->setText(help);
    updateSecuritySummary();
}
void ServerSettingsWidget::updateSecuritySummary() {
    QStringList warnings;
    if(!verify->isChecked()) warnings.append(tr("Server identity verification is off."));
    if(allowUnverifiedNodes->isChecked()) warnings.append(tr("Tunnel identity verification is off."));
    securitySummary->setText(warnings.join(' '));
    securitySummary->setVisible(!warnings.isEmpty());
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
