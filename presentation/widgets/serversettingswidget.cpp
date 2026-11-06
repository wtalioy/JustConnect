#include "serversettingswidget.h"
#include "presentation/presentationhelpers.h"
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
    layout->setSpacing(12);
    form = new QFormLayout;
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setContentsMargins(0,0,0,0);
    form->setHorizontalSpacing(12);
    form->setVerticalSpacing(8);
    form->setLabelAlignment(Qt::AlignLeft|Qt::AlignVCenter);
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

    verify=new QCheckBox(this);
    verify->setObjectName("tlsVerifyCheckBox"); verify->setChecked(TlsOptions{}.verify);
    warning=new QLabel(this);
    warning->setObjectName("tlsWarningLabel"); warning->setWordWrap(true); warning->hide();
    warning->setProperty("warning",true);
    allowUnverifiedNodes=new QCheckBox(this);
    allowUnverifiedNodes->setObjectName("allowUnverifiedNodesCheckBox");
    nodeWarning=new QLabel(this);
    nodeWarning->setObjectName("nodeTlsWarningLabel"); nodeWarning->setWordWrap(true); nodeWarning->hide();
    nodeWarning->setProperty("warning",true);
    auto *tlsOptions=new QVBoxLayout;
    tlsOptions->setContentsMargins(0,0,0,0);tlsOptions->setSpacing(4);
    tlsOptions->addWidget(verify); tlsOptions->addWidget(warning);
    tlsOptions->addWidget(allowUnverifiedNodes); tlsOptions->addWidget(nodeWarning);
    layout->addLayout(tlsOptions);
    caToggle=new QToolButton(this);caToggle->setObjectName("schoolCaToggle");
    caToggle->setCheckable(true);caToggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    PresentationHelpers::setButtonIcon(caToggle,":/resource/chevron-right.svg");
    layout->addWidget(caToggle,0,Qt::AlignLeft);
    caPem=new QPlainTextEdit(this); caPem->setObjectName("tlsCaPemEdit"); caPem->setMaximumHeight(88);caPem->hide();
    layout->addWidget(caPem);
    connect(caToggle,&QToolButton::toggled,this,[this](bool open) {caPem->setVisible(open);PresentationHelpers::setButtonIcon(caToggle,open?":/resource/chevron.svg":":/resource/chevron-right.svg");});
    domainDnsRules=new QPlainTextEdit(this);
    domainDnsRules->setObjectName("domainDnsRulesEdit");
    domainDnsRules->setMaximumHeight(112);
    domainDnsRules->setPlaceholderText("host.example.edu\nother.example.edu 192.0.2.53");
    rulesHelp=new QLabel(this);
    rulesHelp->setWordWrap(true);rulesHelp->setProperty("secondary",true);
    domainDnsLabel=new QLabel(this);
    domainDnsLabel->setBuddy(domainDnsRules);
    layout->addWidget(domainDnsLabel);layout->addWidget(domainDnsRules);layout->addWidget(rulesHelp);
    layout->addStretch();
    connect(verify,&QCheckBox::toggled,warning,[this](bool checked){warning->setVisible(!checked);});
    connect(allowUnverifiedNodes,&QCheckBox::toggled,nodeWarning,&QLabel::setVisible);
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
    verify->setText(tr("Verify server certificate"));
    warning->setText(tr("The server's identity will not be verified."));
    allowUnverifiedNodes->setText(tr("Skip tunnel verification"));
    nodeWarning->setText(tr("The tunnel peer will not be verified. Sign-in verification is unchanged."));
    caToggle->setText(tr("School CA (optional)"));
    caPem->setAccessibleName(tr("School CA (optional)"));
    caPem->setPlaceholderText(tr("Optional school CA in PEM format. Leave empty to use system trust."));
    domainDnsLabel->setText(tr("Domain DNS"));
    QString help=tr("One domain per line; optional IPv4 DNS servers after it. Otherwise use gateway DNS.");
#ifndef Q_OS_WIN
    help+=" "+tr("Use the local application proxy for domains not published by the gateway.");
#endif
    rulesHelp->setText(help);
}
void ServerSettingsWidget::load(const QSettings &settings) {
    QSignalBlocker blocker(this), presetBlocker(preset);
    verify->setChecked(settings.value("JustConnect/TLSVerify",TlsOptions{}.verify).toBool());
    caPem->setPlainText(settings.value("JustConnect/TLSCAPEM").toString());
    caToggle->setChecked(!caPem->toPlainText().isEmpty());
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
    form->setRowVisible(address,kind=="Custom");form->setRowVisible(port,kind=="Custom");
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
