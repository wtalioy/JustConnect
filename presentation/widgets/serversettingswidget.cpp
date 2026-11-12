#include "serversettingswidget.h"
#include <QEvent>
#include "presentation/widgets/alignedcheckbox.h"
#include <QPlainTextEdit>
#include <QComboBox>
#include <QLabel>
#include <QFormLayout>
#include <QLineEdit>
#include <QSettings>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QStyle>
#include <QVBoxLayout>
#include "application/defaultsettings.h"
#include "core/connectionoptions.h"

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
    address = new QLineEdit(this);
    address->setObjectName("serverAddressLineEdit");
    address->setPlaceholderText("vpn.example.edu.cn");
    port = new QSpinBox(this);
    port->setObjectName("serverPortSpinBox");
    port->setRange(1,65535); port->setValue(443);
    routingMode=new QComboBox(this);
    routingMode->setObjectName("routingModeComboBox");
    routingMode->addItem(QString{},QString::fromLatin1(DefaultSettings::AutomaticMode));
    routingMode->addItem(QString{},QString::fromLatin1(DefaultSettings::LocalProxyMode));
    socksPort=new QSpinBox(this);
    socksPort->setObjectName("localSocksPortSpinBox");
    socksPort->setRange(0,65535);
    socksPort->setValue(DefaultSettings::DefaultSocksPort);
    campusTargets=new QPlainTextEdit(this);
    campusTargets->setObjectName("campusTargetsEdit");
    campusTargets->setMaximumHeight(112);
    clashHelp=new QLabel(this);
    clashHelp->setWordWrap(true);
    clashHelp->setProperty("secondary",true);
    connect(routingMode,&QComboBox::currentIndexChanged,this,&ServerSettingsWidget::updateRoutingFields);
    for(auto *field:QList<QWidget *>{address,port,routingMode,socksPort}) {
        auto *label=new QLabel(this);label->setBuddy(field);
        // QFormLayout otherwise caps label height at 7/4 of its text height, above our taller inputs.
        label->setSizePolicy(QSizePolicy::Preferred,QSizePolicy::Expanding);
        form->addRow(label,field);
    }
    form->addRow(new QLabel(this),campusTargets);
    qobject_cast<QLabel *>(form->labelForField(campusTargets))->setBuddy(campusTargets);
    form->addRow(clashHelp);
    layout->addLayout(form);
    layout->addSpacing(8);

    verify=new AlignedCheckBox(this);
    verify->setObjectName("tlsVerifyCheckBox"); verify->setChecked(TlsOptions{}.verify);
    warning=new QLabel(this);
    warning->setObjectName("tlsWarningLabel"); warning->setWordWrap(true); warning->hide();
    warning->setProperty("warning",true);
    allowUnverifiedNodes=new AlignedCheckBox(this);
    allowUnverifiedNodes->setObjectName("allowUnverifiedNodesCheckBox");
    nodeWarning=new QLabel(this);
    nodeWarning->setObjectName("nodeTlsWarningLabel"); nodeWarning->setWordWrap(true); nodeWarning->hide();
    nodeWarning->setProperty("warning",true);
    auto *tlsOptions=new QVBoxLayout;
    tlsOptions->setContentsMargins(0,0,0,0);tlsOptions->setSpacing(4);
    tlsOptions->addWidget(verify); tlsOptions->addWidget(warning);
    tlsOptions->addWidget(allowUnverifiedNodes); tlsOptions->addWidget(nodeWarning);
    layout->addLayout(tlsOptions);
    auto *caSection=new QVBoxLayout;caSection->setContentsMargins(0,0,0,0);caSection->setSpacing(8);
    caLabel=new QLabel(this);caLabel->setObjectName("serverCaLabel");caLabel->setMinimumHeight(28);
    caPem=new QPlainTextEdit(this);caPem->setObjectName("tlsCaPemEdit");caPem->setMaximumHeight(112);
    caLabel->setBuddy(caPem);
    caSection->addWidget(caLabel);caSection->addWidget(caPem);layout->addLayout(caSection);
    layout->addSpacing(8);
    domainDnsRules=new QPlainTextEdit(this);
    domainDnsRules->setObjectName("domainDnsRulesEdit");
    domainDnsRules->setMaximumHeight(112);
    domainDnsRules->setPlaceholderText("host.example.edu\nother.example.edu 192.0.2.53");
    rulesHelp=new QLabel(this);
    rulesHelp->setWordWrap(true);rulesHelp->setProperty("secondary",true);
    domainDnsLabel=new QLabel(this);
    domainDnsLabel->setMinimumHeight(28);
    domainDnsLabel->setBuddy(domainDnsRules);
    auto *dnsSection=new QVBoxLayout;dnsSection->setContentsMargins(0,0,0,0);dnsSection->setSpacing(8);
    dnsSection->addWidget(domainDnsLabel);dnsSection->addWidget(domainDnsRules);dnsSection->addWidget(rulesHelp);
    layout->addLayout(dnsSection);
    layout->addStretch();
    connect(verify,&QCheckBox::toggled,warning,[this](bool checked){warning->setVisible(!checked);});
    connect(allowUnverifiedNodes,&QCheckBox::toggled,nodeWarning,&QLabel::setVisible);
    connect(address,&QLineEdit::textChanged,this,&ServerSettingsWidget::serverChanged);
    connect(port,&QSpinBox::valueChanged,this,&ServerSettingsWidget::serverChanged);
    retranslate();
    updateRoutingFields();
}
void ServerSettingsWidget::updateRoutingFields() {
    const bool local=routingMode->currentData().toString()==DefaultSettings::LocalProxyMode;
    form->setRowVisible(socksPort,local);
    form->setRowVisible(campusTargets,local);
    form->setRowVisible(clashHelp,local);
}
void ServerSettingsWidget::changeEvent(QEvent *event) {
    QWidget::changeEvent(event);
    if(event->type()==QEvent::LanguageChange) retranslate();
}
void ServerSettingsWidget::retranslate() {
    qobject_cast<QLabel *>(form->labelForField(address))->setText(tr("Address"));
    qobject_cast<QLabel *>(form->labelForField(port))->setText(tr("Port"));
    qobject_cast<QLabel *>(form->labelForField(routingMode))->setText(tr("Routing mode"));
    routingMode->setItemText(0,tr("Automatic routing"));
    routingMode->setItemText(1,tr("Local proxy only"));
    qobject_cast<QLabel *>(form->labelForField(socksPort))->setText(tr("Local SOCKS5 port"));
    socksPort->setSpecialValueText(tr("Off"));
    qobject_cast<QLabel *>(form->labelForField(campusTargets))->setText(tr("Campus targets"));
    campusTargets->setPlaceholderText(tr("One domain or IPv4 address per line"));
    clashHelp->setText(tr("Clash routes these targets in Rule mode. After saving, copy the script from the connection menu."));
    verify->setText(tr("Verify server certificate"));
    warning->setText(tr("The server's identity will not be verified."));
    allowUnverifiedNodes->setText(tr("Skip tunnel verification"));
    nodeWarning->setText(tr("The tunnel peer will not be verified. Sign-in verification is unchanged."));
    caLabel->setText(tr("Server CA"));
    caPem->setAccessibleName(tr("Server CA"));
    caPem->setPlaceholderText(tr("Optional server CA in PEM format. Leave empty to use system trust."));
    domainDnsLabel->setText(tr("Domain DNS"));
    QString help=tr("One domain per line; optional IPv4 DNS servers after it. Otherwise use gateway DNS.");
#ifndef Q_OS_WIN
    help+=" "+tr("Use the local application proxy for domains not published by the gateway.");
#endif
    rulesHelp->setText(help);
}
void ServerSettingsWidget::load(const QSettings &settings) {
    const QSignalBlocker blocker(this);
    const auto host = settings.value("JustConnect/ServerAddress").toString();
    const auto number = settings.value("JustConnect/ServerPort", 443).toInt();
    routingMode->setCurrentIndex(qMax(0,routingMode->findData(settings.value(DefaultSettings::RoutingModeKey))));
    socksPort->setValue(settings.value(DefaultSettings::SocksPortKey,DefaultSettings::DefaultSocksPort).toInt());
    campusTargets->setPlainText(settings.value(DefaultSettings::CampusTargetsKey).toString());
    updateRoutingFields();
    builtIn = DefaultSettings::isBuiltInConnection(settings);
    address->setText(host);
    address->setReadOnly(builtIn);
    port->setValue(number);
    if (port->isReadOnly()!=builtIn) {
        port->setReadOnly(builtIn);
        // Refresh the read-only stylesheet selector when import changes the endpoint type.
        if (port->testAttribute(Qt::WA_WState_Polished)) port->style()->polish(port);
    }
    verify->setChecked(settings.value("JustConnect/TLSVerify", TlsOptions{}.verify).toBool());
    caPem->setPlainText(settings.value("JustConnect/TLSCAPEM").toString());
    allowUnverifiedNodes->setChecked(settings.value("JustConnect/AllowUnverifiedNodes", TlsOptions{}.allowUnverifiedNodes).toBool());
    domainDnsRules->setPlainText(settings.value(DefaultSettings::DomainDnsRules).toString());
}

QString ServerSettingsWidget::serverAddress() const { return address->text().trimmed(); }
int ServerSettingsWidget::serverPort() const { return port->value(); }
bool ServerSettingsWidget::isBuiltIn() const { return builtIn; }

QVariantMap ServerSettingsWidget::settingsValues() const {
    return {{"JustConnect/TLSVerify",verify->isChecked()},{"JustConnect/TLSCAPEM",caPem->toPlainText()},
        {"JustConnect/AllowUnverifiedNodes",allowUnverifiedNodes->isChecked()},
        {"JustConnect/ConnectionKind", builtIn ? DefaultSettings::builtInConnection().value("JustConnect/ConnectionKind") : QVariant("Custom")},{"JustConnect/ServerAddress",serverAddress()},
        {"JustConnect/ServerPort",serverPort()},{DefaultSettings::DomainDnsRules,domainDnsRules->toPlainText().trimmed()},
        {DefaultSettings::RoutingModeKey,routingMode->currentData()},{DefaultSettings::SocksPortKey,socksPort->value()},
        {DefaultSettings::CampusTargetsKey,campusTargets->toPlainText().trimmed()},
        {"Common/NeedsConfiguration",false}};
}
