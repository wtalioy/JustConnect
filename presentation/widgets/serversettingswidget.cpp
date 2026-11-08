#include "serversettingswidget.h"
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
#include <QHBoxLayout>
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
    address = new QLineEdit(this);
    address->setObjectName("serverAddressLineEdit");
    address->setPlaceholderText("vpn.example.edu.cn");
    port = new QSpinBox(this);
    port->setObjectName("serverPortSpinBox");
    port->setRange(1,65535); port->setValue(443);
    for(auto *field:QList<QWidget *>{address,port}) {
        auto *label=new QLabel(this);label->setBuddy(field);
        // QFormLayout otherwise caps label height at 7/4 of its text height, above our taller inputs.
        label->setSizePolicy(QSizePolicy::Preferred,QSizePolicy::Expanding);
        form->addRow(label,field);
    }
    layout->addLayout(form);
    layout->addSpacing(8);

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
    auto *caSection=new QVBoxLayout;caSection->setContentsMargins(0,0,0,0);caSection->setSpacing(8);
    auto *caHeader=new QHBoxLayout;caHeader->setContentsMargins(0,0,0,0);caHeader->setSpacing(8);
    caLabel=new QLabel(this);caLabel->setObjectName("serverCaLabel");caLabel->setWordWrap(true);
    caToggle=new QToolButton(this);caToggle->setObjectName("serverCaToggle");
    caToggle->setCheckable(true);caToggle->setAutoRaise(true);
    caToggle->setIcon(QIcon(":/resource/chevron.svg"));caToggle->setIconSize(QSize(16,16));
    caLabel->setBuddy(caToggle);caHeader->addWidget(caLabel);caHeader->addWidget(caToggle);caHeader->addStretch();
    caSection->addLayout(caHeader);
    caPem=new QPlainTextEdit(this); caPem->setObjectName("tlsCaPemEdit"); caPem->setMaximumHeight(88);caPem->hide();
    caSection->addWidget(caPem);layout->addLayout(caSection);
    connect(caToggle,&QToolButton::toggled,this,[this](bool open) {
        caPem->setVisible(open);caToggle->setIcon(QIcon(open?":/resource/chevron-up.svg":":/resource/chevron.svg"));
    });
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
}
void ServerSettingsWidget::changeEvent(QEvent *event) {
    QWidget::changeEvent(event);
    if(event->type()==QEvent::LanguageChange) retranslate();
}
void ServerSettingsWidget::retranslate() {
    qobject_cast<QLabel *>(form->labelForField(address))->setText(tr("Address"));
    qobject_cast<QLabel *>(form->labelForField(port))->setText(tr("Port"));
    verify->setText(tr("Verify server certificate"));
    warning->setText(tr("The server's identity will not be verified."));
    allowUnverifiedNodes->setText(tr("Skip tunnel verification"));
    nodeWarning->setText(tr("The tunnel peer will not be verified. Sign-in verification is unchanged."));
    caLabel->setText(tr("Server CA (optional)"));
    caToggle->setAccessibleName(tr("Server CA (optional)"));caToggle->setToolTip(tr("Server CA (optional)"));
    caPem->setAccessibleName(tr("Server CA (optional)"));
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
    const auto kind = settings.value("JustConnect/ProfileKind").toString();
    builtIn = !settings.value("Common/NeedsConfiguration").toBool()
        && kind == DefaultSettings::builtInProfile().value("JustConnect/ProfileKind")
        && kind == DefaultSettings::profileKindForEndpoint(host, number);
    address->setText(host);
    address->setReadOnly(builtIn);
    port->setValue(number);
    port->setReadOnly(builtIn);
    port->setButtonSymbols(builtIn ? QAbstractSpinBox::NoButtons : QAbstractSpinBox::UpDownArrows);
    verify->setChecked(settings.value("JustConnect/TLSVerify", TlsOptions{}.verify).toBool());
    caPem->setPlainText(settings.value("JustConnect/TLSCAPEM").toString());
    caToggle->setChecked(!caPem->toPlainText().isEmpty());
    allowUnverifiedNodes->setChecked(settings.value("JustConnect/AllowUnverifiedNodes", TlsOptions{}.allowUnverifiedNodes).toBool());
    domainDnsRules->setPlainText(DefaultSettings::domainDnsRules(DefaultSettings::publicValues(settings)));
}

QString ServerSettingsWidget::serverAddress() const { return address->text().trimmed(); }
int ServerSettingsWidget::serverPort() const { return port->value(); }
bool ServerSettingsWidget::isBuiltIn() const { return builtIn; }

QVariantMap ServerSettingsWidget::settingsValues() const {
    return {{"JustConnect/TLSVerify",verify->isChecked()},{"JustConnect/TLSCAPEM",caPem->toPlainText()},
        {"JustConnect/AllowUnverifiedNodes",allowUnverifiedNodes->isChecked()},
        {"JustConnect/ProfileKind", builtIn ? DefaultSettings::profileKindForEndpoint(serverAddress(), serverPort()) : QStringLiteral("Custom")},{"JustConnect/ServerAddress",serverAddress()},
        {"JustConnect/ServerPort",serverPort()},{DefaultSettings::DomainDnsRules,domainDnsRules->toPlainText().trimmed()},
        {"Common/NeedsConfiguration",false}};
}
