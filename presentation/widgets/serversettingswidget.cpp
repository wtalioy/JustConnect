#include "serversettingswidget.h"
#include <QComboBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QSettings>
#include <QSignalBlocker>
#include <QSpinBox>
#include "application/applicationconstants.h"

ServerSettingsWidget::ServerSettingsWidget(QWidget *parent) : QWidget(parent) {
    auto *form = new QFormLayout(this);
    form->setContentsMargins(0,0,0,0);
    preset = new QComboBox(this);
    preset->setObjectName("profileKindComboBox");
    preset->addItem("请选择入口", "");
    preset->addItem("Fudan", "Fudan");
    preset->addItem("Custom", "Custom");
    address = new QLineEdit(this);
    address->setObjectName("serverAddressLineEdit");
    address->setPlaceholderText("vpn.example.edu.cn");
    port = new QSpinBox(this);
    port->setObjectName("serverPortSpinBox");
    port->setRange(1,65535); port->setValue(443);
    form->addRow("入口",preset); form->addRow("服务器地址",address); form->addRow("服务器端口",port);
    connect(preset,&QComboBox::currentIndexChanged,this,&ServerSettingsWidget::selectPreset);
    connect(address,&QLineEdit::textChanged,this,&ServerSettingsWidget::serverChanged);
    connect(port,&QSpinBox::valueChanged,this,&ServerSettingsWidget::serverChanged);
    selectPreset();
}
void ServerSettingsWidget::load(const QSettings &settings) {
    QSignalBlocker blocker(this), presetBlocker(preset);
    customAddress = settings.value("JustConnect/ServerAddress").toString();
    customPort = settings.value("JustConnect/ServerPort",443).toInt();
    QString kind = settings.value("JustConnect/ProfileKind","Custom").toString();
    if (settings.value("Common/NeedsConfiguration",false).toBool()) kind.clear();
    if (kind == "Fudan" && (customAddress != ApplicationConstants::FudanServer || customPort != ApplicationConstants::FudanPort)) kind = "Custom";
    preset->setCurrentIndex(preset->findData(kind));
    previousPreset.clear();
    selectPreset();
}
void ServerSettingsWidget::selectPreset() {
    const auto kind = preset->currentData().toString();
    if (previousPreset == "Custom") { customAddress = address->text(); customPort = port->value(); }
    address->setText(kind == "Fudan" ? ApplicationConstants::FudanServer : customAddress);
    port->setValue(kind == "Fudan" ? ApplicationConstants::FudanPort : customPort);
    address->setReadOnly(kind != "Custom"); port->setEnabled(kind == "Custom");
    previousPreset = kind;
    emit serverChanged();
}
QString ServerSettingsWidget::serverAddress() const { return preset->currentData().toString().isEmpty() ? QString() : address->text().trimmed(); }
int ServerSettingsWidget::serverPort() const { return port->value(); }
bool ServerSettingsWidget::isFudan() const { return preset->currentData() == "Fudan"; }
void ServerSettingsWidget::applyTo(QSettings &settings) const {
    settings.setValue("JustConnect/ProfileKind",preset->currentData());
    settings.setValue("JustConnect/ServerAddress",serverAddress());
    settings.setValue("JustConnect/ServerPort",serverPort());
    settings.setValue("Common/NeedsConfiguration",false);
}
