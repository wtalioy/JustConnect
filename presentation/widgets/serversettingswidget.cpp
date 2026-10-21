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
#include "application/applicationconstants.h"

ServerSettingsWidget::ServerSettingsWidget(QWidget *parent) : QWidget(parent) {
    auto *form = new QFormLayout(this);
    form->setContentsMargins(0,0,0,0);
    form->setFormAlignment(Qt::AlignLeft|Qt::AlignTop);
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
    verify=new QCheckBox("验证服务器证书（推荐）",this);
    verify->setObjectName("tlsVerifyCheckBox"); verify->setChecked(true);
    caPem=new QPlainTextEdit(this); caPem->setObjectName("tlsCaPemEdit"); caPem->setMaximumHeight(72);
    caPem->setPlaceholderText("可选：学校提供的 PEM 格式 CA 证书；留空使用系统信任。");
    auto *warning=new QLabel("关闭验证会失去服务器身份保护；不会因连接失败自动关闭。",this);
    warning->setObjectName("tlsWarningLabel"); warning->setWordWrap(true); warning->setVisible(false);
    form->addRow("TLS",verify); form->addRow(warning); form->addRow("附加 CA",caPem);
    allowUnverifiedNodes=new QCheckBox("跳过隧道证书校验",this);
    allowUnverifiedNodes->setObjectName("allowUnverifiedNodesCheckBox");
    auto *nodeWarning=new QLabel("隧道仍加密，但不验证对端身份。登录与资源请求的校验设置保持不变。",this);
    nodeWarning->setObjectName("nodeTlsWarningLabel"); nodeWarning->setWordWrap(true); nodeWarning->hide();
    form->addRow(allowUnverifiedNodes); form->addRow(nodeWarning);
    connect(verify,&QCheckBox::toggled,warning,[warning](bool checked){warning->setVisible(!checked);});
    connect(allowUnverifiedNodes,&QCheckBox::toggled,nodeWarning,&QLabel::setVisible);
    connect(preset,&QComboBox::currentIndexChanged,this,&ServerSettingsWidget::selectPreset);
    connect(address,&QLineEdit::textChanged,this,&ServerSettingsWidget::serverChanged);
    connect(port,&QSpinBox::valueChanged,this,&ServerSettingsWidget::serverChanged);
    selectPreset();
}
void ServerSettingsWidget::load(const QSettings &settings) {
    QSignalBlocker blocker(this), presetBlocker(preset);
    verify->setChecked(settings.value("JustConnect/TLSVerify",true).toBool());
    caPem->setPlainText(settings.value("JustConnect/TLSCAPEM").toString());
    allowUnverifiedNodes->setChecked(settings.value("JustConnect/AllowUnverifiedNodes",false).toBool());
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
QVariantMap ServerSettingsWidget::settingsValues() const {
    return {{"JustConnect/TLSVerify",verify->isChecked()},{"JustConnect/TLSCAPEM",caPem->toPlainText()},
        {"JustConnect/AllowUnverifiedNodes",allowUnverifiedNodes->isChecked()},
        {"JustConnect/ProfileKind",preset->currentData()},{"JustConnect/ServerAddress",serverAddress()},
        {"JustConnect/ServerPort",serverPort()},{"Common/NeedsConfiguration",false}};
}
