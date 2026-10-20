#include "settingwindow.h"
#include "ui_settingwindow.h"
#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QTemporaryDir>
#include <QVBoxLayout>
#include "application/defaultsettings.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "application/settingsmigrator.h"
#include "infrastructure/platform/autostart.h"
#include "infrastructure/settings/profilemanager.h"
#include "infrastructure/settings/settingsprofileloader.h"
#include "infrastructure/storage/applicationpaths.h"
#include "presentation/dialogs/authinfowindow/authinfowindow.h"
#include "presentation/presentationhelpers.h"
#include "presentation/widgets/serversettingswidget.h"

SettingWindow::SettingWindow(QWidget *parent,QSettings *inputSettings,const QString &id)
    : QDialog(parent),ui(new Ui::SettingWindow),settings(inputSettings),profileId(id) {
    ui->setupUi(this);
    setWindowModality(Qt::WindowModal); setAttribute(Qt::WA_DeleteOnClose);
    serverEditor = new ServerSettingsWidget(ui->serverSettingsContainer);
    auto *layout = new QVBoxLayout(ui->serverSettingsContainer);
    layout->setContentsMargins(0,0,0,0); layout->addWidget(serverEditor);
    const QStringList methods{"","psw","smsCheckCode","cas","httpsOauth2"};
    for (int i=0;i<methods.size();++i) ui->authTypeComboBox->setItemData(i,methods[i]);
    ui->loginUrlLineEdit->setReadOnly(true);
    ui->loginUrlLineEdit->setToolTip("认证查询结果预览；连接时使用当前会话返回的地址。");
    loadSettings(*settings);
    connect(serverEditor,&ServerSettingsWidget::serverChanged,this,[this] {
        selectedAuthId.clear(); selectedAuthSubType.clear();
        ui->authTypeComboBox->setCurrentIndex(0);
        ui->loginDomainLineEdit->clear(); ui->loginUrlLineEdit->clear();
    });
    const auto clearIdentity=[this] { selectedAuthId.clear(); selectedAuthSubType.clear(); };
    connect(ui->authTypeComboBox,&QComboBox::currentIndexChanged,this,clearIdentity);
    connect(ui->loginDomainLineEdit,&QLineEdit::textEdited,this,clearIdentity);
    connect(ui->passwordVisibleCheckBox,&QCheckBox::toggled,this,[this](bool on) {
        ui->passwordLineEdit->setEchoMode(on ? QLineEdit::Normal : QLineEdit::Password);
    });
    connect(ui->totpSecretVisibleCheckBox,&QCheckBox::toggled,this,[this](bool on) {
        ui->totpSecretLineEdit->setEchoMode(on ? QLineEdit::Normal : QLineEdit::Password);
    });
    connect(ui->openLogDirectoryPushButton,&QPushButton::clicked,this,[this] {
        if (!QDesktopServices::openUrl(QUrl::fromLocalFile(ApplicationPaths::logDirectory())))
            QMessageBox::warning(this,"日志目录","无法打开日志目录。");
    });
    connect(ui->authSelectPushButton,&QPushButton::clicked,this,[this] {
        const auto host=serverEditor->serverAddress(); const auto port=serverEditor->serverPort();
        auto *query=new AuthInfoWindow(this);
        connect(query,&AuthInfoWindow::finishAuthInfo,this,[this,host,port](const QJsonObject &selection) {
            if (host!=serverEditor->serverAddress() || port!=serverEditor->serverPort()) return;
            auto method=selection["type"].toString();
            if (method.startsWith("auth/")) method.remove(0,5);
            int index=ui->authTypeComboBox->findData(method);
            if (index<0) { ui->authTypeComboBox->addItem(method,method); index=ui->authTypeComboBox->count()-1; }
            ui->authTypeComboBox->setCurrentIndex(index);
            ui->loginDomainLineEdit->setText(selection["domain"].toString()); ui->loginUrlLineEdit->setText(selection["login_url"].toString());
            selectedAuthId=selection["auth_id"].toString(); selectedAuthSubType=selection["sub_type"].toString();
        });
        query->fetchAuthInfo(currentProfile(),serverEditor->isFudan()); query->show();
    });
    connect(ui->buttonBox->button(QDialogButtonBox::Ok),&QPushButton::clicked,this,[this] {
        if (applySettings()) accept();
    });
    connect(ui->buttonBox->button(QDialogButtonBox::Apply),&QPushButton::clicked,this,[this] {
        if (applySettings()) loadSettings(*settings);
    });
    connect(ui->resetDefaultPushButton,&QPushButton::clicked,this,[this] {
        if (QMessageBox::question(this,"恢复默认值","恢复当前窗口的默认值，应用后生效。是否继续？")!=QMessageBox::Yes) return;
        QTemporaryDir folder;
        if (!folder.isValid()) { QMessageBox::warning(this,"重置失败","无法创建临时配置。"); return; }
        QSettings draft(folder.filePath("defaults.ini"),QSettings::IniFormat);
        DefaultSettings::reset(draft); loadSettings(draft);
    });
    connect(ui->importPushButton,&QPushButton::clicked,this,[this] {
        const auto path=QFileDialog::getOpenFileName(this,"导入配置",{},"Config Ini (*.ini)");
        if (path.isEmpty()) return;
        QTemporaryDir folder;
        QSettings source(path,QSettings::IniFormat);
        const auto keys=source.allKeys();
        if (!folder.isValid() || source.status()!=QSettings::NoError) { QMessageBox::warning(this,"导入失败","无法读取配置。"); return; }
        QSettings draft(folder.filePath("import.ini"),QSettings::IniFormat);
        for (const auto &key:keys) draft.setValue(key,source.value(key));
        if (SettingsMigrator::prepare(draft)==SettingsMigrationAction::Failed || !SettingsMigrator::finish(draft)) {
            QMessageBox::warning(this,"导入失败","无法准备配置，当前设置未修改。"); return;
        }
        loadSettings(draft);
    });
    connect(ui->exportPushButton,&QPushButton::clicked,this,[this] {
        const auto path=QFileDialog::getSaveFileName(this,"导出已保存配置",{},"Config Ini (*.ini)");
        if (path.isEmpty()) return;
        settings->sync();
        if (settings->status()!=QSettings::NoError || !DefaultSettings::exportTo(*settings,path))
            QMessageBox::warning(this,"导出失败","无法提交导出文件；不能覆盖当前配置。");
    });
}
SettingWindow::~SettingWindow() { delete ui; }

void SettingWindow::loadSettings(const QSettings &source) {
    ProfileManager manager;
    ui->autoStartCheckBox->setChecked(manager.autoStartEnabled());
    ui->silentStartCheckBox->setChecked(manager.silentStartEnabled());
    serverEditor->load(source);
    ui->usernameLineEdit->setText(source.value("Credential/Username").toString());
    ui->passwordLineEdit->setText(QString::fromUtf8(QByteArray::fromBase64(source.value("Credential/Password").toByteArray())));
    ui->totpSecretLineEdit->setText(source.value("Credential/TOTPSecret").toString());
    const auto method=source.value("JustConnect/AuthType","psw").toString();
    int index=ui->authTypeComboBox->findData(method);
    if (index<0) { ui->authTypeComboBox->addItem(method,method); index=ui->authTypeComboBox->count()-1; }
    ui->authTypeComboBox->setCurrentIndex(index);
    selectedAuthId=source.value("JustConnect/AuthID").toString(); selectedAuthSubType=source.value("JustConnect/AuthSubType").toString();
    ui->loginDomainLineEdit->setText(source.value("JustConnect/LoginDomain").toString());
    ui->loginUrlLineEdit->setText(source.value("JustConnect/LoginURL").toString());
    ui->countryCodeLineEdit->setText(source.value("JustConnect/PhoneCountryCode","86").toString());
    ui->phoneNumberLineEdit->setText(source.value("JustConnect/PhoneNumber").toString());
    ui->connectAfterStartCheckBox->setChecked(source.value("Common/ConnectAfterStart").toBool());
    ui->checkUpdateAfterStartCheckBox->setChecked(source.value("Common/CheckUpdateAfterStart").toBool());
    ui->autoReconnectCheckBox->setChecked(source.value("Common/AutoReconnect").toBool());
    ui->reconnectTimeSpinBox->setValue(source.value("Common/ReconnectTime",1).toInt());
    ui->autoSetProxyCheckBox->setChecked(source.value("Common/AutoSetProxy").toBool());
    ui->systemProxyBypassLineEdit->setText(source.value("Common/SystemProxyBypass").toString());
    ui->suppressProxyOverrideWarningCheckBox->setChecked(source.value("Common/SuppressProxyOverrideWarning").toBool());
    ui->socks5PortSpinBox->setValue(source.value("JustConnect/SOCKS5Port").toInt());
    ui->httpPortSpinBox->setValue(source.value("JustConnect/HTTPPort").toInt());
    ui->localDnsServerLineEdit->setText(source.value("JustConnect/LocalDNSServer").toString());
    ui->secondaryDnsLineEdit->setText(source.value("JustConnect/SecondaryDNS").toString());
    ui->dnsTTLSpinBox->setValue(source.value("JustConnect/DNSTTL",3600).toInt());
    ui->bindInterfaceLineEdit->setText(source.value("JustConnect/BindInterface").toString());
    ui->autoDetectInterfaceCheckBox->setChecked(source.value("JustConnect/AutoDetectInterface").toBool());
    ui->disableDNSCheckBox->setChecked(source.value("JustConnect/DisableRemoteDNS").toBool());
}

ConnectionProfile SettingWindow::currentProfile() const {
    ConnectionProfile profile;
    profile.credentials = {ui->usernameLineEdit->text().trimmed(), ui->passwordLineEdit->text(), ui->totpSecretLineEdit->text().trimmed()};
    profile.tls=serverEditor->tlsOptions();
    profile.endpoint.server = serverEditor->serverAddress(); profile.endpoint.port = serverEditor->serverPort();
    profile.endpoint.authId=selectedAuthId; profile.endpoint.authSubType=selectedAuthSubType;
    profile.endpoint.authType = ui->authTypeComboBox->currentData().toString();
    profile.endpoint.loginDomain = ui->loginDomainLineEdit->text().trimmed();
    const auto country=ui->countryCodeLineEdit->text().trimmed(), phone=ui->phoneNumberLineEdit->text().trimmed();
    if (!country.isEmpty() && !phone.isEmpty()) profile.endpoint.phone=country+'-'+phone;
    const auto bind = [](int port) { return port ? "127.0.0.1:"+QString::number(port) : QString(); };
    profile.proxy.socksBind=bind(ui->socks5PortSpinBox->value()); profile.proxy.httpBind=bind(ui->httpPortSpinBox->value());
    profile.dns.localDnsServer=ui->localDnsServerLineEdit->text().trimmed();
    profile.dns.secondary=ui->secondaryDnsLineEdit->text().trimmed(); profile.dns.ttl=ui->dnsTTLSpinBox->value();
    profile.dns.disableRemoteDns=ui->disableDNSCheckBox->isChecked();
    profile.behavior.bindInterface=ui->bindInterfaceLineEdit->text().trimmed();
    profile.behavior.autoDetectInterface=ui->autoDetectInterfaceCheckBox->isChecked();
    return profile;
}

bool SettingWindow::applySettings() {
    const auto profile=currentProfile();
    if (serverEditor->isFudan() && profile.endpoint.authType.isEmpty()) {
        QMessageBox::warning(this,"请选择认证方式","请从 Fudan 服务器获取并选择认证方式。"); return false;
    }
    const auto validation=EmbeddedCoreEngine::validateConfiguration(profile);
    if (validation!=ConnectionError::NONE) {
        const bool unavailable=validation==ConnectionError::CORE_UNAVAILABLE;
        QMessageBox::warning(this,unavailable ? "核心不可用" : "配置无效",
            unavailable ? "无法校验配置，请检查应用安装是否完整。配置未保存。" : "请检查服务器、认证方式、本地端口及 DNS 地址。配置未保存。");
        return false;
    }
    const auto before=SettingsProfileLoader::load(*settings);
    ProfileManager manager;
    const bool autoStart=ui->autoStartCheckBox->isChecked();
    if (manager.autoStartEnabled()!=autoStart) {
        const auto result=AutoStart::setEnabled(autoStart);
        if (!result.succeeded()) { QMessageBox::warning(this,"自启动操作未完成",PresentationHelpers::platformOperationMessage(result)); return false; }
        if (!manager.setAutoStartEnabled(autoStart)) { QMessageBox::warning(this,"自启动偏好未保存","系统项已修改，但偏好保存失败，请检查后重试。"); return false; }
    }
    manager.setSilentStartEnabled(ui->silentStartCheckBox->isChecked());
    serverEditor->applyTo(*settings);
    settings->setValue("Credential/Username",profile.credentials.username);
    settings->setValue("Credential/Password",QString::fromLatin1(profile.credentials.password.toUtf8().toBase64()));
    settings->setValue("Credential/TOTPSecret",profile.credentials.totpSecret);
    settings->setValue("JustConnect/AuthType",profile.endpoint.authType);
    settings->setValue("JustConnect/AuthID",profile.endpoint.authId);
    settings->setValue("JustConnect/AuthSubType",profile.endpoint.authSubType);
    settings->setValue("JustConnect/LoginDomain",profile.endpoint.loginDomain);
    settings->setValue("JustConnect/LoginURL",ui->loginUrlLineEdit->text());
    settings->setValue("JustConnect/PhoneCountryCode",ui->countryCodeLineEdit->text().trimmed());
    settings->setValue("JustConnect/PhoneNumber",ui->phoneNumberLineEdit->text().trimmed());
    settings->setValue("Common/ConnectAfterStart",ui->connectAfterStartCheckBox->isChecked());
    settings->setValue("Common/CheckUpdateAfterStart",ui->checkUpdateAfterStartCheckBox->isChecked());
    settings->setValue("Common/AutoReconnect",ui->autoReconnectCheckBox->isChecked());
    settings->setValue("Common/ReconnectTime",ui->reconnectTimeSpinBox->value());
    settings->setValue("Common/AutoSetProxy",ui->autoSetProxyCheckBox->isChecked());
    settings->setValue("Common/SystemProxyBypass",ui->systemProxyBypassLineEdit->text());
    settings->setValue("Common/SuppressProxyOverrideWarning",ui->suppressProxyOverrideWarningCheckBox->isChecked());
    settings->setValue("JustConnect/SOCKS5Port",ui->socks5PortSpinBox->value());
    settings->setValue("JustConnect/HTTPPort",ui->httpPortSpinBox->value());
    settings->setValue("JustConnect/LocalDNSServer",profile.dns.localDnsServer);
    settings->setValue("JustConnect/SecondaryDNS",profile.dns.secondary);
    settings->setValue("JustConnect/DNSTTL",profile.dns.ttl);
    settings->setValue("JustConnect/DisableRemoteDNS",profile.dns.disableRemoteDns);
    settings->setValue("JustConnect/BindInterface",profile.behavior.bindInterface);
    settings->setValue("JustConnect/AutoDetectInterface",profile.behavior.autoDetectInterface);
    if (!SettingsMigrator::finish(*settings)) { QMessageBox::warning(this,"保存设置失败","部分设置可能已保存，请检查后重试。"); return false; }
    if (!before.hasSameAuthentication(profile)) ApplicationPaths::clearClientData(profileId);
    return true;
}
