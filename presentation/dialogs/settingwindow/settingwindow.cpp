#include "settingwindow.h"
#include "ui_settingwindow.h"
#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
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

SettingWindow::SettingWindow(QWidget *parent,QSettings *inputSettings,CredentialAccess *credentials,const CredentialSource &source)
    : QDialog(parent),ui(new Ui::SettingWindow),settings(inputSettings),credentials(credentials),credentialSource(source) {
    ui->setupUi(this);
    setWindowModality(Qt::WindowModal); setAttribute(Qt::WA_DeleteOnClose);
    serverEditor = new ServerSettingsWidget(ui->serverSettingsContainer);
    auto *layout = new QVBoxLayout(ui->serverSettingsContainer);
    layout->setContentsMargins(0,0,0,0); layout->addWidget(serverEditor);
    const QStringList methods{"","psw","smsCheckCode","cas","httpsOauth2"};
    for (int i=0;i<methods.size();++i) ui->authTypeComboBox->setItemData(i,methods[i]);
    ui->loginUrlLineEdit->setReadOnly(true);
    ui->loginUrlLineEdit->setToolTip("认证查询结果预览；连接时使用当前会话返回的地址。");
    credentialStatus=new QLabel(ui->credentialsGroup);credentialStatus->setObjectName("credentialStatusLabel");credentialStatus->setWordWrap(true);
    ui->credentialsForm->addRow(credentialStatus);
    auto *hint=new QLabel("留空保留已保存凭据；删除请使用下方按钮。",ui->credentialsGroup);hint->setWordWrap(true);ui->credentialsForm->addRow(hint);
    clearCredentialButton=new QPushButton("清除已保存的密码和 TOTP",ui->credentialsGroup);clearCredentialButton->setObjectName("clearCredentialButton");
    ui->credentialsForm->addRow(clearCredentialButton);
    connect(clearCredentialButton,&QPushButton::clicked,this,&SettingWindow::clearCredentials);
    connect(this,&QDialog::finished,this,[this]{closed=true;++loadGeneration;});
    loadSettings(*settings);
    connect(serverEditor,&ServerSettingsWidget::serverChanged,this,[this] {
        clearDraftCredentials();
        selectedAuthId.clear(); selectedAuthSubType.clear();
        ui->authTypeComboBox->setCurrentIndex(0);
        ui->loginDomainLineEdit->clear(); ui->loginUrlLineEdit->clear();
    });
    const auto clearIdentity=[this] { selectedAuthId.clear(); selectedAuthSubType.clear(); clearDraftCredentials(); };
    connect(ui->usernameLineEdit,&QLineEdit::textChanged,this,&SettingWindow::clearDraftCredentials);
    connect(ui->countryCodeLineEdit,&QLineEdit::textChanged,this,&SettingWindow::clearDraftCredentials);
    connect(ui->phoneNumberLineEdit,&QLineEdit::textChanged,this,&SettingWindow::clearDraftCredentials);
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
            if (closed || host!=serverEditor->serverAddress() || port!=serverEditor->serverPort()) return;
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
        applySettings(true);
    });
    connect(ui->buttonBox->button(QDialogButtonBox::Apply),&QPushButton::clicked,this,[this] {
        applySettings(false);
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
        if (!folder.isValid() || source.status()!=QSettings::NoError) { QMessageBox::warning(this,"导入失败","无法读取配置。"); return; }
        QSettings draft(folder.filePath("import.ini"),QSettings::IniFormat);
        if (!SettingsMigrator::publicDraft(source,draft)) {
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
    readCredentials();

}
SettingWindow::~SettingWindow() { delete ui; }

void SettingWindow::loadSettings(const QSettings &source) {
    ++loadGeneration;loading=false;updateBusy();
    ProfileManager manager;
    ui->autoStartCheckBox->setChecked(manager.autoStartEnabled());
    ui->silentStartCheckBox->setChecked(manager.silentStartEnabled());
    serverEditor->load(source);
    ui->usernameLineEdit->setText(source.value("Credential/Username").toString());
    clearDraftCredentials();
    const auto method=source.value("JustConnect/AuthType","psw").toString();
    int index=ui->authTypeComboBox->findData(method);
    if (index<0) { ui->authTypeComboBox->addItem(method,method); index=ui->authTypeComboBox->count()-1; }
    ui->authTypeComboBox->setCurrentIndex(index);
    selectedAuthId=source.value("JustConnect/AuthID").toString(); selectedAuthSubType=source.value("JustConnect/AuthSubType").toString();
    ui->loginDomainLineEdit->setText(source.value("JustConnect/LoginDomain").toString());
    ui->loginUrlLineEdit->clear();
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

void SettingWindow::clearDraftCredentials() {
    loadedCredentials={};
    ui->passwordLineEdit->setText({});ui->totpSecretLineEdit->setText({});
    credentialStatus->setText("可留空，连接时使用该帐号已保存的凭据或手动输入。");
}
void SettingWindow::updateBusy() {
    ui->tabWidget->setEnabled(!saving);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(!loading && !saving);
    ui->buttonBox->button(QDialogButtonBox::Apply)->setEnabled(!loading && !saving);
    clearCredentialButton->setEnabled(!loading && !saving);
}
void SettingWindow::readCredentials() {
    loading=true;updateBusy();const auto generation=++loadGeneration;
    const auto source=credentialSource;
    credentials->load(source).then(this,[this,source,generation](const CredentialLoadResult &loaded) {
        if (closed || generation!=loadGeneration) return;
        loading=false;updateBusy();
        if (!CredentialAccess::matches(source,*settings)) {credentialStatus->setText("已保存配置已变化，请重新打开设置。");return;}
        credentialStatus->setText(PresentationHelpers::credentialOperationMessage(loaded.result.status));
        if (loaded.result.succeeded() && currentProfile().authenticationIdentity()==source.profile.authenticationIdentity()) {
            const bool passwordUntouched=ui->passwordLineEdit->text()==loadedCredentials.password;
            const bool totpUntouched=ui->totpSecretLineEdit->text()==loadedCredentials.totpSecret;
            loadedCredentials=loaded.credentials;
            if (passwordUntouched) ui->passwordLineEdit->setText(loaded.credentials.password);
            if (totpUntouched) ui->totpSecretLineEdit->setText(loaded.credentials.totpSecret);
        }
    });
}
void SettingWindow::clearCredentials() {
    if (closed || loading || saving) return;
    if (!CredentialAccess::matches(credentialSource,*settings)) {
        QMessageBox::warning(this,"配置已变化","请重新打开设置后再清除凭据。");return;
    }
    auto account=credentialSource.profile.credentials.username;
    if (account.isEmpty()) account=credentialSource.profile.endpoint.phone;
    if (account.isEmpty()) account="当前配置";
    if (QMessageBox::question(this,"清除已保存凭据","清除已保存配置中 "+account+" 的密码和 TOTP？其他帐号不受影响。")!=QMessageBox::Yes) return;
    const auto source=credentialSource;++loadGeneration;saving=true;updateBusy();
    credentials->clear(source).then(this,[this](const CredentialResult &result) {
        if (closed) return;
        saving=false;updateBusy();
        if (!result.succeeded()) {QMessageBox::warning(this,"清除未完成",PresentationHelpers::credentialOperationMessage(result.status));return;}
        if (ui->passwordLineEdit->text()==loadedCredentials.password) ui->passwordLineEdit->setText({});
        if (ui->totpSecretLineEdit->text()==loadedCredentials.totpSecret) ui->totpSecretLineEdit->setText({});
        loadedCredentials={};
        credentialStatus->setText("已清除保存的密码和 TOTP，未应用的输入保持不变。");
        credentialSource=CredentialAccess::source(*settings,credentialSource.legacyCachePath);
    });
}
void SettingWindow::applySettings(bool closeAfter) {
    if (closed || loading || saving) return;
    if (!CredentialAccess::matches(credentialSource,*settings) || credentialSource.publicValues!=DefaultSettings::publicValues(*settings)) {
        QMessageBox::warning(this,"配置已变化","请重新打开设置后再应用修改。");return;
    }
    auto profile=currentProfile();
    if (profile.authenticationIdentity()==credentialSource.profile.authenticationIdentity()) {
        if (profile.credentials.password.isEmpty()) profile.credentials.password=loadedCredentials.password;
        if (profile.credentials.totpSecret.isEmpty()) profile.credentials.totpSecret=loadedCredentials.totpSecret;
    }
    if (profile.endpoint.authType.isEmpty()) {
        QMessageBox::warning(this,"请选择认证方式","请选择认证方式；可从当前服务器获取可用列表。");return;
    }
    const auto validation=EmbeddedCoreEngine::validateConfiguration(profile);
    if (validation!=ConnectionError::NONE) {
        const bool unavailable=validation==ConnectionError::CORE_UNAVAILABLE;
        QMessageBox::warning(this,unavailable ? "核心不可用" : "配置无效",
            unavailable ? "无法校验配置，请检查应用安装是否完整。配置未保存。" : "请检查服务器、认证方式、本地端口及 DNS 地址。配置未保存。");return;
    }
    saving=true;updateBusy();
    ProfileManager manager;
    const bool autoStart=ui->autoStartCheckBox->isChecked();
    if (manager.autoStartEnabled()!=autoStart) {
        const auto result=AutoStart::setEnabled(autoStart);
        if (!result.succeeded()) {saving=false;updateBusy();QMessageBox::warning(this,"自启动操作未完成",PresentationHelpers::platformOperationMessage(result));return;}
        if (!manager.setAutoStartEnabled(autoStart)) {saving=false;updateBusy();QMessageBox::warning(this,"自启动偏好未保存","系统项已修改，但偏好保存失败，请检查后重试。");return;}
    }
    manager.setSilentStartEnabled(ui->silentStartCheckBox->isChecked());
    auto changes=serverEditor->settingsValues();
    changes.insert("Credential/Username",profile.credentials.username);
    changes.insert("JustConnect/AuthType",profile.endpoint.authType);changes.insert("JustConnect/AuthID",profile.endpoint.authId);
    changes.insert("JustConnect/AuthSubType",profile.endpoint.authSubType);changes.insert("JustConnect/LoginDomain",profile.endpoint.loginDomain);
    changes.insert("JustConnect/PhoneCountryCode",ui->countryCodeLineEdit->text().trimmed());changes.insert("JustConnect/PhoneNumber",ui->phoneNumberLineEdit->text().trimmed());
    changes.insert("Common/ConnectAfterStart",ui->connectAfterStartCheckBox->isChecked());changes.insert("Common/CheckUpdateAfterStart",ui->checkUpdateAfterStartCheckBox->isChecked());
    changes.insert("Common/AutoReconnect",ui->autoReconnectCheckBox->isChecked());changes.insert("Common/ReconnectTime",ui->reconnectTimeSpinBox->value());
    changes.insert("Common/AutoSetProxy",ui->autoSetProxyCheckBox->isChecked());changes.insert("Common/SystemProxyBypass",ui->systemProxyBypassLineEdit->text());
    changes.insert("Common/SuppressProxyOverrideWarning",ui->suppressProxyOverrideWarningCheckBox->isChecked());
    changes.insert("JustConnect/SOCKS5Port",ui->socks5PortSpinBox->value());changes.insert("JustConnect/HTTPPort",ui->httpPortSpinBox->value());
    changes.insert("JustConnect/LocalDNSServer",profile.dns.localDnsServer);changes.insert("JustConnect/SecondaryDNS",profile.dns.secondary);changes.insert("JustConnect/DNSTTL",profile.dns.ttl);
    changes.insert("JustConnect/DisableRemoteDNS",profile.dns.disableRemoteDns);changes.insert("JustConnect/BindInterface",profile.behavior.bindInterface);
    changes.insert("JustConnect/AutoDetectInterface",profile.behavior.autoDetectInterface);
    const bool edited=(!ui->passwordLineEdit->text().isEmpty() && ui->passwordLineEdit->text()!=loadedCredentials.password)
        || (!ui->totpSecretLineEdit->text().isEmpty() && ui->totpSecretLineEdit->text()!=loadedCredentials.totpSecret);
    saving=true;updateBusy();const auto source=credentialSource;
    credentials->save(source,profile,edited,changes).then(this,[this,source,profile,closeAfter](const CredentialResult &result) {
        if (closed) return;
        saving=false;updateBusy();
        if (!result.succeeded()) {QMessageBox::warning(this,"保存设置未完成",PresentationHelpers::credentialOperationMessage(result.status));return;}
        if (settings->fileName()!=source.path || settings->value(ProfileCredentials::ScopeSetting)!=source.scope) return;
        credentialSource=CredentialAccess::source(*settings,source.legacyCachePath);
        if (closeAfter) accept();
        else {loadSettings(*settings);readCredentials();}
    });
}
