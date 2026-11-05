#include "settingwindow.h"
#include "ui_settingwindow.h"
#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QEvent>
#include <QSignalBlocker>
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
#include "core/connectionsessionstate.h"
#include "infrastructure/autostart/autostart.h"
#include "infrastructure/settings/profilemanager.h"
#include "application/profileservice.h"
#include "infrastructure/storage/applicationpaths.h"
#include "presentation/dialogs/authinfowindow/authinfowindow.h"
#include "presentation/presentationhelpers.h"
#include "presentation/widgets/serversettingswidget.h"

SettingWindow::SettingWindow(QWidget *parent,CredentialAccess *credentials,const CredentialSource &source,bool openProfileTab)
    : QDialog(parent),ui(new Ui::SettingWindow),settings(source.path,QSettings::IniFormat),credentials(credentials),credentialSource(source) {
    ui->setupUi(this);
    ui->reconnectTimeSpinBox->setMaximum(ConnectionSessionState::MaxReconnectDelayMs / 1000);
    if(openProfileTab)ui->tabWidget->setCurrentWidget(ui->loginTab);
    setWindowModality(Qt::WindowModal); setAttribute(Qt::WA_DeleteOnClose);
    serverEditor = new ServerSettingsWidget(ui->serverSettingsContainer);
    auto *layout = new QVBoxLayout(ui->serverSettingsContainer);
    layout->setContentsMargins(0,0,0,0); layout->addWidget(serverEditor);
    const QStringList methods{"","psw","smsCheckCode","cas","httpsOauth2"};
    for (int i=0;i<methods.size();++i) ui->authTypeComboBox->setItemData(i,methods[i]);
    const QStringList keepAliveModes{"auto","target","off"};
    for (int i=0;i<keepAliveModes.size();++i) ui->keepAliveModeComboBox->setItemData(i,keepAliveModes[i]);
    connect(ui->keepAliveModeComboBox,&QComboBox::currentIndexChanged,this,[this] {
        ui->keepAliveUrlLineEdit->setEnabled(ui->keepAliveModeComboBox->currentData()=="target");
    });
    ui->loginUrlLineEdit->setReadOnly(true);
    credentialStatus=new QLabel(ui->credentialsGroup);credentialStatus->setObjectName("credentialStatusLabel");credentialStatus->setWordWrap(true);
    ui->credentialsForm->addRow(credentialStatus);
    rememberAuthentication=new QCheckBox(ui->credentialsGroup);
    rememberAuthentication->setObjectName("rememberAuthenticationCheckBox");
    ui->credentialsForm->addRow(rememberAuthentication);
    credentialHint=new QLabel(ui->credentialsGroup);credentialHint->setWordWrap(true);ui->credentialsForm->addRow(credentialHint);
    clearCredentialButton=new QPushButton(ui->credentialsGroup);clearCredentialButton->setObjectName("clearCredentialButton");
    ui->credentialsForm->addRow(clearCredentialButton);
    connect(clearCredentialButton,&QPushButton::clicked,this,&SettingWindow::clearCredentials);
    connect(this,&QDialog::finished,this,[this]{closed=true;++loadGeneration;});
    loadSettings(settings);
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
            QMessageBox::warning(this,tr("Log folder"),tr("Could not open the log folder."));
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
        query->fetchAuthInfo(currentProfile(),serverEditor->prefersOAuth()); query->show();
    });
    connect(ui->buttonBox->button(QDialogButtonBox::Ok),&QPushButton::clicked,this,[this] {
        applySettings(true);
    });
    connect(ui->buttonBox->button(QDialogButtonBox::Apply),&QPushButton::clicked,this,[this] {
        applySettings(false);
    });
    connect(ui->resetDefaultPushButton,&QPushButton::clicked,this,[this] {
        if (QMessageBox::question(this,tr("Reset draft"),tr("Reset this draft to its defaults? Changes take effect after saving."))!=QMessageBox::Yes) return;
        QTemporaryDir folder;
        if (!folder.isValid()) { QMessageBox::warning(this,tr("Reset failed"),tr("Could not create a temporary profile.")); return; }
        QSettings draft(folder.filePath("defaults.ini"),QSettings::IniFormat);
        DefaultSettings::reset(draft); loadSettings(draft);
    });
    connect(ui->importPushButton,&QPushButton::clicked,this,[this] {
        const auto path=QFileDialog::getOpenFileName(this,tr("Import profile"),{},tr("INI profiles (*.ini)"));
        if (path.isEmpty()) return;
        QTemporaryDir folder;
        QSettings source(path,QSettings::IniFormat);
        if (!folder.isValid() || source.status()!=QSettings::NoError) { QMessageBox::warning(this,tr("Import failed"),tr("Could not read this profile.")); return; }
        QSettings draft(folder.filePath("import.ini"),QSettings::IniFormat);
        if (!SettingsMigrator::publicDraft(source,draft)) {
            QMessageBox::warning(this,tr("Import failed"),tr("Could not prepare this profile. The current draft is unchanged.")); return;
        }
        loadSettings(draft);
    });
    connect(ui->exportPushButton,&QPushButton::clicked,this,[this] {
        const auto path=QFileDialog::getSaveFileName(this,tr("Export saved profile"),{},tr("INI profiles (*.ini)"));
        if (path.isEmpty()) return;
        settings.sync();
        if (settings.status()!=QSettings::NoError || !SettingsMigrator::readableFile(settings.fileName()) || !DefaultSettings::exportTo(settings,path))
            QMessageBox::warning(this,tr("Export failed"),tr("Could not write the export. The current profile cannot be overwritten."));
    });
    retranslate();
    readCredentials();

}
SettingWindow::~SettingWindow() { delete ui; }

void SettingWindow::changeEvent(QEvent *event) {
    QDialog::changeEvent(event);
    if(event->type()==QEvent::LanguageChange) retranslate();
}
void SettingWindow::retranslate() {
    QSignalBlocker authBlocker(ui->authTypeComboBox),modeBlocker(ui->keepAliveModeComboBox);
    ui->retranslateUi(this);
    ui->commonFormLabel5->setText(tr("Initial reconnect delay (s; up to %1 attempts)").arg(ConnectionSessionState::MaxReconnectAttempts));
    ui->loginUrlLineEdit->setToolTip(tr("Preview from the sign-in query. Connections use the URL returned by the current session."));
    rememberAuthentication->setText(tr("Remember authentication"));
    rememberAuthentication->setToolTip(tr("Use the system credential store to resume after disconnecting or restarting, for as long as the server allows. Turning this off stops saving and resuming. Use Clear current account authentication cache to delete existing data."));
    credentialHint->setText(tr("Leave empty to keep saved credentials. Use the button below to remove them."));
    clearCredentialButton->setText(tr("Clear saved password and key"));
    credentialStatus->setText(credentialStatusText ? tr(credentialStatusText) : PresentationHelpers::credentialOperationMessage(credentialLoadStatus));
    const auto mode=ui->keepAliveModeComboBox->currentData().toString();
    if(!QStringList{"auto","target","off"}.contains(mode))
        ui->keepAliveModeComboBox->setItemText(ui->keepAliveModeComboBox->currentIndex(),tr("Invalid mode — choose another"));
}

void SettingWindow::loadSettings(const QSettings &source) {
    ++loadGeneration;loading=false;updateBusy();
    ProfileManager manager;
    ui->autoStartCheckBox->setChecked(manager.autoStartEnabled());
    ui->silentStartCheckBox->setChecked(manager.silentStartEnabled());
    serverEditor->load(source);
    ui->usernameLineEdit->setText(source.value("Credential/Username").toString());
    rememberAuthentication->setChecked(source.value(DefaultSettings::RememberAuthentication,ConnectionBehavior{}.rememberAuthentication).toBool());
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
    ui->dnsTTLSpinBox->setValue(source.value("JustConnect/DNSTTL",DnsOptions{}.ttl).toInt());
    ui->bindInterfaceLineEdit->setText(source.value("JustConnect/BindInterface").toString());
    ui->autoDetectInterfaceCheckBox->setChecked(source.value("JustConnect/AutoDetectInterface",ConnectionBehavior{}.autoDetectInterface).toBool());
    ui->disableDNSCheckBox->setChecked(source.value("JustConnect/DisableRemoteDNS",DnsOptions{}.disableRemoteDns).toBool());
    const auto mode=source.value("JustConnect/KeepAliveMode",KeepAliveOptions{}.mode).toString();
    int keepAliveIndex=ui->keepAliveModeComboBox->findData(mode);
    if (keepAliveIndex<0) {
        ui->keepAliveModeComboBox->addItem(tr("Invalid mode — choose another"),mode);
        keepAliveIndex=ui->keepAliveModeComboBox->count()-1;
    }
    ui->keepAliveModeComboBox->setCurrentIndex(keepAliveIndex);
    ui->keepAliveUrlLineEdit->setText(source.value("JustConnect/KeepAliveURL").toString());
    ui->keepAliveUrlLineEdit->setEnabled(mode=="target");
}

QVariantMap SettingWindow::publicChanges() const {
    auto changes=serverEditor->settingsValues();
    changes.insert("Credential/Username",ui->usernameLineEdit->text().trimmed());
    changes.insert(DefaultSettings::RememberAuthentication,rememberAuthentication->isChecked());
    changes.insert("JustConnect/AuthType",ui->authTypeComboBox->currentData().toString());changes.insert("JustConnect/AuthID",selectedAuthId);
    changes.insert("JustConnect/AuthSubType",selectedAuthSubType);changes.insert("JustConnect/LoginDomain",ui->loginDomainLineEdit->text().trimmed());
    changes.insert("JustConnect/PhoneCountryCode",ui->countryCodeLineEdit->text().trimmed());changes.insert("JustConnect/PhoneNumber",ui->phoneNumberLineEdit->text().trimmed());
    changes.insert("Common/ConnectAfterStart",ui->connectAfterStartCheckBox->isChecked());changes.insert("Common/CheckUpdateAfterStart",ui->checkUpdateAfterStartCheckBox->isChecked());
    changes.insert("Common/AutoReconnect",ui->autoReconnectCheckBox->isChecked());changes.insert("Common/ReconnectTime",ui->reconnectTimeSpinBox->value());
    changes.insert("Common/AutoSetProxy",ui->autoSetProxyCheckBox->isChecked());changes.insert("Common/SystemProxyBypass",ui->systemProxyBypassLineEdit->text());
    changes.insert("Common/SuppressProxyOverrideWarning",ui->suppressProxyOverrideWarningCheckBox->isChecked());
    changes.insert("JustConnect/SOCKS5Port",ui->socks5PortSpinBox->value());changes.insert("JustConnect/HTTPPort",ui->httpPortSpinBox->value());
    changes.insert("JustConnect/LocalDNSServer",ui->localDnsServerLineEdit->text().trimmed());changes.insert("JustConnect/SecondaryDNS",ui->secondaryDnsLineEdit->text().trimmed());changes.insert("JustConnect/DNSTTL",ui->dnsTTLSpinBox->value());
    changes.insert("JustConnect/DisableRemoteDNS",ui->disableDNSCheckBox->isChecked());changes.insert("JustConnect/BindInterface",ui->bindInterfaceLineEdit->text().trimmed());
    changes.insert("JustConnect/AutoDetectInterface",ui->autoDetectInterfaceCheckBox->isChecked());
    changes.insert("JustConnect/KeepAliveMode",ui->keepAliveModeComboBox->currentData().toString());
    changes.insert("JustConnect/KeepAliveURL",ui->keepAliveUrlLineEdit->text().trimmed());
    return changes;
}

ConnectionProfile SettingWindow::currentProfile() const {
    auto profile=ProfileService::load(publicChanges());
    profile.credentials.password=ui->passwordLineEdit->text();
    profile.credentials.totpSecret=ui->totpSecretLineEdit->text().trimmed();
    return profile;
}

void SettingWindow::clearDraftCredentials() {
    loadedCredentials={};
    ui->passwordLineEdit->setText({});ui->totpSecretLineEdit->setText({});
    credentialStatusText=QT_TR_NOOP("Leave empty to use this account’s saved credentials or enter them when connecting.");
    credentialStatus->setText(tr(credentialStatusText));
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
        if (!CredentialAccess::matches(source,settings)) {
            credentialStatusText=QT_TR_NOOP("The saved profile changed. Reopen the editor.");
            credentialStatus->setText(tr(credentialStatusText));return;
        }
        credentialStatusText=nullptr;credentialLoadStatus=loaded.result.status;
        credentialStatus->setText(PresentationHelpers::credentialOperationMessage(credentialLoadStatus));
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
    if (!CredentialAccess::matches(credentialSource,settings)) {
        QMessageBox::warning(this,tr("Profile changed"),tr("Reopen the editor before clearing credentials."));return;
    }
    auto account=credentialSource.profile.credentials.username;
    if (account.isEmpty()) account=credentialSource.profile.endpoint.phone;
    if (account.isEmpty()) account=tr("the current profile");
    if (QMessageBox::question(this,tr("Clear saved credentials"),tr("Clear saved passwords and authenticator keys for %1? Other accounts are unaffected.").arg(account))!=QMessageBox::Yes) return;
    const auto source=credentialSource;++loadGeneration;saving=true;updateBusy();
    credentials->clear(source).then(this,[this](const CredentialResult &result) {
        if (closed) return;
        saving=false;updateBusy();
        if (!result.succeeded()) {QMessageBox::warning(this,tr("Could not clear credentials"),PresentationHelpers::credentialOperationMessage(result.status));return;}
        if (ui->passwordLineEdit->text()==loadedCredentials.password) ui->passwordLineEdit->setText({});
        if (ui->totpSecretLineEdit->text()==loadedCredentials.totpSecret) ui->totpSecretLineEdit->setText({});
        loadedCredentials={};
        credentialStatusText=QT_TR_NOOP("Saved passwords and authenticator keys were cleared. Unsaved input is unchanged.");
        credentialStatus->setText(tr(credentialStatusText));
        credentialSource=CredentialAccess::source(settings,credentialSource.legacyCachePath);
    });
}
void SettingWindow::applySettings(bool closeAfter) {
    if (closed || loading || saving) return;
    if (!CredentialAccess::matches(credentialSource,settings) || credentialSource.publicValues!=DefaultSettings::publicValues(settings)) {
        QMessageBox::warning(this,tr("Profile changed"),tr("Reopen the editor before applying changes."));return;
    }
    auto profile=currentProfile();
    if (profile.authenticationIdentity()==credentialSource.profile.authenticationIdentity()) {
        if (profile.credentials.password.isEmpty()) profile.credentials.password=loadedCredentials.password;
        if (profile.credentials.totpSecret.isEmpty()) profile.credentials.totpSecret=loadedCredentials.totpSecret;
    }
    if (profile.endpoint.authType.isEmpty()) {
        QMessageBox::warning(this,tr("Choose a sign-in method"),tr("Choose a method from the list provided by your server."));return;
    }
    const auto validation=EmbeddedCoreEngine::validateConfiguration(profile);
    if (validation!=ConnectionError::NONE) {
        const bool unavailable=validation==ConnectionError::CORE_UNAVAILABLE;
        QMessageBox::warning(this,unavailable ? tr("Core unavailable") : tr("Invalid profile"),
            unavailable ? tr("Cannot validate this profile. Check the application installation. Nothing was saved.") : tr("Check the server, sign-in method, ports, DNS and probe target. Nothing was saved."));return;
    }
    saving=true;updateBusy();
    ProfileManager manager;
    const bool autoStart=ui->autoStartCheckBox->isChecked();
    if (manager.autoStartEnabled()!=autoStart) {
        const auto result=AutoStart::setEnabled(autoStart);
        if (!result.succeeded()) {saving=false;updateBusy();QMessageBox::warning(this,tr("Could not update startup registration"),PresentationHelpers::platformOperationMessage(result));return;}
        if (!manager.setAutoStartEnabled(autoStart)) {saving=false;updateBusy();QMessageBox::warning(this,tr("Could not save startup preference"),tr("Startup registration changed, but its preference could not be saved. Check it before retrying."));return;}
    }
    if (!manager.setSilentStartEnabled(ui->silentStartCheckBox->isChecked())) {
        saving=false;updateBusy();QMessageBox::warning(this,tr("Could not save startup preference"),tr("Could not save background startup. Check the configuration folder and retry. This draft has not been applied."));return;
    }
    const auto changes=publicChanges();
    const bool edited=(!ui->passwordLineEdit->text().isEmpty() && ui->passwordLineEdit->text()!=loadedCredentials.password)
        || (!ui->totpSecretLineEdit->text().isEmpty() && ui->totpSecretLineEdit->text()!=loadedCredentials.totpSecret);
    saving=true;updateBusy();const auto source=credentialSource;
    credentials->save(source,profile,edited,changes).then(this,[this,source,profile,closeAfter](const CredentialResult &result) {
        if (closed) return;
        saving=false;updateBusy();
        if (!result.succeeded()) {QMessageBox::warning(this,tr("Could not save profile"),PresentationHelpers::credentialOperationMessage(result.status));return;}
        if (settings.fileName()!=source.path || settings.value(ProfileCredentials::ScopeSetting)!=source.scope) return;
        credentialSource=CredentialAccess::source(settings,source.legacyCachePath);
        if (closeAfter) accept();
        else {loadSettings(settings);readCredentials();}
    });
}
