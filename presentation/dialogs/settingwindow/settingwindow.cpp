#include "settingwindow.h"
#include "ui_settingwindow.h"
#include <QCheckBox>
#include <QComboBox>
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
#include <QJsonArray>
#include <QVBoxLayout>
#include "application/defaultsettings.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "application/settingsmigrator.h"
#include "application/profileservice.h"
#include "application/authmethodsquery.h"
#include "presentation/coordinators/controllerselectioncoordinator.h"
#include "presentation/presentationhelpers.h"
#include "presentation/widgets/serversettingswidget.h"

SettingWindow::SettingWindow(QWidget *parent,CredentialAccess *credentials,const CredentialSource &source,CoreEngine *queryEngine)
    : QDialog(parent),ui(new Ui::SettingWindow),settings(source.path,QSettings::IniFormat),credentials(credentials),credentialSource(source) {
    ui->setupUi(this);
    saveButton=ui->buttonBox->addButton(QString(),QDialogButtonBox::AcceptRole);
    saveButton->setObjectName("saveProfileButton");saveButton->setDefault(true);
    dismissButton=ui->buttonBox->addButton(QString(),QDialogButtonBox::RejectRole);
    dismissButton->setObjectName("dismissSettingsButton");
    profileHint=new QLabel(this);profileHint->setObjectName("profileReadOnlyHint");profileHint->setWordWrap(true);profileHint->setProperty("secondary",true);profileHint->hide();
    ui->dialogLayout->insertWidget(0,profileHint);
    setWindowModality(Qt::WindowModal); setAttribute(Qt::WA_DeleteOnClose);
    serverEditor = new ServerSettingsWidget(ui->serverSettingsContainer);
    auto *layout = new QVBoxLayout(ui->serverSettingsContainer);
    layout->setContentsMargins(0,0,0,0); layout->addWidget(serverEditor);
    authQuery=new AuthMethodsQuery(queryEngine ? queryEngine : new EmbeddedCoreEngine,this);
    controllerSelection=new ControllerSelectionCoordinator(this,this);
    queryStatus=new QLabel(this);queryStatus->setObjectName("authQueryStatus");queryStatus->setWordWrap(true);queryStatus->hide();
    ui->authLayout->addWidget(queryStatus);
    connect(authQuery,&AuthMethodsQuery::settled,this,[this]{querying=false;updateBusy();});
    connect(authQuery,&AuthMethodsQuery::ready,this,[this](const QJsonArray &methods) {
        if (closed) return;
        QSignalBlocker blocker(ui->authTypeComboBox);
        ui->authTypeComboBox->clear();ui->authTypeComboBox->addItem(tr("Choose a method"),"");
        int selected=0,preferred=0,oauthCount=0;
        for (const auto &entry:methods) {
            const auto method=entry.toObject();auto type=method["type"].toString();
            if (type.startsWith("auth/")) type.remove(0,5);
            ui->authTypeComboBox->addItem(method["name"].toString().isEmpty()?type:method["name"].toString(),type);
            const int index=ui->authTypeComboBox->count()-1;
            ui->authTypeComboBox->setItemData(index,method,Qt::UserRole+1);
            if (method["auth_id"].toString()==selectedAuthId && !selectedAuthId.isEmpty()) selected=index;
            if (type=="httpsOauth2") {preferred=index;++oauthCount;}
        }
        if (!selected && methods.size()==1) selected=1;
        if (!selected && (selectedAuthType=="httpsOauth2" || serverEditor->prefersOAuth()) && oauthCount==1) selected=preferred;
        ui->authTypeComboBox->setCurrentIndex(selected);
        blocker.unblock();
        emit ui->authTypeComboBox->currentIndexChanged(selected);
        queryStatusText=methods.isEmpty() ? QT_TR_NOOP("No sign-in methods are available.") : nullptr;
        queryStatus->setVisible(queryStatusText);if(queryStatusText)queryStatus->setText(tr(queryStatusText));
    });
    connect(authQuery,&AuthMethodsQuery::failed,this,[this](ConnectionError error) {
        if (closed) return;
        switch (error) {
        case ConnectionError::PERMISSION_DENIED: queryStatusText=QT_TR_NOOP("Network permission was denied. Check interface access or authorization.");break;
        case ConnectionError::TLS_TRUST: queryStatusText=QT_TR_NOOP("The server certificate is not trusted or does not match. Check the address, system time and campus CA.");break;
        case ConnectionError::TLS_PROTOCOL: queryStatusText=QT_TR_NOOP("TLS negotiation failed. Check the server port and TLS compatibility.");break;
        case ConnectionError::NETWORK_FAILED: queryStatusText=QT_TR_NOOP("Connection failed. Check DNS, connectivity and the server address.");break;
        case ConnectionError::TIMED_OUT: queryStatusText=QT_TR_NOOP("The query timed out. Check your network and retry.");break;
        case ConnectionError::AUTHENTICATION_CHANGED: queryStatusText=QT_TR_NOOP("Sign-in methods changed. Query them again.");break;
        default: queryStatusText=QT_TR_NOOP("Could not query sign-in methods. Check the server and connection, then retry.");break;
        }
        queryStatus->setText(tr(queryStatusText));queryStatus->show();
    });
    credentialStatus=new QLabel(ui->credentialsGroup);credentialStatus->setObjectName("credentialStatusLabel");credentialStatus->setWordWrap(true);
    ui->credentialsForm->addRow(credentialStatus);
    rememberAuthentication=new QCheckBox(ui->credentialsGroup);
    rememberAuthentication->setObjectName("rememberAuthenticationCheckBox");
    ui->credentialsForm->addRow(rememberAuthentication);
    clearCredentialButton=new QPushButton(ui->credentialsGroup);clearCredentialButton->setObjectName("clearCredentialButton");clearCredentialButton->setAutoDefault(false);
    ui->credentialsForm->addRow(clearCredentialButton);
    connect(clearCredentialButton,&QPushButton::clicked,this,&SettingWindow::clearCredentials);
    connect(this,&QDialog::finished,this,[this]{closed=true;++loadGeneration;});
    loadSettings(settings);
    connect(serverEditor,&ServerSettingsWidget::serverChanged,this,[this] {
        cancelQuery();
        clearDraftCredentials();
        selectedAuthId.clear(); selectedAuthSubType.clear(); selectedAuthDomain.clear();selectedAuthType.clear();
        resetAuthChoices();updateAuthFields();
    });
    connect(ui->usernameLineEdit,&QLineEdit::textChanged,this,&SettingWindow::clearDraftCredentials);
    connect(ui->countryCodeLineEdit,&QLineEdit::textChanged,this,&SettingWindow::clearDraftCredentials);
    connect(ui->phoneNumberLineEdit,&QLineEdit::textChanged,this,&SettingWindow::clearDraftCredentials);
    connect(ui->authTypeComboBox,&QComboBox::currentIndexChanged,this,[this](int index) {
        const auto method=ui->authTypeComboBox->itemData(index,Qt::UserRole+1).toJsonObject();
        const auto id=method["auth_id"].toString(),subtype=method["sub_type"].toString(),domain=method["domain"].toString();
        if (ui->authTypeComboBox->currentData().toString()!=selectedAuthType || id!=selectedAuthId || subtype!=selectedAuthSubType || domain!=selectedAuthDomain) clearDraftCredentials();
        selectedAuthId=id;selectedAuthSubType=subtype;selectedAuthDomain=domain;
        selectedAuthType=ui->authTypeComboBox->currentData().toString();updateAuthFields();
    });
    connect(ui->authSelectPushButton,&QPushButton::clicked,this,&SettingWindow::queryMethods);
    connect(saveButton,&QPushButton::clicked,this,&SettingWindow::saveSettings);
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
    resize(600,680);

}
SettingWindow::~SettingWindow() { delete ui; }

void SettingWindow::changeEvent(QEvent *event) {
    QDialog::changeEvent(event);
    if(event->type()==QEvent::LanguageChange) retranslate();
}
void SettingWindow::retranslate() {
    QSignalBlocker authBlocker(ui->authTypeComboBox);
    ui->retranslateUi(this);
    const auto forms=ui->loginTabContents->findChildren<QFormLayout *>();
    QList<QWidget *> labels;int labelWidth=0;
    for (auto *form:forms) {
        for (int row=0;row<form->rowCount();++row) {
            auto *item=form->itemAt(row,QFormLayout::LabelRole);
            if (auto *label=item ? item->widget() : nullptr) {
                label->setMinimumWidth(0);
                labels.append(label);labelWidth=qMax(labelWidth,label->sizeHint().width());
            }
        }
    }
    for (auto *label:labels) label->setMinimumWidth(labelWidth);
    PresentationHelpers::passwordVisibilityAction(ui->passwordLineEdit);
    PresentationHelpers::passwordVisibilityAction(ui->totpSecretLineEdit);
    const QStringList types{"","psw","smsCheckCode","cas","httpsOauth2"};
    const QStringList names{tr("Choose a method"),tr("Password"),tr("SMS code"),tr("CAS"),tr("Web sign-in")};
    for (int i=0;i<ui->authTypeComboBox->count();++i) {
        const int known=types.indexOf(ui->authTypeComboBox->itemData(i).toString());
        if (known>=0 && !ui->authTypeComboBox->itemData(i,Qt::UserRole+1).isValid()) ui->authTypeComboBox->setItemText(i,names[known]);
    }
    if (queryStatusText) queryStatus->setText(tr(queryStatusText));
    rememberAuthentication->setText(tr("Remember authentication"));
    rememberAuthentication->setToolTip(tr("Use the system credential store to resume after disconnecting or restarting, for as long as the server allows. Turning this off stops saving and resuming. Use Clear current account authentication cache to delete existing data."));
    ui->passwordLineEdit->setPlaceholderText(tr("Leave blank to keep saved"));
    ui->totpSecretLineEdit->setPlaceholderText(tr("Leave blank to keep saved"));
    clearCredentialButton->setText(tr("Clear saved credentials…"));
    credentialStatus->setText(credentialStatusText ? tr(credentialStatusText) : PresentationHelpers::credentialOperationMessage(credentialLoadStatus));
    updateBusy();
}

void SettingWindow::loadSettings(const QSettings &source) {
    cancelQuery();
    const QSignalBlocker methodBlocker(ui->authTypeComboBox);
    resetAuthChoices();
    ++loadGeneration;loading=false;updateBusy();
    draftValues=DefaultSettings::publicValues(source);
    draftValues.remove("Common/ConfigVersion"); // Schema revisions belong to SettingsMigrator.
    serverEditor->load(source);
    ui->usernameLineEdit->setText(source.value("Credential/Username").toString());
    rememberAuthentication->setChecked(source.value(DefaultSettings::RememberAuthentication,ConnectionBehavior{}.rememberAuthentication).toBool());
    clearDraftCredentials();
    const auto method=source.value("JustConnect/AuthType","psw").toString();
    int index=ui->authTypeComboBox->findData(method);
    if (index<0) { ui->authTypeComboBox->addItem(method,method); index=ui->authTypeComboBox->count()-1; }
    ui->authTypeComboBox->setCurrentIndex(index);
    selectedAuthId=source.value("JustConnect/AuthID").toString(); selectedAuthSubType=source.value("JustConnect/AuthSubType").toString();
    selectedAuthDomain=source.value("JustConnect/LoginDomain").toString();
    ui->countryCodeLineEdit->setText(source.value("JustConnect/PhoneCountryCode","86").toString());
    ui->phoneNumberLineEdit->setText(source.value("JustConnect/PhoneNumber").toString());
    ui->connectAfterStartCheckBox->setChecked(source.value("Common/ConnectAfterStart").toBool());
    ui->checkUpdateAfterStartCheckBox->setChecked(source.value("Common/CheckUpdateAfterStart").toBool());
    ui->autoReconnectCheckBox->setChecked(source.value("Common/AutoReconnect").toBool());
    selectedAuthType=method;updateAuthFields();retranslate();

}

QVariantMap SettingWindow::publicChanges() const {
    auto changes=draftValues;
    const auto server=serverEditor->settingsValues();
    for (auto it=server.cbegin();it!=server.cend();++it) changes.insert(it.key(),it.value());
    changes.insert("Credential/Username",ui->usernameLineEdit->text().trimmed());
    changes.insert(DefaultSettings::RememberAuthentication,rememberAuthentication->isChecked());
    changes.insert("JustConnect/AuthType",ui->authTypeComboBox->currentData().toString());changes.insert("JustConnect/AuthID",selectedAuthId);
    changes.insert("JustConnect/AuthSubType",selectedAuthSubType);changes.insert("JustConnect/LoginDomain",selectedAuthDomain);
    changes.insert("JustConnect/PhoneCountryCode",ui->countryCodeLineEdit->text().trimmed());changes.insert("JustConnect/PhoneNumber",ui->phoneNumberLineEdit->text().trimmed());
    changes.insert("Common/ConnectAfterStart",ui->connectAfterStartCheckBox->isChecked());changes.insert("Common/CheckUpdateAfterStart",ui->checkUpdateAfterStartCheckBox->isChecked());
    changes.insert("Common/AutoReconnect",ui->autoReconnectCheckBox->isChecked());
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
    credentialStatusText=nullptr;credentialStatus->clear();credentialStatus->hide();
}
void SettingWindow::resetAuthChoices() {
    const QSignalBlocker blocker(ui->authTypeComboBox);
    ui->authTypeComboBox->clear();
    for (const auto &method:QStringList{"","psw","smsCheckCode","cas","httpsOauth2"}) ui->authTypeComboBox->addItem(method,method);
    retranslate();
}
void SettingWindow::updateAuthFields() {
    const bool sms=ui->authTypeComboBox->currentData()=="smsCheckCode";
    const bool password=ui->authTypeComboBox->currentData()=="psw";
    ui->credentialsForm->setRowVisible(ui->usernameLineEdit,password);
    ui->credentialsForm->setRowVisible(ui->passwordLineEdit,password);
    ui->credentialsForm->setRowVisible(ui->totpSecretLineEdit,password);
    clearCredentialButton->setVisible(password);
    credentialStatus->setVisible(credentialStatusText || (credentialLoadStatus!=CredentialStatus::Success && credentialLoadStatus!=CredentialStatus::NotFound));
    ui->authForm->setRowVisible(ui->countryCodeLineEdit,sms);
    ui->authForm->setRowVisible(ui->phoneNumberLineEdit,sms);
}
void SettingWindow::setConnectAfterSave(bool connect) {
    connectAfterSave=connect;retranslate();
}
void SettingWindow::setProfileEditable(bool editable) {
    profileEditable=editable;
    if (!editable) cancelQuery();
    updateBusy();
}
void SettingWindow::updateBusy() {
    ui->loginTabContents->setEnabled(profileEditable && !saving);
    profileHint->setVisible(!profileEditable);
    profileHint->setText(tr("Disconnect to edit this connection."));
    saveButton->setVisible(profileEditable);
    saveButton->setEnabled(!loading && !saving && !querying);
    saveButton->setText(connectAfterSave ? tr("Save and connect") : tr("Save"));
    dismissButton->setText(profileEditable ? tr("Cancel") : tr("Close"));
    serverEditor->setEnabled(profileEditable && !saving && !querying);
    ui->authTypeComboBox->setEnabled(profileEditable && !saving && !querying);
    ui->authSelectPushButton->setEnabled(profileEditable && !saving);
    ui->authSelectPushButton->setText(querying ? tr("Cancel") : tr("Get methods"));
    PresentationHelpers::setButtonIcon(ui->authSelectPushButton,querying ? ":/resource/close.svg" : ":/resource/search.svg");
    clearCredentialButton->setEnabled(profileEditable && !loading && !saving);
}
void SettingWindow::cancelQuery() {
    ++queryGeneration;controllerSelection->cancel();authQuery->stop();
    if (!authQuery->isActive()) querying=false;
    queryStatusText=nullptr;queryStatus->hide();updateBusy();
}
void SettingWindow::queryMethods() {
    if (!profileEditable || saving) return;
    if (querying) {cancelQuery();return;}
    querying=true;updateBusy();const auto generation=++queryGeneration;
    queryStatusText=QT_TR_NOOP("Loading sign-in methods…");queryStatus->setText(tr(queryStatusText));queryStatus->show();
    controllerSelection->choose([this,generation,profile=currentProfile()](std::optional<QString> address) mutable {
        if (closed || generation!=queryGeneration) return;
        if (address) profile.behavior.controllerAddress=*address;
        if (!address || !authQuery->start(profile)) {
            querying=false;updateBusy();queryStatusText=QT_TR_NOOP("Query cancelled. Try again when ready.");
            queryStatus->setText(tr(queryStatusText));
        }
    });
}
void SettingWindow::done(int result) {
    cancelQuery();
    if (authQuery->isActive()) {
        setAttribute(Qt::WA_DeleteOnClose,false);
        connect(authQuery,&AuthMethodsQuery::settled,this,&QObject::deleteLater,Qt::SingleShotConnection);
    }
    QDialog::done(result);
}
void SettingWindow::readCredentials() {
    loading=true;updateBusy();const auto generation=++loadGeneration;
    const auto source=credentialSource;
    credentials->load(source).then(this,[this,source,generation](const CredentialLoadResult &loaded) {
        if (closed || generation!=loadGeneration) return;
        loading=false;updateBusy();
        if (!CredentialAccess::matches(source,settings)) {
            credentialStatusText=QT_TR_NOOP("The saved profile changed. Reopen the editor.");
            credentialStatus->setText(tr(credentialStatusText));updateAuthFields();return;
        }
        credentialStatusText=nullptr;credentialLoadStatus=loaded.result.status;updateAuthFields();
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
    if (closed || !profileEditable || loading || saving) return;
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
        updateAuthFields();
        credentialSource=CredentialAccess::source(settings,credentialSource.legacyCachePath);
    });
}
void SettingWindow::saveSettings() {
    if (closed || !profileEditable || loading || saving) return;
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
    const auto changes=publicChanges();
    const bool edited=(!ui->passwordLineEdit->text().isEmpty() && ui->passwordLineEdit->text()!=loadedCredentials.password)
        || (!ui->totpSecretLineEdit->text().isEmpty() && ui->totpSecretLineEdit->text()!=loadedCredentials.totpSecret);
    saving=true;updateBusy();const auto source=credentialSource;
    credentials->save(source,profile,edited,changes).then(this,[this,source,profile](const CredentialResult &result) {
        if (closed) return;
        saving=false;updateBusy();
        if (!result.succeeded()) {QMessageBox::warning(this,tr("Could not save profile"),PresentationHelpers::credentialOperationMessage(result.status));return;}
        if (settings.fileName()!=source.path || settings.value(ProfileCredentials::ScopeSetting)!=source.scope) return;
        credentialSource=CredentialAccess::source(settings,source.legacyCachePath);
        accept();if(connectAfterSave)emit connectRequested();
    });
}
