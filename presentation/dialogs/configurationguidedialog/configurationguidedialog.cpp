#include "configurationguidedialog.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFont>
#include <QEvent>
#include <QScrollArea>
#include <QRegularExpressionValidator>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QStackedWidget>
#include <QStringList>
#include <QVBoxLayout>

#include "presentation/dialogs/authinfowindow/authinfowindow.h"
#include "presentation/widgets/serversettingswidget.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "application/profileservice.h"
#include "application/defaultsettings.h"
#include "presentation/presentationhelpers.h"

namespace
{
QString normalizedAuthType(const QString &authType)
{
    QString normalized = authType;
    if (normalized.startsWith("auth/"))
    {
        normalized.remove(0, 5);
    }
    return normalized;
}
}

ConfigurationGuideDialog::ConfigurationGuideDialog(
    QWidget *parent,
    CredentialAccess *credentials,
    const CredentialSource &source
)
    : QDialog(parent),
      sourceSettings(source.path,QSettings::IniFormat),credentials(credentials),credentialSource(source)
{
    setWindowModality(Qt::WindowModal);
    setMinimumSize(320, 400);
    resize(440, 560);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(24,24,24,24);
    layout->setSpacing(16);

    stepLabel = new QLabel(this);
    titleLabel = new QLabel(this);
    QFont titleFont = titleLabel->font();
    titleFont.setPixelSize(24);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);

    layout->addWidget(stepLabel);
    layout->addWidget(titleLabel);

    pages = new QStackedWidget(this);
    pages->setObjectName("guidePages");
    pages->addWidget(createServerPage());
    pages->addWidget(createAuthenticationPage());
    pages->addWidget(createCredentialsPage());
    layout->addWidget(pages, 1);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
    backButton = new QPushButton(this);
    nextButton = buttonBox->addButton(QString(), QDialogButtonBox::AcceptRole);
    nextButton->setObjectName("guideNextButton");
    auto *navigation = new QHBoxLayout;
    navigation->addWidget(backButton);
    navigation->addStretch();
    navigation->addWidget(buttonBox);
    layout->addLayout(navigation);

    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(backButton, &QPushButton::clicked, this, &ConfigurationGuideDialog::goBack);
    connect(nextButton, &QPushButton::clicked, this, &ConfigurationGuideDialog::goNext);
    connect(
        pages,
        &QStackedWidget::currentChanged,
        this,
        &ConfigurationGuideDialog::updateNavigation
    );

    selectAuthenticationMethod({
        {"type",sourceSettings.value("JustConnect/AuthType","psw").toString()},
        {"domain",sourceSettings.value("JustConnect/LoginDomain").toString()},
        {"auth_id",sourceSettings.value("JustConnect/AuthID").toString()},
        {"sub_type",sourceSettings.value("JustConnect/AuthSubType").toString()}
    });

    usernameLineEdit->setText(
        sourceSettings.value("Credential/Username").toString()
    );
    countryCodeLineEdit->setText(
        sourceSettings.value("JustConnect/PhoneCountryCode", "86").toString()
    );
    phoneNumberLineEdit->setText(
        sourceSettings.value("JustConnect/PhoneNumber").toString()
    );
    updateCredentialsPage();
    updateNavigation();
    connect(this,&QDialog::finished,this,[this]{closed=true;++loadGeneration;});
    connect(serverEditor,&ServerSettingsWidget::serverChanged,this,[this] {selectAuthenticationMethod({});});
    for (auto *field:{usernameLineEdit,countryCodeLineEdit,phoneNumberLineEdit})
        connect(field,&QLineEdit::textChanged,this,&ConfigurationGuideDialog::clearDraftCredentials);
    retranslate();
    readCredentials();
}

QVariantMap ConfigurationGuideDialog::publicChanges() const {
    auto changes=serverEditor->settingsValues();
    changes.insert("Credential/Username",usernameLineEdit->text().trimmed());
    changes.insert("JustConnect/PhoneCountryCode",countryCodeLineEdit->text().trimmed());changes.insert("JustConnect/PhoneNumber",phoneNumberLineEdit->text().trimmed());
    changes.insert("JustConnect/AuthType",selectedAuthType);changes.insert("JustConnect/AuthID",selectedAuthId);
    changes.insert("JustConnect/AuthSubType",selectedAuthSubType);changes.insert("JustConnect/LoginDomain",selectedLoginDomain);
    return changes;
}
ConnectionProfile ConfigurationGuideDialog::currentProfile() const {
    auto values=credentialSource.publicValues;
    values.insert(publicChanges());
    auto profile=ProfileService::load(values);
    profile.credentials.password=passwordLineEdit->text();
    profile.credentials.totpSecret=totpSecretLineEdit->text().trimmed();
    return profile;
}
void ConfigurationGuideDialog::clearDraftCredentials() {
    loadedCredentials={};passwordLineEdit->setText({});totpSecretLineEdit->setText({});
    credentialStatusText=QT_TR_NOOP("Leave empty to use saved credentials or enter them when connecting.");
    credentialStatus->setText(tr(credentialStatusText));
}
void ConfigurationGuideDialog::readCredentials() {
    loading=true;updateNavigation();const auto generation=++loadGeneration;const auto source=credentialSource;
    credentials->load(source).then(this,[this,source,generation](const CredentialLoadResult &loaded) {
        if (closed || generation!=loadGeneration) return;
        loading=false;updateNavigation();
        if (!CredentialAccess::matches(source,sourceSettings)) {
            credentialStatusText=QT_TR_NOOP("The saved profile changed. Reopen setup.");
            credentialStatus->setText(tr(credentialStatusText));return;
        }
        credentialStatusText=nullptr;credentialLoadStatus=loaded.result.status;
        credentialStatus->setText(PresentationHelpers::credentialOperationMessage(credentialLoadStatus));
        if (loaded.result.succeeded() && currentProfile().authenticationIdentity()==source.profile.authenticationIdentity()) {
            const bool passwordUntouched=passwordLineEdit->text()==loadedCredentials.password;
            const bool totpUntouched=totpSecretLineEdit->text()==loadedCredentials.totpSecret;
            loadedCredentials=loaded.credentials;
            if (passwordUntouched) passwordLineEdit->setText(loaded.credentials.password);
            if (totpUntouched) totpSecretLineEdit->setText(loaded.credentials.totpSecret);
        }
    });
}
bool ConfigurationGuideDialog::applyTo() {
    if (closed || loading || saving) return false;
    if (!CredentialAccess::matches(credentialSource,sourceSettings) || credentialSource.publicValues!=DefaultSettings::publicValues(sourceSettings)) {
        QMessageBox::warning(this,tr("Profile changed"),tr("Reopen setup before saving."));return false;
    }
    auto profile=currentProfile();
    if (profile.authenticationIdentity()==credentialSource.profile.authenticationIdentity()) {
        if (profile.credentials.password.isEmpty()) profile.credentials.password=loadedCredentials.password;
        if (profile.credentials.totpSecret.isEmpty()) profile.credentials.totpSecret=loadedCredentials.totpSecret;
    }
    if (selectedAuthType.isEmpty()) {
        QMessageBox::warning(this,tr("Choose a sign-in method"),tr("Choose a method from the list provided by your server.")); return false;
    }
    const auto validation=EmbeddedCoreEngine::validateConfiguration(profile);
    if (validation!=ConnectionError::NONE) {
        const bool unavailable=validation==ConnectionError::CORE_UNAVAILABLE;
        QMessageBox::warning(this,unavailable ? tr("Core unavailable") : tr("Invalid profile"),
            unavailable ? tr("Cannot validate this profile. Check the application installation. Nothing was saved.") : tr("Check the server, sign-in method and connection settings. Nothing was saved."));
        return false;
    }
    const auto changes=publicChanges();
    const bool edited=(!passwordLineEdit->text().isEmpty() && passwordLineEdit->text()!=loadedCredentials.password)
        || (!totpSecretLineEdit->text().isEmpty() && totpSecretLineEdit->text()!=loadedCredentials.totpSecret);
    saving=true;pages->setEnabled(false);updateNavigation();const auto source=credentialSource;
    credentials->save(source,profile,edited,changes).then(this,[this,source](const CredentialResult &result) {
        if (closed) return;
        saving=false;pages->setEnabled(true);updateNavigation();
        if (!result.succeeded()) {QMessageBox::warning(this,tr("Could not save profile"),PresentationHelpers::credentialOperationMessage(result.status));return;}
        if (sourceSettings.fileName()==source.path && sourceSettings.value(ProfileCredentials::ScopeSetting)==source.scope) {
            emit connectRequested();accept();
        }
    });
    return true;
}

QWidget *ConfigurationGuideDialog::createServerPage()
{
    serverEditor = new ServerSettingsWidget(this);
    serverEditor->load(sourceSettings);
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setWidget(serverEditor);
    return scroll;
}

QWidget *ConfigurationGuideDialog::createAuthenticationPage()
{
    auto *page = new QWidget(this);
    auto *pageLayout = new QVBoxLayout(page);

    pageLayout->setContentsMargins(0,0,0,0);
    pageLayout->setSpacing(16);
    selectedAuthenticationLabel = new QLabel(page);
    selectedAuthenticationLabel->setWordWrap(true);
    fetchAuthenticationButton = new QPushButton(page);
    pageLayout->addWidget(selectedAuthenticationLabel);
    pageLayout->addWidget(fetchAuthenticationButton);
    pageLayout->addStretch();

    connect(
        fetchAuthenticationButton,
        &QPushButton::clicked,
        this,
        &ConfigurationGuideDialog::fetchAuthenticationMethods
    );
    return page;
}

QWidget *ConfigurationGuideDialog::createCredentialsPage()
{
    auto *page = new QWidget(this);
    auto *pageLayout = new QVBoxLayout(page);
    pageLayout->setContentsMargins(0,0,0,0);
    pageLayout->setSpacing(16);
    credentialPages = new QStackedWidget(page);
    credentialPages->setObjectName("credentialPages");

    auto *passwordPage = new QWidget(credentialPages);
    auto *passwordPageLayout = new QVBoxLayout(passwordPage);
    passwordPageLayout->setContentsMargins(0,0,0,0);
    auto *passwordForm = new QFormLayout;
    passwordForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    passwordForm->setRowWrapPolicy(QFormLayout::WrapAllRows);
    passwordForm->setVerticalSpacing(8);
    passwordPageLayout->addLayout(passwordForm);

    usernameLineEdit = new QLineEdit(passwordPage);
    usernameLineEdit->setObjectName("guideUsernameLineEdit");
    usernameLabel=new QLabel(passwordPage);
    usernameLabel->setBuddy(usernameLineEdit);
    passwordForm->addRow(usernameLabel, usernameLineEdit);

    auto *passwordRow = new QWidget(passwordPage);
    auto *passwordRowLayout = new QHBoxLayout(passwordRow);
    passwordRowLayout->setContentsMargins(0, 0, 0, 0);
    passwordLineEdit = new QLineEdit(passwordRow);
    passwordLineEdit->setObjectName("guidePasswordLineEdit");
    passwordLineEdit->setEchoMode(QLineEdit::Password);
    showPasswordCheckBox = new QCheckBox(passwordRow);
    passwordRowLayout->addWidget(passwordLineEdit, 1);
    passwordRowLayout->addWidget(showPasswordCheckBox);
    passwordLabel=new QLabel(passwordPage);
    passwordLabel->setBuddy(passwordLineEdit);
    passwordForm->addRow(passwordLabel, passwordRow);

    auto *totpRow = new QWidget(passwordPage);
    auto *totpRowLayout = new QHBoxLayout(totpRow);
    totpRowLayout->setContentsMargins(0, 0, 0, 0);
    totpSecretLineEdit = new QLineEdit(totpRow);
    totpSecretLineEdit->setObjectName("guideTotpSecretLineEdit");
    totpSecretLineEdit->setEchoMode(QLineEdit::Password);
    showTotpCheckBox = new QCheckBox(totpRow);
    totpRowLayout->addWidget(totpSecretLineEdit, 1);
    totpRowLayout->addWidget(showTotpCheckBox);
    totpLabel=new QLabel(passwordPage);
    totpLabel->setBuddy(totpSecretLineEdit);
    passwordForm->addRow(totpLabel, totpRow);

    passwordPageLayout->addStretch();
    credentialPages->addWidget(passwordPage);

    auto *phonePage = new QWidget(credentialPages);
    auto *phonePageLayout = new QVBoxLayout(phonePage);
    phonePageLayout->setContentsMargins(0,0,0,0);
    auto *phoneForm = new QFormLayout;
    phonePageLayout->addLayout(phoneForm);
    phoneForm->setRowWrapPolicy(QFormLayout::WrapAllRows);
    phoneForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    auto *phoneRow = new QWidget(phonePage);
    auto *phoneRowLayout = new QHBoxLayout(phoneRow);
    phoneRowLayout->setContentsMargins(0, 0, 0, 0);
    countryCodeLineEdit = new QLineEdit(phoneRow);
    countryCodeLineEdit->setObjectName("guideCountryCodeLineEdit");
    countryCodeLineEdit->setMaximumWidth(64);
    countryCodeLineEdit->setPlaceholderText("86");
    countryCodeLineEdit->setValidator(new QRegularExpressionValidator(
        QRegularExpression("[0-9]{1,4}"),
        countryCodeLineEdit
    ));
    phoneNumberLineEdit = new QLineEdit(phoneRow);
    phoneNumberLineEdit->setObjectName("guidePhoneNumberLineEdit");
    phoneNumberLineEdit->setValidator(new QRegularExpressionValidator(
        QRegularExpression("[0-9]{1,20}"),
        phoneNumberLineEdit
    ));
    phoneRowLayout->addWidget(new QLabel("+", phoneRow));
    phoneRowLayout->addWidget(countryCodeLineEdit);
    phoneRowLayout->addWidget(phoneNumberLineEdit, 1);
    phoneLabel=new QLabel(phonePage);
    phoneLabel->setBuddy(phoneNumberLineEdit);
    phoneForm->addRow(phoneLabel, phoneRow);
    phonePageLayout->addStretch();
    credentialPages->addWidget(phonePage);

    auto *ssoPage = new QWidget(credentialPages);
    auto *ssoPageLayout = new QVBoxLayout(ssoPage);
    ssoPageLayout->setContentsMargins(0,0,0,0);
    ssoLabel = new QLabel(ssoPage);
    ssoLabel->setWordWrap(true);
    ssoPageLayout->addWidget(ssoLabel);
    ssoPageLayout->addStretch();
    credentialPages->addWidget(ssoPage);

    pageLayout->addWidget(credentialPages);
    credentialStatus=new QLabel(page);credentialStatus->setObjectName("credentialStatusLabel");credentialStatus->setWordWrap(true);
    pageLayout->addWidget(credentialStatus);

    connect(showPasswordCheckBox, &QCheckBox::toggled, this, [this](bool checked) {
        passwordLineEdit->setEchoMode(
            checked ? QLineEdit::Normal : QLineEdit::Password
        );
    });
    connect(showTotpCheckBox, &QCheckBox::toggled, this, [this](bool checked) {
        totpSecretLineEdit->setEchoMode(
            checked ? QLineEdit::Normal : QLineEdit::Password
        );
    });
    return page;
}

void ConfigurationGuideDialog::goBack()
{
    if (pages->currentIndex() > 0)
    {
        pages->setCurrentIndex(pages->currentIndex() - 1);
    }
}

void ConfigurationGuideDialog::goNext()
{
    if (!validateCurrentPage())
    {
        return;
    }

    if (pages->currentIndex() == pages->count() - 1)
    {
        applyTo();
        return;
    }
    pages->setCurrentIndex(pages->currentIndex() + 1);
}

void ConfigurationGuideDialog::updateCredentialsPage()
{
    if (credentialPages == nullptr)
    {
        return;
    }

    if (selectedAuthType == "smsCheckCode")
    {
        credentialPages->setCurrentIndex(1);
    }
    else if (selectedAuthType == "cas" || selectedAuthType == "httpsOauth2")
    {
        credentialPages->setCurrentIndex(2);
    }
    else
    {
        credentialPages->setCurrentIndex(0);
    }
}

void ConfigurationGuideDialog::fetchAuthenticationMethods()
{
    auto *authInfoWindow = new AuthInfoWindow(this);
    const auto host=serverEditor->serverAddress(); const auto port=serverEditor->serverPort();
    connect(authInfoWindow,&AuthInfoWindow::finishAuthInfo,this,[this,host,port](const QJsonObject &method) {
        if (!closed && host==serverEditor->serverAddress() && port==serverEditor->serverPort())
            selectAuthenticationMethod(method);
    });
    authInfoWindow->fetchAuthInfo(currentProfile(),serverEditor->prefersOAuth());
    authInfoWindow->show();
}

bool ConfigurationGuideDialog::validateCurrentPage()
{
    if (pages->currentIndex() == 0)
    {
        if (serverEditor->serverAddress().isEmpty())
        {
            QMessageBox::warning(this, tr("Invalid server"), tr("Enter a server address."));
            return false;
        }
    }
    else if (pages->currentIndex() == 1)
    {
        if (selectedAuthType.isEmpty())
        {
            QMessageBox::warning(
                this,
                tr("No sign-in method selected"),
                tr("Get the available sign-in methods and choose one.")
            );
            return false;
        }
    }
    else if (pages->currentIndex() == 2)
    {
        if (credentialPages->currentIndex() == 1
            && (countryCodeLineEdit->text().trimmed().isEmpty()
                || phoneNumberLineEdit->text().trimmed().isEmpty()))
        {
            QMessageBox::warning(
                this,
                tr("Incomplete phone number"),
                tr("Enter the country code and phone number.")
            );
            return false;
        }

    }
    return true;
}

void ConfigurationGuideDialog::updateNavigation()
{
    const QStringList titles{tr("School and server"),tr("Sign-in method"),tr("Account")};
    const int pageIndex = pages->currentIndex();
    stepLabel->setText(tr("%1 / %2").arg(pageIndex + 1).arg(pages->count()));
    titleLabel->setText(titles.value(pageIndex));
    backButton->setText(tr("Back"));
    backButton->setVisible(pageIndex > 0);
    backButton->setEnabled(!saving);
    nextButton->setEnabled(!saving && (!loading || pageIndex < pages->count()-1));
    nextButton->setText(
        pageIndex == pages->count() - 1 ? tr("Save and connect") : tr("Next")
    );
    updateCredentialsPage();
}

void ConfigurationGuideDialog::selectAuthenticationMethod(const QJsonObject &method)
{
    clearDraftCredentials();
    selectedAuthType=normalizedAuthType(method["type"].toString());
    selectedLoginDomain=method["domain"].toString();
    selectedAuthId=method["auth_id"].toString(); selectedAuthSubType=method["sub_type"].toString();

    updateAuthenticationSelection();
    updateCredentialsPage();
}

void ConfigurationGuideDialog::updateAuthenticationSelection()
{
    QString details=authenticationMethodName(selectedAuthType);
    if (!selectedLoginDomain.isEmpty()) details+=tr("\nDomain: %1").arg(selectedLoginDomain);
    selectedAuthenticationLabel->setText(details);
    fetchAuthenticationButton->setText(selectedAuthType.isEmpty() ? tr("Get sign-in methods") : tr("Change sign-in method"));
}

void ConfigurationGuideDialog::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if(event->type()==QEvent::LanguageChange) retranslate();
}

void ConfigurationGuideDialog::retranslate()
{
    setWindowTitle(tr("Connection setup"));
    usernameLabel->setText(tr("Username"));
    passwordLabel->setText(tr("Password"));
    totpLabel->setText(tr("Authenticator key (optional)"));
    phoneLabel->setText(tr("Phone number"));
    usernameLineEdit->setPlaceholderText(tr("VPN account"));
    passwordLineEdit->setPlaceholderText(tr("Enter when connecting"));
    totpSecretLineEdit->setPlaceholderText(tr("TOTP secret"));
    phoneNumberLineEdit->setPlaceholderText(tr("Phone number"));
    showPasswordCheckBox->setText(tr("Show"));
    showTotpCheckBox->setText(tr("Show"));
    ssoLabel->setText(tr("Your school's sign-in page opens when you connect."));
    credentialStatus->setText(credentialStatusText ? tr(credentialStatusText) : PresentationHelpers::credentialOperationMessage(credentialLoadStatus));
    updateNavigation();
    updateAuthenticationSelection();
}

QString ConfigurationGuideDialog::authenticationMethodName(
    const QString &authType
) const
{
    if (authType == "psw")
    {
        return tr("Username and password");
    }
    if (authType == "smsCheckCode")
    {
        return tr("SMS code");
    }
    if (authType == "cas")
    {
        return "CAS";
    }
    if (authType == "httpsOauth2")
    {
        return "OAuth2";
    }
    return authType.isEmpty() ? tr("Not selected") : authType;
}
