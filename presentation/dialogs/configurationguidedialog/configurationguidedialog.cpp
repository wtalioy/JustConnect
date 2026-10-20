#include "configurationguidedialog.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFont>
#include <QGroupBox>
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
#include "infrastructure/settings/settingsprofileloader.h"
#include "application/settingsmigrator.h"

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
    QSettings *settings
)
    : QDialog(parent),
      sourceSettings(settings)
{
    setWindowTitle("配置引导");
    setWindowModality(Qt::WindowModal);
    setMinimumSize(520, 340);

    auto *layout = new QVBoxLayout(this);

    stepLabel = new QLabel(this);
    titleLabel = new QLabel(this);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(titleFont.pointSize() + 4);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);

    descriptionLabel = new QLabel(this);
    descriptionLabel->setWordWrap(true);

    layout->addWidget(stepLabel);
    layout->addWidget(titleLabel);
    layout->addWidget(descriptionLabel);

    pages = new QStackedWidget(this);
    pages->addWidget(createServerPage());
    pages->addWidget(createAuthenticationPage());
    pages->addWidget(createCredentialsPage());
    layout->addWidget(pages, 1);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
    backButton = buttonBox->addButton("上一步", QDialogButtonBox::ActionRole);
    nextButton = buttonBox->addButton("下一步", QDialogButtonBox::AcceptRole);
    layout->addWidget(buttonBox);

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
        {"type",sourceSettings->value("JustConnect/AuthType","psw").toString()},
        {"domain",sourceSettings->value("JustConnect/LoginDomain").toString()},
        {"login_url",sourceSettings->value("JustConnect/LoginURL").toString()},
        {"auth_id",sourceSettings->value("JustConnect/AuthID").toString()},
        {"sub_type",sourceSettings->value("JustConnect/AuthSubType").toString()}
    });

    usernameLineEdit->setText(
        sourceSettings->value("Credential/Username").toString()
    );
    passwordLineEdit->setText(QByteArray::fromBase64(
        sourceSettings->value("Credential/Password").toByteArray()
    ));
    totpSecretLineEdit->setText(
        sourceSettings->value("Credential/TOTPSecret").toString()
    );
    countryCodeLineEdit->setText(
        sourceSettings->value("JustConnect/PhoneCountryCode", "86").toString()
    );
    phoneNumberLineEdit->setText(
        sourceSettings->value("JustConnect/PhoneNumber").toString()
    );
    updateCredentialsPage();
    updateNavigation();
    connect(serverEditor,&ServerSettingsWidget::serverChanged,this,[this] {
        selectAuthenticationMethod({});
    });
}

bool ConfigurationGuideDialog::applyTo(QSettings &settings)
{
    auto profile=SettingsProfileLoader::load(settings);
    profile.endpoint.server=serverEditor->serverAddress(); profile.endpoint.port=serverEditor->serverPort();
    profile.endpoint.authId=selectedAuthId; profile.endpoint.authSubType=selectedAuthSubType;
    profile.endpoint.authType=selectedAuthType; profile.endpoint.loginDomain=selectedLoginDomain;
    profile.credentials={usernameLineEdit->text().trimmed(),passwordLineEdit->text(),totpSecretLineEdit->text().trimmed()};
    const auto country=countryCodeLineEdit->text().trimmed(),phone=phoneNumberLineEdit->text().trimmed();
    profile.endpoint.phone=!country.isEmpty() && !phone.isEmpty() ? country+'-'+phone : QString();
    if (serverEditor->isFudan() && selectedAuthType.isEmpty()) {
        QMessageBox::warning(this,"请选择认证方式","请从 Fudan 服务器获取并选择认证方式。"); return false;
    }
    const auto validation=EmbeddedCoreEngine::validateConfiguration(profile);
    if (validation!=ConnectionError::NONE) {
        const bool unavailable=validation==ConnectionError::CORE_UNAVAILABLE;
        QMessageBox::warning(this,unavailable ? "核心不可用" : "配置无效",
            unavailable ? "无法校验配置，请检查应用安装是否完整。配置未保存。" : "请检查服务器、认证方式及连接设置。配置未保存。");
        return false;
    }
    serverEditor->applyTo(settings);
    settings.setValue(
        "Credential/Username",
        usernameLineEdit->text().trimmed()
    );
    settings.setValue(
        "Credential/Password",
        QString(passwordLineEdit->text().toUtf8().toBase64())
    );
    settings.setValue(
        "Credential/TOTPSecret",
        totpSecretLineEdit->text().trimmed()
    );
    settings.setValue(
        "JustConnect/PhoneCountryCode",
        countryCodeLineEdit->text().trimmed()
    );
    settings.setValue(
        "JustConnect/PhoneNumber",
        phoneNumberLineEdit->text().trimmed()
    );

    settings.setValue("JustConnect/AuthType", selectedAuthType);
    settings.setValue("JustConnect/AuthID",selectedAuthId);
    settings.setValue("JustConnect/AuthSubType",selectedAuthSubType);
    settings.setValue("JustConnect/LoginDomain", selectedLoginDomain);
    settings.setValue("JustConnect/LoginURL", selectedLoginUrl);
    if (!SettingsMigrator::finish(settings)) {
        QMessageBox::warning(this,"保存设置失败","部分设置可能已保存，请检查后重试。"); return false;
    }
    return true;
}

QWidget *ConfigurationGuideDialog::createServerPage()
{
    serverEditor = new ServerSettingsWidget(this);
    serverEditor->load(*sourceSettings);
    return serverEditor;
}

QWidget *ConfigurationGuideDialog::createAuthenticationPage()
{
    auto *page = new QWidget(this);
    auto *pageLayout = new QVBoxLayout(page);

    auto *atrustPage = new QWidget(page);
    auto *atrustLayout = new QVBoxLayout(atrustPage);
    auto *atrustInfo = new QLabel(
        "从服务器读取可用的认证方式，然后选择与你的账号相符的一项。",
        atrustPage
    );
    atrustInfo->setWordWrap(true);
    selectedAuthenticationLabel = new QLabel(atrustPage);
    selectedAuthenticationLabel->setWordWrap(true);
    fetchAuthenticationButton = new QPushButton("获取认证方式", atrustPage);
    atrustLayout->addWidget(atrustInfo);
    atrustLayout->addWidget(selectedAuthenticationLabel);
    atrustLayout->addWidget(fetchAuthenticationButton, 0, Qt::AlignLeft);
    atrustLayout->addStretch();
    pageLayout->addWidget(atrustPage);

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
    credentialPages = new QStackedWidget(page);
    credentialPages->setObjectName("credentialPages");

    auto *passwordPage = new QWidget(credentialPages);
    auto *passwordPageLayout = new QVBoxLayout(passwordPage);
    auto *passwordGroup = new QGroupBox("账号凭据", passwordPage);
    auto *passwordForm = new QFormLayout(passwordGroup);
    passwordForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    usernameLineEdit = new QLineEdit(passwordGroup);
    usernameLineEdit->setObjectName("guideUsernameLineEdit");
    usernameLineEdit->setPlaceholderText("VPN 账号");
    passwordForm->addRow("账号", usernameLineEdit);

    auto *passwordRow = new QWidget(passwordGroup);
    auto *passwordRowLayout = new QHBoxLayout(passwordRow);
    passwordRowLayout->setContentsMargins(0, 0, 0, 0);
    passwordLineEdit = new QLineEdit(passwordRow);
    passwordLineEdit->setObjectName("guidePasswordLineEdit");
    passwordLineEdit->setEchoMode(QLineEdit::Password);
    passwordLineEdit->setPlaceholderText("VPN 密码");
    auto *showPasswordCheckBox = new QCheckBox("显示", passwordRow);
    passwordRowLayout->addWidget(passwordLineEdit, 1);
    passwordRowLayout->addWidget(showPasswordCheckBox);
    passwordForm->addRow("密码", passwordRow);

    auto *totpRow = new QWidget(passwordGroup);
    auto *totpRowLayout = new QHBoxLayout(totpRow);
    totpRowLayout->setContentsMargins(0, 0, 0, 0);
    totpSecretLineEdit = new QLineEdit(totpRow);
    totpSecretLineEdit->setObjectName("guideTotpSecretLineEdit");
    totpSecretLineEdit->setEchoMode(QLineEdit::Password);
    totpSecretLineEdit->setPlaceholderText("可选，TOTP 验证器密钥");
    auto *showTotpCheckBox = new QCheckBox("显示", totpRow);
    totpRowLayout->addWidget(totpSecretLineEdit, 1);
    totpRowLayout->addWidget(showTotpCheckBox);
    passwordForm->addRow("TOTP 密钥", totpRow);

    passwordPageLayout->addWidget(passwordGroup);
    passwordPageLayout->addStretch();
    credentialPages->addWidget(passwordPage);

    auto *phonePage = new QWidget(credentialPages);
    auto *phonePageLayout = new QVBoxLayout(phonePage);
    auto *phoneGroup = new QGroupBox("短信验证手机号", phonePage);
    auto *phoneForm = new QFormLayout(phoneGroup);
    phoneForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    auto *phoneRow = new QWidget(phoneGroup);
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
    phoneNumberLineEdit->setPlaceholderText("手机号码");
    phoneNumberLineEdit->setValidator(new QRegularExpressionValidator(
        QRegularExpression("[0-9]{1,20}"),
        phoneNumberLineEdit
    ));
    phoneRowLayout->addWidget(new QLabel("+", phoneRow));
    phoneRowLayout->addWidget(countryCodeLineEdit);
    phoneRowLayout->addWidget(phoneNumberLineEdit, 1);
    phoneForm->addRow("手机号", phoneRow);
    phonePageLayout->addWidget(phoneGroup);
    phonePageLayout->addStretch();
    credentialPages->addWidget(phonePage);

    auto *ssoPage = new QWidget(credentialPages);
    auto *ssoPageLayout = new QVBoxLayout(ssoPage);
    auto *ssoLabel = new QLabel(
        "此认证方式将在连接时打开登录页面，无需提前填写登录凭据。",
        ssoPage
    );
    ssoLabel->setWordWrap(true);
    ssoPageLayout->addWidget(ssoLabel);
    ssoPageLayout->addStretch();
    credentialPages->addWidget(ssoPage);

    pageLayout->addWidget(credentialPages);

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
        if (applyTo(*sourceSettings)) accept();
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
        if (host==serverEditor->serverAddress() && port==serverEditor->serverPort())
            selectAuthenticationMethod(method);
    });
    auto profile=SettingsProfileLoader::load(*sourceSettings);
    profile.endpoint.server=host; profile.endpoint.port=port;
    authInfoWindow->fetchAuthInfo(profile,serverEditor->isFudan());
    authInfoWindow->show();
}

bool ConfigurationGuideDialog::validateCurrentPage()
{
    if (pages->currentIndex() == 0)
    {
        if (serverEditor->serverAddress().isEmpty())
        {
            QMessageBox::warning(this, "服务器地址无效", "服务器地址不能为空。");
            return false;
        }
    }
    else if (pages->currentIndex() == 1)
    {
        if (selectedAuthType.isEmpty())
        {
            QMessageBox::warning(
                this,
                "尚未选择认证方式",
                "请先获取并选择服务器支持的认证方式。"
            );
            return false;
        }
    }
    else if (pages->currentIndex() == 2)
    {
        if (credentialPages->currentIndex() == 0
            && (usernameLineEdit->text().trimmed().isEmpty()
                || passwordLineEdit->text().isEmpty()))
        {
            QMessageBox::warning(
                this,
                "登录凭据不完整",
                "请填写 VPN 账号和密码。"
            );
            return false;
        }
        if (credentialPages->currentIndex() == 1
            && (countryCodeLineEdit->text().trimmed().isEmpty()
                || phoneNumberLineEdit->text().trimmed().isEmpty()))
        {
            QMessageBox::warning(
                this,
                "手机号不完整",
                "请填写国家代码和手机号码。"
            );
            return false;
        }

    }
    return true;
}

void ConfigurationGuideDialog::updateNavigation()
{
    static const QStringList titles{
        "配置服务器",
        "选择认证方式",
        "配置登录凭据"
    };
    static const QStringList descriptions{
        "选择 Fudan，或使用 Custom 填写其他 aTrust 服务器。",
        "选择服务器为你的账号提供的认证方式。",
        "填写当前认证方式连接时需要的登录信息。"
    };

    const int pageIndex = pages->currentIndex();
    stepLabel->setText(
        QString("步骤 %1 / %2").arg(pageIndex + 1).arg(pages->count())
    );
    titleLabel->setText(titles.value(pageIndex));
    descriptionLabel->setText(descriptions.value(pageIndex));
    backButton->setEnabled(pageIndex > 0);
    nextButton->setText(
        pageIndex == pages->count() - 1 ? "保存" : "下一步"
    );
    updateCredentialsPage();
}

void ConfigurationGuideDialog::selectAuthenticationMethod(const QJsonObject &method)
{
    selectedAuthType=normalizedAuthType(method["type"].toString());
    selectedLoginDomain=method["domain"].toString(); selectedLoginUrl=method["login_url"].toString();
    selectedAuthId=method["auth_id"].toString(); selectedAuthSubType=method["sub_type"].toString();

    QString details = "当前选择：" + authenticationMethodName(selectedAuthType);
    if (!selectedLoginDomain.isEmpty())
    {
        details += "\n登录域：" + selectedLoginDomain;
    }
    selectedAuthenticationLabel->setText(details);
    fetchAuthenticationButton->setText("重新获取认证方式");
    updateCredentialsPage();
}

QString ConfigurationGuideDialog::authenticationMethodName(
    const QString &authType
) const
{
    if (authType == "psw")
    {
        return "用户名和密码";
    }
    if (authType == "smsCheckCode")
    {
        return "短信验证码";
    }
    if (authType == "cas")
    {
        return "CAS";
    }
    if (authType == "httpsOauth2")
    {
        return "OAuth2";
    }
    return authType.isEmpty() ? "尚未选择" : authType;
}
