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
#include <QRegularExpressionValidator>
#include <QSettings>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStringList>
#include <QVBoxLayout>

#include "presentation/dialogs/authinfowindow/authinfowindow.h"

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
    const QSettings *settings
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

    selectAuthenticationMethod(
        sourceSettings->value("JustConnect/AuthType", "psw").toString(),
        sourceSettings->value("JustConnect/LoginDomain").toString(),
        sourceSettings->value("JustConnect/LoginURL").toString()
    );

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
}

void ConfigurationGuideDialog::applyTo(QSettings &settings) const
{
    settings.setValue(
        "JustConnect/ServerAddress",
        serverAddressLineEdit->text().trimmed()
    );
    settings.setValue("JustConnect/ServerPort", serverPortSpinBox->value());
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

    settings.setValue("JustConnect/Protocol", "atrust");
    settings.setValue("JustConnect/AuthType", selectedAuthType);
    settings.setValue("JustConnect/LoginDomain", selectedLoginDomain);
    settings.setValue("JustConnect/LoginURL", selectedLoginUrl);
    settings.sync();
}

QWidget *ConfigurationGuideDialog::createServerPage()
{
    auto *page = new QWidget(this);
    auto *pageLayout = new QVBoxLayout(page);
    auto *formLayout = new QFormLayout();
    formLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    serverAddressLineEdit = new QLineEdit(page);
    serverAddressLineEdit->setPlaceholderText("例如：vpn.example.edu.cn");
    serverAddressLineEdit->setText(
        sourceSettings->value("JustConnect/ServerAddress").toString()
    );
    formLayout->addRow("服务器地址", serverAddressLineEdit);

    serverPortSpinBox = new QSpinBox(page);
    serverPortSpinBox->setRange(1, 65535);
    serverPortSpinBox->setValue(
        sourceSettings->value("JustConnect/ServerPort", 443).toInt()
    );
    formLayout->addRow("服务器端口", serverPortSpinBox);

    pageLayout->addLayout(formLayout);
    pageLayout->addStretch();
    return page;
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
        accept();
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
    connect(
        authInfoWindow,
        &AuthInfoWindow::finishAuthInfo,
        this,
        &ConfigurationGuideDialog::selectAuthenticationMethod
    );
    authInfoWindow->fetchAuthInfo(
        serverAddressLineEdit->text().trimmed(),
        serverPortSpinBox->value()
    );
    authInfoWindow->show();
}

bool ConfigurationGuideDialog::validateCurrentPage()
{
    if (pages->currentIndex() == 0)
    {
        if (serverAddressLineEdit->text().trimmed().isEmpty())
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
        "填写 VPN 服务器提供方给出的地址和端口。",
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

void ConfigurationGuideDialog::selectAuthenticationMethod(
    const QString &authType,
    const QString &loginDomain,
    const QString &loginUrl
)
{
    selectedAuthType = normalizedAuthType(authType);
    selectedLoginDomain = loginDomain;
    selectedLoginUrl = loginUrl;

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
