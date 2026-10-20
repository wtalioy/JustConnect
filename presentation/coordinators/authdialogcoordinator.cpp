#include "authdialogcoordinator.h"

#include <QCheckBox>
#include <QDebug>
#include <QDialog>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

#include "presentation/dialogs/graphcaptchawindow/graphcaptchawindow.h"
#include "presentation/dialogs/loginwindow/loginwindow.h"
#include "presentation/dialogs/ssologinwebview/ssologinwebview.h"
#include "application/coreengine.h"
#include <QSignalBlocker>

AuthDialogCoordinator::AuthDialogCoordinator(
    QWidget *parentWidget,
    QObject *parent
)
    : QObject(parent),
      parentWidget(parentWidget)
{
}

void AuthDialogCoordinator::requestLogin(
    const QString &username,
    const QString &password
)
{
    if (loginWindow != nullptr)
    {
        loginWindow->raise();
        loginWindow->activateWindow();
        return;
    }

    loginWindow = new LoginWindow(parentWidget);
    loginWindow->setAttribute(Qt::WA_DeleteOnClose);
    loginWindow->setDetail(username, password);
    const QPointer<LoginWindow> dialog=loginWindow;
    connect(dialog,&LoginWindow::login,this,[this,dialog](const QString &username,const QString &password,bool save) {
        if (dialog && loginWindow==dialog) emit loginSubmitted(username,password,save);
    });
    connect(dialog,&QDialog::finished,this,[this,dialog](int result) {
        if (loginWindow!=dialog) return;
        loginWindow=nullptr;
        if (result==QDialog::Rejected) emit credentialInputCancelled();
    });
    loginWindow->show();
}

void AuthDialogCoordinator::requestPhoneNumber(
    const QString &countryCode,
    const QString &phoneNumber
)
{
    if (phoneNumberDialog != nullptr)
    {
        phoneNumberDialog->raise();
        phoneNumberDialog->activateWindow();
        return;
    }

    auto *dialog = new QDialog(parentWidget);
    phoneNumberDialog = dialog;
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowModality(Qt::WindowModal);
    dialog->setWindowTitle("短信验证");

    auto *layout = new QVBoxLayout(dialog);
    layout->addWidget(new QLabel("请输入接收验证码的手机号码：", dialog));

    auto *phoneLayout = new QHBoxLayout;
    phoneLayout->addWidget(new QLabel("+", dialog));
    auto *countryCodeEdit = new QLineEdit(countryCode, dialog);
    countryCodeEdit->setObjectName("countryCodeLineEdit");
    countryCodeEdit->setMaximumWidth(60);
    countryCodeEdit->setPlaceholderText("国家码");
    phoneLayout->addWidget(countryCodeEdit);
    phoneLayout->addWidget(new QLabel("-", dialog));
    auto *phoneNumberEdit = new QLineEdit(phoneNumber, dialog);
    phoneNumberEdit->setObjectName("phoneNumberLineEdit");
    phoneNumberEdit->setPlaceholderText("手机号码");
    phoneLayout->addWidget(phoneNumberEdit);
    layout->addLayout(phoneLayout);

    auto *saveCheckBox = new QCheckBox("记住手机号码（可在设置中删除）", dialog);
    layout->addWidget(saveCheckBox);

    auto *buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        dialog
    );
    connect(
        buttonBox,
        &QDialogButtonBox::accepted,
        dialog,
        [this, dialog, countryCodeEdit, phoneNumberEdit, saveCheckBox]()
        {
            if (phoneNumberDialog!=dialog) return;
            const QString submittedCountryCode = countryCodeEdit->text().trimmed();
            const QString submittedPhoneNumber = phoneNumberEdit->text().trimmed();
            if (submittedCountryCode.isEmpty() || submittedPhoneNumber.isEmpty())
            {
                QMessageBox::warning(
                    dialog,
                    "警告",
                    "国家码或手机号码不能为空。"
                );
                return;
            }

            emit phoneNumberSubmitted(
                submittedCountryCode,
                submittedPhoneNumber,
                saveCheckBox->isChecked()
            );
            dialog->accept();
        }
    );
    connect(dialog,&QDialog::finished,this,[this,dialog](int result) {
        if (phoneNumberDialog!=dialog) return;
        phoneNumberDialog=nullptr;
        if (result==QDialog::Rejected) emit credentialInputCancelled();
    });
    connect(buttonBox, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    if (phoneNumber.isEmpty())
    {
        phoneNumberEdit->setFocus();
    }
    else
    {
        countryCodeEdit->setFocus();
    }
    dialog->show();
}

void AuthDialogCoordinator::closeCredentialPrompts()
{
    const auto login=loginWindow;loginWindow=nullptr;
    const auto phone=phoneNumberDialog;phoneNumberDialog=nullptr;
    if (login) {const QSignalBlocker blocker(login);login->close();}
    if (phone) {const QSignalBlocker blocker(phone);phone->close();}
}

void AuthDialogCoordinator::closeAuthentication()
{
    if (!challengeDialog) return;
    const QSignalBlocker blocker(challengeDialog);
    challengeDialog->close();
    challengeDialog = nullptr;
}

void AuthDialogCoordinator::requestAuthentication(const QJsonObject &request, const QUrl &callbackServer,const TlsOptions &tls)
{
    closeAuthentication();
    const auto challenge = request["challenge"].toObject();
    const auto kind = challenge["kind"].toString();
    const auto submit = [this, request](const QJsonObject &fields) {
        emit responseSubmitted(CoreEngine::responseFor(request, fields));
    };
    QDialog *dialog = nullptr;
    if (kind == "click_captcha" || kind == "text_captcha") {
        auto *captcha = new GraphCaptchaWindow(parentWidget);
        captcha->setGraph(QByteArray::fromBase64(challenge["image"].toString().toUtf8()), kind == "text_captcha");
        connect(captcha, &GraphCaptchaWindow::finishCaptcha, this, [submit](QJsonObject fields) {
            fields["action"] = "submit";
            submit(fields);
        });
        dialog = captcha;
    } else if (kind == "cas" || kind == "oauth2") {
        auto callback=callbackServer;
        callback.setPath(kind=="cas" ? "/passport/v1/auth/cas" : "/passport/v1/auth/httpsOauth2");
        callback.setQuery(QString());callback.setFragment(QString());
        auto *web = new SsoLoginWebView(parentWidget,callback,tls);
        web->setInitialUrl(QUrl(challenge["login_url"].toString()));
        connect(web, &SsoLoginWebView::loginCompleted, this, [submit](const QString &url) {
            if (!url.isEmpty()) submit({{"action", "submit"}, {"callback_url", url}});
        });
        dialog = web;
    } else if (kind == "trusted_device") {
        dialog = new QDialog(parentWidget);
        dialog->setWindowTitle("确认可信设备");
        auto *layout = new QVBoxLayout(dialog);
        auto *label = new QLabel("服务器要求将当前设备登记为可信设备。是否确认？", dialog);
        label->setWordWrap(true);
        layout->addWidget(label);
        auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog);
        buttons->button(QDialogButtonBox::Ok)->setText("确认登记");
        buttons->button(QDialogButtonBox::Ok)->setAutoDefault(false);
        buttons->button(QDialogButtonBox::Cancel)->setDefault(true);
        layout->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        connect(dialog, &QDialog::accepted, this, [submit] { submit({{"action", "confirm"}}); });
    } else if (kind == "sms" || kind == "totp" || kind == "radius") {
        dialog = new QDialog(parentWidget);
        dialog->setWindowTitle(kind == "sms" ? "短信验证码" : kind == "totp" ? "TOTP 验证码" : "RADIUS 动态口令");
        auto *layout = new QVBoxLayout(dialog);
        layout->addWidget(new QLabel("请输入验证码：", dialog));
        auto *code = new QLineEdit(dialog);
        code->setObjectName("authCodeEdit");
        layout->addWidget(code);
        auto *skip = new QCheckBox("跳过以后的二次认证", dialog);
        skip->setObjectName("skipSecondaryAuthCheckBox");
        skip->setVisible(challenge["can_skip_secondary_auth"].toBool());
        layout->addWidget(skip);
        auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog);
        layout->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::accepted, dialog, [dialog, code, skip, challenge] {
            if (code->text().trimmed().isEmpty()
                && !(challenge["can_skip_secondary_auth"].toBool() && skip->isChecked())) return;
            dialog->accept();
        });
        connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        connect(dialog, &QDialog::accepted, this, [submit, code, skip, challenge] {
            submit({{"action", "submit"}, {"code", code->text()},
                {"skip_secondary_auth", challenge["can_skip_secondary_auth"].toBool() && skip->isChecked()}});
        });
    } else {
        submit({{"action", "cancel"}});
        return;
    }
    challengeDialog = dialog;
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowModality(Qt::WindowModal);
    connect(dialog, &QDialog::rejected, this, [submit] { submit({{"action", "cancel"}}); });
    dialog->show();
}
