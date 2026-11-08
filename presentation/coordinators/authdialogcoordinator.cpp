#include "authdialogcoordinator.h"
#include "presentation/widgets/localizeddialog.h"
#include "presentation/presentationhelpers.h"

#include <QCheckBox>
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

namespace {
void spaceForm(QVBoxLayout *layout) {layout->setContentsMargins(24,24,24,24);layout->setSpacing(12);layout->parentWidget()->setMinimumWidth(320);}
}

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
        PresentationHelpers::activateWindow(parentWidget);PresentationHelpers::activateWindow(loginWindow);
        return;
    }

    loginWindow = new LoginWindow(parentWidget);
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
    PresentationHelpers::activateWindow(parentWidget);PresentationHelpers::activateWindow(loginWindow);
}

void AuthDialogCoordinator::requestPhoneNumber(
    const QString &countryCode,
    const QString &phoneNumber
)
{
    if (phoneNumberDialog != nullptr)
    {
        PresentationHelpers::activateWindow(parentWidget);PresentationHelpers::activateWindow(phoneNumberDialog);
        return;
    }

    auto *dialog = new LocalizedDialog<QDialog>(parentWidget);
    phoneNumberDialog = dialog;
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowModality(Qt::WindowModal);

    auto *layout = new QVBoxLayout(dialog);
    spaceForm(layout);
    auto *phoneLabel=new QLabel(dialog);phoneLabel->setWordWrap(true);layout->addWidget(phoneLabel);

    auto *phoneLayout = new QHBoxLayout;
    phoneLayout->addWidget(new QLabel("+", dialog));
    auto *countryCodeEdit = new QLineEdit(countryCode, dialog);
    countryCodeEdit->setObjectName("countryCodeLineEdit");
    countryCodeEdit->setMaximumWidth(88);
    phoneLayout->addWidget(countryCodeEdit);
    phoneLayout->addWidget(new QLabel("-", dialog));
    auto *phoneNumberEdit = new QLineEdit(phoneNumber, dialog);
    phoneNumberEdit->setObjectName("phoneNumberLineEdit");
    phoneLayout->addWidget(phoneNumberEdit);
    layout->addLayout(phoneLayout);

    auto *saveCheckBox = new QCheckBox(dialog);
    phoneLabel->setBuddy(phoneNumberEdit);
    dialog->setTranslation([dialog,phoneLabel,countryCodeEdit,phoneNumberEdit,saveCheckBox] {
        dialog->setWindowTitle(tr("SMS verification"));phoneLabel->setText(tr("Phone number"));
        countryCodeEdit->setPlaceholderText(tr("Country"));phoneNumberEdit->setPlaceholderText(tr("Phone number"));
        saveCheckBox->setText(tr("Remember phone number"));
    });
    layout->addWidget(saveCheckBox);

    auto *buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        dialog
    );
    connect(
        buttonBox,
        &QDialogButtonBox::accepted,
        this,
        [this, dialog, countryCodeEdit, phoneNumberEdit, saveCheckBox]()
        {
            if (phoneNumberDialog!=dialog) return;
            const QString submittedCountryCode = countryCodeEdit->text().trimmed();
            const QString submittedPhoneNumber = phoneNumberEdit->text().trimmed();
            if (submittedCountryCode.isEmpty() || submittedPhoneNumber.isEmpty())
            {
                QMessageBox::warning(
                    dialog,
                    tr("Warning"),
                    tr("Country code and phone number are required.")
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
    dialog->resize(400,dialog->sizeHint().height());
    PresentationHelpers::activateWindow(parentWidget);PresentationHelpers::activateWindow(dialog);
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
    SsoLoginWebView *signIn = nullptr;
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
        signIn = new SsoLoginWebView(parentWidget,callback,tls);
        connect(signIn, &SsoLoginWebView::loginCompleted, this, [submit](const QString &url) {
            if (!url.isEmpty()) submit({{"action", "submit"}, {"callback_url", url}});
        });
        dialog = signIn;
    } else if (kind == "trusted_device") {
        auto *input=new LocalizedDialog<QDialog>(parentWidget);dialog=input;
        auto *layout = new QVBoxLayout(dialog);
        spaceForm(layout);
        auto *label = new QLabel(dialog);
        input->setTranslation([input,label] {input->setWindowTitle(tr("Trust this device?"));label->setText(tr("The server wants to remember this device as trusted. Allow it?"));});
        label->setWordWrap(true);
        layout->addWidget(label);
        auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog);
        buttons->button(QDialogButtonBox::Ok)->setAutoDefault(false);
        buttons->button(QDialogButtonBox::Cancel)->setDefault(true);
        layout->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        connect(dialog, &QDialog::accepted, this, [submit] { submit({{"action", "confirm"}}); });
        input->resize(400,input->sizeHint().height());
    } else if (kind == "sms" || kind == "totp" || kind == "radius") {
        auto *input=new LocalizedDialog<QDialog>(parentWidget);dialog=input;
        auto *layout = new QVBoxLayout(dialog);
        spaceForm(layout);
        auto *prompt=new QLabel(dialog);layout->addWidget(prompt);
        auto *code = new QLineEdit(dialog);
        code->setObjectName("authCodeEdit");
        layout->addWidget(code);
        auto *skip = new QCheckBox(dialog);
        prompt->setBuddy(code);
        input->setTranslation([input,prompt,skip,kind] {
            input->setWindowTitle(kind=="sms"?tr("SMS code"):kind=="totp"?tr("Authenticator code"):tr("RADIUS passcode"));
            prompt->setText(tr("Verification code"));skip->setText(tr("Skip future verification"));
        });
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
        input->resize(400,input->sizeHint().height());
    } else {
        submit({{"action", "cancel"}});
        return;
    }
    challengeDialog = dialog;
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowModality(Qt::WindowModal);
    connect(dialog, &QDialog::rejected, this, [submit] { submit({{"action", "cancel"}}); });
    PresentationHelpers::activateWindow(parentWidget);PresentationHelpers::activateWindow(dialog);
    if (signIn) signIn->setInitialUrl(QUrl(challenge["login_url"].toString()));
}
