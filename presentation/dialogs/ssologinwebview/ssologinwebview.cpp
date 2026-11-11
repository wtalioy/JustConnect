#include "presentation/browser/origin.h"
#include "ssologinwebview.h"
#include "ui_ssologinwebview.h"
#include "corelib/abi/constants.h"

#include <QDialogButtonBox>
#include <QEvent>
#include <QIcon>
#include <QShortcut>
#include <QLineEdit>
#include <QToolButton>
#include "presentation/browser/signinbrowser.h"
#include <QUrl>
#include <QUrlQuery>
#include <QHostAddress>

namespace {
bool authCallbackPath(const QString &path) {return path=="/passport/v1/auth/cas" || path=="/passport/v1/auth/httpsOauth2";}


}

SsoLoginWebView::SsoLoginWebView(QWidget *parent,const QUrl &callback,const TlsOptions &policy)
    : QDialog(parent)
    , ui(new Ui::SsoLoginWebView)
    , callbackUrl(callback)
    , tls(policy)
{
    ui->setupUi(this);
    ui->backButton->setIcon(QIcon(":/resource/arrow-left.svg"));
    ui->forwardButton->setIcon(QIcon(":/resource/arrow-right.svg"));
    ui->reloadButton->setIcon(QIcon(":/resource/refresh.svg"));
    for (auto *button:{ui->backButton,ui->forwardButton,ui->reloadButton}) button->setIconSize(QSize(18,18));
    browser=new SignInBrowser(ui->browserHost,callbackUrl,tls,[this](const QUrl &url,bool mainFrame) {
        if (!mainFrame && (url==QUrl("about:blank") || url==QUrl("about:srcdoc"))) return true;
        if (!isAllowedUrl(url)) {showNavigationError();return false;}
        if (!BrowserOrigin::sameEndpoint(url,callbackUrl)) return true;
        if (mainFrame && isCallbackUrl(url)) {
            if (!loginCompletedEmitted) {
                loginCompletedEmitted=true;emit loginCompleted(QString::fromLatin1(url.toEncoded()));
            }
            accept();
        } else if (mainFrame) showNavigationError();
        return false;
    });
    ui->browserLayout->addWidget(browser);
    connect(new QShortcut(QKeySequence::Back,this),&QShortcut::activated,browser,&SignInBrowser::back);
    connect(new QShortcut(QKeySequence::Forward,this),&QShortcut::activated,browser,&SignInBrowser::forward);
    connect(new QShortcut(QKeySequence::Refresh,this),&QShortcut::activated,browser,&SignInBrowser::reload);
    connect(new QShortcut(QKeySequence(QKeyCombination(Qt::ControlModifier,Qt::Key_L)),this),&QShortcut::activated,this,[this] {
        ui->addressLineEdit->setFocus();ui->addressLineEdit->selectAll();
    });

    setAttribute(Qt::WA_DeleteOnClose);
    setModal(true);

    ui->tlsWarningLabel->setVisible(!tls.verify);
    setupConnections();
    connect(browser,&SignInBrowser::certificateRejected,this,[this] {
        failure=NavigationFailure::Certificate;updateWarning();
    });
    connect(browser,&SignInBrowser::initializationFailed,this,[this] {
        failure=NavigationFailure::Runtime;updateWarning();
    });
    connect(browser,&SignInBrowser::addressFocusRequested,this,[this] {
        ui->addressLineEdit->setFocus();ui->addressLineEdit->selectAll();
    });
}

SsoLoginWebView::~SsoLoginWebView()
{
    delete browser;
    delete ui;
}

void SsoLoginWebView::setupConnections()
{
    connect(ui->backButton, &QToolButton::clicked, browser, &SignInBrowser::back);
    connect(ui->forwardButton, &QToolButton::clicked, browser, &SignInBrowser::forward);
    connect(ui->reloadButton, &QToolButton::clicked, browser, &SignInBrowser::reload);
    connect(ui->addressLineEdit, &QLineEdit::returnPressed, this, [&]()
    {
        setInitialUrl(QUrl::fromUserInput(ui->addressLineEdit->text()));
    });

    connect(browser, &SignInBrowser::urlChanged, this, [&](const QUrl &url)
    {
        ui->addressLineEdit->setText(url.toString());
    });

}

void SsoLoginWebView::showNavigationError()
{
    failure=NavigationFailure::Address;updateWarning();
}

void SsoLoginWebView::setInitialUrl(const QUrl &url)
{
    ui->addressLineEdit->setText(url.toString());
    if (!isAllowedUrl(url)) {showNavigationError();return;}
    failure=NavigationFailure::None;updateWarning();
    browser->load(url);
}

bool SsoLoginWebView::isAllowedUrl(const QUrl &url) const
{
    const auto path=callbackUrl.path(QUrl::FullyEncoded);
    if (!callbackUrl.isValid() || callbackUrl.host().isEmpty() || callbackUrl.authority().contains('@') || callbackUrl.port(443)==0
        || callbackUrl.hasFragment() || callbackUrl.hasQuery()
        || !authCallbackPath(path)) return false;
    const bool localGateway=callbackUrl.scheme()=="http" && QHostAddress(callbackUrl.host()).isLoopback();
    if (callbackUrl.scheme()!="https" && !localGateway) return false;
    if (!url.isValid() || url.host().isEmpty() || url.authority().contains('@') || url.port(443)==0) return false;
    if (!tls.verify && BrowserOrigin::escapesCertificateScope(url,callbackUrl)) return false;
    if (authCallbackPath(url.path(QUrl::FullyEncoded)) && !BrowserOrigin::sameEndpoint(url,callbackUrl)) return false;
    return url.scheme()=="https" || (localGateway && BrowserOrigin::same(url,callbackUrl));
}

bool SsoLoginWebView::isCallbackUrl(const QUrl &url) const
{
    if (url.toEncoded().size()>JC_MAX_URL || !isAllowedUrl(url) || !BrowserOrigin::sameEndpoint(url,callbackUrl) || url.hasFragment() || url.query(QUrl::FullyEncoded).contains(';')) return false;
    const auto token=callbackUrl.path()=="/passport/v1/auth/cas" ? QString("ticket") : QString("code");
    int count=0;
    for (const auto &item:QUrlQuery(url).queryItems(QUrl::FullyDecoded)) {
        if (item.first!=token) continue;
        if (item.second.trimmed().isEmpty() || item.second.contains(QChar(0)) || item.second.contains('\r') || item.second.contains('\n')) return false;
        ++count;
    }
    return count==1;
}

void SsoLoginWebView::updateWarning()
{
    ui->navigationWarningLabel->setVisible(failure!=NavigationFailure::None);
    ui->navigationWarningLabel->setText(failure==NavigationFailure::Certificate
        ? tr("The sign-in page certificate is not trusted. Check the server, system time and campus CA.")
        : failure==NavigationFailure::Runtime?tr("The system sign-in browser could not start. On Windows, install or update Microsoft Edge WebView2 Runtime.")
        : failure==NavigationFailure::Address?tr("This sign-in address or callback is not allowed. Check your server and sign-in method."):QString());
}
void SsoLoginWebView::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if (event->type()!=QEvent::LanguageChange) return;
    ui->retranslateUi(this);updateWarning();
}
