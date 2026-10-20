#include "ssologinwebview.h"
#include "ui_ssologinwebview.h"
#include "corelib/abi/constants.h"

#include <QDialogButtonBox>
#include <QLineEdit>
#include <QToolButton>
#include <QWebEngineHistory>
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QtWebEngineCore>
#include <QUrl>
#include <QUrlQuery>
#include <QHostAddress>

namespace {
class SsoPage final:public QWebEnginePage {
public:
    using QWebEnginePage::QWebEnginePage;
protected:
    // Identity-provider scripts can put tokens and callback URLs in console output.
    void javaScriptConsoleMessage(JavaScriptConsoleMessageLevel,const QString &,int,const QString &) override {}
};
bool authCallbackPath(const QString &path) {return path=="/passport/v1/auth/cas" || path=="/passport/v1/auth/httpsOauth2";}
bool sameOrigin(const QUrl &a,const QUrl &b) {
    const auto port=[](const QUrl &url){return url.port(url.scheme()=="https" ? 443 : 80);};
    return a.scheme()==b.scheme() && a.host().compare(b.host(),Qt::CaseInsensitive)==0 && port(a)==port(b);
}
}

SsoLoginWebView::SsoLoginWebView(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::SsoLoginWebView)
{
    ui->setupUi(this);
    auto *profile = new QWebEngineProfile(this);
    ui->webEngineView->setPage(new SsoPage(profile, ui->webEngineView));

    setAttribute(Qt::WA_DeleteOnClose);
    setModal(true);

    setupConnections();
}

SsoLoginWebView::~SsoLoginWebView()
{
    delete ui;
}

void SsoLoginWebView::setupConnections()
{
    connect(ui->backButton, &QToolButton::clicked, ui->webEngineView, &QWebEngineView::back);
    connect(ui->forwardButton, &QToolButton::clicked, ui->webEngineView, &QWebEngineView::forward);
    connect(ui->reloadButton, &QToolButton::clicked, ui->webEngineView, &QWebEngineView::reload);
    connect(ui->addressLineEdit, &QLineEdit::returnPressed, this, [&]()
    {
        setInitialUrl(QUrl::fromUserInput(ui->addressLineEdit->text()));
    });

    connect(ui->webEngineView, &QWebEngineView::urlChanged, this, [&](const QUrl &url)
    {
        ui->addressLineEdit->setText(url.toString());
    });

    connect(ui->webEngineView->page(),&QWebEnginePage::navigationRequested,this,
        [this](QWebEngineNavigationRequest &request) {
            const auto url=request.url();
            if (!request.isMainFrame() && (url==QUrl("about:blank") || url==QUrl("about:srcdoc"))) {request.accept();return;}
            if (!isAllowedUrl(url)) {
                request.reject();ui->navigationWarningLabel->show();return;
            }
            if (sameOrigin(url,callbackUrl) && url.path(QUrl::FullyEncoded)==callbackUrl.path(QUrl::FullyEncoded)) {
                request.reject();
                if (request.isMainFrame() && isCallbackUrl(url)) {
                    if (!loginCompletedEmitted) {
                        loginCompletedEmitted=true;emit loginCompleted(QString::fromLatin1(url.toEncoded()));
                    }
                    accept();
                } else if (request.isMainFrame()) ui->navigationWarningLabel->show();
                return;
            }
            request.accept();
        });
}

void SsoLoginWebView::setInitialUrl(const QUrl &url)
{
    ui->addressLineEdit->setText(url.toString());
    if (!isAllowedUrl(url)) {ui->navigationWarningLabel->show();return;}
    ui->navigationWarningLabel->hide();
    ui->webEngineView->load(url);
}

void SsoLoginWebView::setCallbackUrl(const QUrl &url)
{
    callbackUrl=url;
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
    if (authCallbackPath(url.path(QUrl::FullyEncoded)) && (!sameOrigin(url,callbackUrl) || url.path(QUrl::FullyEncoded)!=path)) return false;
    return url.scheme()=="https" || (localGateway && sameOrigin(url,callbackUrl));
}

bool SsoLoginWebView::isCallbackUrl(const QUrl &url) const
{
    if (url.toEncoded().size()>JC_MAX_URL || !isAllowedUrl(url) || !sameOrigin(url,callbackUrl) || url.hasFragment()
        || url.path(QUrl::FullyEncoded)!=callbackUrl.path(QUrl::FullyEncoded) || url.query(QUrl::FullyEncoded).contains(';')) return false;
    const auto token=callbackUrl.path()=="/passport/v1/auth/cas" ? QString("ticket") : QString("code");
    int count=0;
    for (const auto &item:QUrlQuery(url).queryItems(QUrl::FullyDecoded)) {
        if (item.first!=token) continue;
        if (item.second.trimmed().isEmpty() || item.second.contains(QChar(0)) || item.second.contains('\r') || item.second.contains('\n')) return false;
        ++count;
    }
    return count==1;
}
