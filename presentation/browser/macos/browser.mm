#include "presentation/browser/origin.h"
#include "presentation/browser/signinbrowser.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QPointer>
#include <QSslCertificate>
#include <QTimer>
#import <AppKit/AppKit.h>
#import <Security/Security.h>
#import <WebKit/WebKit.h>

namespace {
QUrl url(NSURL *value) {return QUrl(QString::fromNSString(value.absoluteString));}

bool trusted(SecTrustRef trust,const QString &pem,const QString &host) {
    NSMutableArray *anchors=[NSMutableArray array];
    for (const auto &certificate:QSslCertificate::fromData(pem.toUtf8())) {
        const auto der=certificate.toDer();
        SecCertificateRef anchor=SecCertificateCreateWithData(nullptr,(__bridge CFDataRef)[NSData dataWithBytes:der.data() length:der.size()]);
        if (anchor) {[anchors addObject:(__bridge id)anchor];CFRelease(anchor);}
    }
    if (!anchors.count) return false;
    SecPolicyRef policy=SecPolicyCreateSSL(true,(__bridge CFStringRef)host.toNSString());
    const auto policyResult=SecTrustSetPolicies(trust,policy);CFRelease(policy);
    return policyResult==errSecSuccess && SecTrustSetAnchorCertificates(trust,(__bridge CFArrayRef)anchors)==errSecSuccess
        && SecTrustSetAnchorCertificatesOnly(trust,false)==errSecSuccess && SecTrustEvaluateWithError(trust,nullptr);
}
}

@interface JCSignInView : WKWebView
{
@public
    std::function<void()> addressFocus;
}
@end
@implementation JCSignInView
- (BOOL)performKeyEquivalent:(NSEvent *)event {
    if ((event.modifierFlags & NSEventModifierFlagCommand) && [event.charactersIgnoringModifiers isEqualToString:@"l"] && addressFocus) {addressFocus();return YES;}
    return [super performKeyEquivalent:event];
}
@end

@interface JCSignInDelegate : NSObject<WKNavigationDelegate>
{
@public
    std::function<bool(const QUrl &,bool)> navigate;
    std::function<void()> started;
    std::function<void(bool)> finished;
    std::function<void(const QUrl &)> changed;
    std::function<bool(NSURLAuthenticationChallenge *)> certificate;
}
@end
@implementation JCSignInDelegate
- (void)webView:(WKWebView *)view decidePolicyForNavigationAction:(WKNavigationAction *)action decisionHandler:(void (^)(WKNavigationActionPolicy))decision {
    const bool main=action.targetFrame==nil || action.targetFrame.mainFrame;
    const bool allowed=action.targetFrame!=nil && navigate && navigate(url(action.request.URL),main);
    decision(allowed?WKNavigationActionPolicyAllow:WKNavigationActionPolicyCancel);
    if (!allowed && main && finished) finished(false);
}
- (void)webView:(WKWebView *)view didStartProvisionalNavigation:(WKNavigation *)navigation {if(started) started();}
- (void)webView:(WKWebView *)view didFinishNavigation:(WKNavigation *)navigation {
    if (changed) changed(url(view.URL));
    if (finished) finished(true);
}
- (void)webView:(WKWebView *)view didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {if(finished) finished(false);}
- (void)webView:(WKWebView *)view didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error {if(finished) finished(false);}
- (void)webView:(WKWebView *)view didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition,NSURLCredential *))completion {
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completion(NSURLSessionAuthChallengePerformDefaultHandling,nil);return;
    }
    if (certificate && certificate(challenge)) completion(NSURLSessionAuthChallengeUseCredential,[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
    else completion(NSURLSessionAuthChallengeCancelAuthenticationChallenge,nil);
}
@end

struct SignInBrowser::Native {
    JCSignInView *view;
    JCSignInDelegate *delegate;
    QUrl current;
    ~Native() {
        delegate->navigate={};delegate->started={};delegate->finished={};delegate->changed={};delegate->certificate={};
        view->addressFocus={};view.navigationDelegate=nil;[view stopLoading];[view removeFromSuperview];
    }
};

SignInBrowser::SignInBrowser(QWidget *parent,const QUrl &gateway,const TlsOptions &tls,NavigationPolicy navigation)
    :QWidget(parent),native(std::make_unique<Native>()) {
    setAttribute(Qt::WA_NativeWindow);setFocusPolicy(Qt::StrongFocus);
    WKWebViewConfiguration *configuration=[[WKWebViewConfiguration alloc] init];
    configuration.websiteDataStore=[WKWebsiteDataStore nonPersistentDataStore];
    NSView *host=(__bridge NSView *)reinterpret_cast<void *>(winId());
    native->view=[[JCSignInView alloc] initWithFrame:host.bounds configuration:configuration];
    native->view.autoresizingMask=NSViewWidthSizable|NSViewHeightSizable;
    native->delegate=[[JCSignInDelegate alloc] init];
    const QPointer<SignInBrowser> self(this);
    native->view->addressFocus=[self]{if(self)emit self->addressFocusRequested();};
    native->delegate->navigate=[self,navigation](const QUrl &target,bool main){return self && navigation(target,main);};
    native->delegate->started=[self]{if(self)emit self->loadStarted();};
    native->delegate->finished=[self](bool okay){if(self)emit self->loadFinished(okay);};
    native->delegate->changed=[self](const QUrl &target){if(self){self->native->current=target;emit self->urlChanged(target);}};
    native->delegate->certificate=[self,gateway,tls](NSURLAuthenticationChallenge *challenge) {
        const auto space=challenge.protectionSpace;
        QUrl origin;origin.setScheme(QString::fromNSString(space.protocol));origin.setHost(QString::fromNSString(space.host));origin.setPort(int(space.port));
        const bool okay=(!tls.verify && BrowserOrigin::same(origin,gateway))
            || SecTrustEvaluateWithError(space.serverTrust,nullptr) || trusted(space.serverTrust,tls.caPem,origin.host());
        if (!okay && self) emit self->certificateRejected();
        return okay;
    };
    native->view.navigationDelegate=native->delegate;
    [host addSubview:native->view];
}
SignInBrowser::~SignInBrowser() {disconnect(this,nullptr,nullptr,nullptr);}
void SignInBrowser::load(const QUrl &target) {[native->view loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:QString::fromLatin1(target.toEncoded()).toNSString()]]];}
QUrl SignInBrowser::url() const {return native->current;}
void SignInBrowser::back() {[native->view goBack];}
void SignInBrowser::forward() {[native->view goForward];}
void SignInBrowser::reload() {[native->view reload];}
void SignInBrowser::setHtml(const QString &html) {[native->view loadHTMLString:html.toNSString() baseURL:nil];}
void SignInBrowser::runJavaScript(const QString &script,std::function<void(const QVariant &)> result) {
    const QPointer<SignInBrowser> self(this);
    [native->view evaluateJavaScript:script.toNSString() completionHandler:^(id value,NSError *error) {
        if (!self) return;
        NSData *json=value && !error?[NSJSONSerialization dataWithJSONObject:@[value] options:0 error:nil]:nil;
        const auto document=QJsonDocument::fromJson(json?QByteArray(static_cast<const char *>(json.bytes),json.length):QByteArray());
        result(document.array().isEmpty()?QVariant():document.array().first().toVariant());
    }];
}
void SignInBrowser::resizeEvent(QResizeEvent *) {}
void SignInBrowser::showEvent(QShowEvent *) {native->view.hidden=NO;}
void SignInBrowser::hideEvent(QHideEvent *) {native->view.hidden=YES;}
void SignInBrowser::focusInEvent(QFocusEvent *) {[native->view.window makeFirstResponder:native->view];}
