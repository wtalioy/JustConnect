#include "presentation/browser/origin.h"
#include "presentation/browser/signinbrowser.h"

#include <QDir>
#include <QFocusEvent>
#include <QJsonArray>
#include <QLoggingCategory>
#include <QJsonDocument>
#include <QPointer>
#include <QSslCertificate>
#include <QTemporaryDir>
#include <QTimer>
#include <optional>
#include <utility>
#include <qt_windows.h>
#include <wincrypt.h>
#include <wrl.h>
#include <WebView2.h>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
namespace {
Q_LOGGING_CATEGORY(browserLog,"justconnect.signin",QtWarningMsg)
constexpr int CallbackResponseStatus=200;
QString takeString(LPWSTR value) {const auto result=QString::fromWCharArray(value);CoTaskMemFree(value);return result;}

void addCertificates(HCERTSTORE store,const QByteArray &pem) {
    for (const auto &certificate:QSslCertificate::fromData(pem)) {
        const auto der=certificate.toDer();
        CertAddEncodedCertificateToStore(store,X509_ASN_ENCODING,reinterpret_cast<const BYTE *>(der.constData()),DWORD(der.size()),CERT_STORE_ADD_ALWAYS,nullptr);
    }
}
bool trusted(ICoreWebView2Certificate *certificate,const QString &caPem,const QString &host) {
    if (caPem.isEmpty()) return false;
    LPWSTR pem=nullptr;if (FAILED(certificate->ToPemEncoding(&pem))) return false;
    const auto certificates=QSslCertificate::fromData(takeString(pem).toUtf8());
    if (certificates.isEmpty()) return false;
    const auto der=certificates.first().toDer();
    auto leaf=CertCreateCertificateContext(X509_ASN_ENCODING,reinterpret_cast<const BYTE *>(der.constData()),DWORD(der.size()));
    if (!leaf) return false;
    auto roots=CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,0,nullptr);
    auto issuers=CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,0,nullptr);
    if (!roots || !issuers) {
        if(roots)CertCloseStore(roots,0);if(issuers)CertCloseStore(issuers,0);CertFreeCertificateContext(leaf);return false;
    }
    addCertificates(roots,caPem.toUtf8());addCertificates(issuers,caPem.toUtf8());
    ComPtr<ICoreWebView2StringCollection> chain;
    if (SUCCEEDED(certificate->get_PemEncodedIssuerCertificateChain(&chain))) {
        UINT32 count=0;chain->get_Count(&count);
        for (UINT32 index=0;index<count;++index) {
            LPWSTR item=nullptr;if(SUCCEEDED(chain->GetValueAtIndex(index,&item))) addCertificates(issuers,takeString(item).toUtf8());
        }
    }
    CERT_CHAIN_ENGINE_CONFIG config{};config.cbSize=sizeof(config);config.hExclusiveRoot=roots;
    HCERTCHAINENGINE engine=nullptr;PCCERT_CHAIN_CONTEXT context=nullptr;bool okay=false;
    CERT_CHAIN_PARA parameters{};parameters.cbSize=sizeof(parameters);
    if (CertCreateCertificateChainEngine(&config,&engine) && CertGetCertificateChain(engine,leaf,nullptr,issuers,&parameters,0,nullptr,&context)) {
        auto hostname=host.toStdWString();
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};ssl.cbSize=sizeof(ssl);ssl.dwAuthType=AUTHTYPE_SERVER;ssl.pwszServerName=hostname.data();
        CERT_CHAIN_POLICY_PARA policy{};policy.cbSize=sizeof(policy);policy.pvExtraPolicyPara=&ssl;
        CERT_CHAIN_POLICY_STATUS status{};status.cbSize=sizeof(status);
        okay=CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,context,&policy,&status) && status.dwError==0;
    }
    if(context)CertFreeCertificateChain(context);if(engine)CertFreeCertificateChainEngine(engine);
    CertCloseStore(issuers,0);CertCloseStore(roots,0);CertFreeCertificateContext(leaf);return okay;
}
// Retain the environment until its last process exits, then remove the ephemeral profile directory.
struct BrowserStorage {
    ComPtr<ICoreWebView2Environment5> environment;
    QTemporaryDir directory{QDir::tempPath()+"/JustConnect-signin-XXXXXX"};
    EventRegistrationToken exited{};
};
}
struct SignInBrowser::Native {
    ComPtr<ICoreWebView2Controller> controller;
    ComPtr<ICoreWebView2> view;
    std::shared_ptr<BrowserStorage> storage=std::make_shared<BrowserStorage>();
    QUrl current,pending;
    QString html;
    std::optional<UINT64> navigation;
    std::optional<QUrl> callbackNavigation;
    bool htmlPending=false,certificatePending=false,callbackIntercepted=false,failed=false;
    HRESULT apartment=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    void resize(HWND window) {if(controller){RECT bounds{};GetClientRect(window,&bounds);controller->put_Bounds(bounds);}}
    ~Native() {if(controller)controller->Close();view.Reset();controller.Reset();storage.reset();if(SUCCEEDED(apartment))CoUninitialize();}
};

SignInBrowser::SignInBrowser(QWidget *parent,const QUrl &callbackUrl,const TlsOptions &tls,NavigationPolicy navigation)
    :QWidget(parent),native(std::make_unique<Native>()) {
    setAttribute(Qt::WA_NativeWindow);setFocusPolicy(Qt::StrongFocus);setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    const QPointer<SignInBrowser> self(this);
    QTimer::singleShot(0,this,[self,callbackUrl,tls,navigation] {
        const auto fail=[self] {if(self){self->native->failed=true;emit self->initializationFailed();emit self->loadFinished(false);}};
        auto *state=self->native.get();
        qCDebug(browserLog)<<"environment start"<<state->pending.isEmpty();
        if (FAILED(state->apartment) || !state->storage->directory.isValid()) {fail();return;}
        const auto folder=state->storage->directory.path().toStdWString();
        auto storage=state->storage;
        const auto result=CreateCoreWebView2EnvironmentWithOptions(nullptr,folder.c_str(),nullptr,
            Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>([self,callbackUrl,tls,navigation,fail,storage](HRESULT status,ICoreWebView2Environment *environment)->HRESULT {
                qCDebug(browserLog)<<"environment result"<<Qt::hex<<status;
                if (FAILED(status) || !environment) {fail();return S_OK;}
                ComPtr<ICoreWebView2Environment10> modern;
                if (FAILED(environment->QueryInterface(IID_PPV_ARGS(&modern))) || FAILED(environment->QueryInterface(IID_PPV_ARGS(&storage->environment)))) {fail();return S_OK;}
                storage->environment->add_BrowserProcessExited(Callback<ICoreWebView2BrowserProcessExitedEventHandler>([storage](ICoreWebView2Environment *,ICoreWebView2BrowserProcessExitedEventArgs *)->HRESULT {
                    storage->environment->remove_BrowserProcessExited(storage->exited);storage->environment.Reset();storage->directory.remove();return S_OK;
                }).Get(),&storage->exited);
                if (!self) return S_OK;
                ComPtr<ICoreWebView2ControllerOptions> controllerOptions;
                if (FAILED(modern->CreateCoreWebView2ControllerOptions(&controllerOptions))) {fail();return S_OK;}
                if (FAILED(controllerOptions->put_IsInPrivateModeEnabled(TRUE))) {fail();return S_OK;}
                const auto result=modern->CreateCoreWebView2ControllerWithOptions(reinterpret_cast<HWND>(self->winId()),controllerOptions.Get(),
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>([self,callbackUrl,tls,navigation,fail](HRESULT status,ICoreWebView2Controller *controller)->HRESULT {
                        qCDebug(browserLog)<<"controller result"<<Qt::hex<<status;
                        if (!self) {if(controller)controller->Close();return S_OK;}
                        if (FAILED(status) || !controller) {fail();return S_OK;}
                        auto *state=self->native.get();state->controller=controller;
                        if (FAILED(controller->get_CoreWebView2(&state->view))) {fail();return S_OK;}
                        ComPtr<ICoreWebView2_22> modernView;
                        if (FAILED(state->view.As(&modernView))) {fail();return S_OK;}
                        ComPtr<ICoreWebView2Settings> settings;state->view->get_Settings(&settings);
                        if (!settings || FAILED(settings->put_AreDevToolsEnabled(FALSE)) || FAILED(settings->put_IsStatusBarEnabled(FALSE))) {fail();return S_OK;}
                        const auto onNavigation=[self,callbackUrl,navigation](bool main) {
                            return Callback<ICoreWebView2NavigationStartingEventHandler>([self,callbackUrl,navigation,main](ICoreWebView2 *,ICoreWebView2NavigationStartingEventArgs *event)->HRESULT {
                                if (!self) {event->put_Cancel(TRUE);return S_OK;}
                                LPWSTR text=nullptr;event->get_Uri(&text);const QUrl target(takeString(text));
                                qCDebug(browserLog)<<"navigation requested"<<main;
                                const bool callback=BrowserOrigin::sameEndpoint(target,callbackUrl);
                                if(main){self->native->callbackNavigation=callback?std::optional<QUrl>(target):std::nullopt;self->native->callbackIntercepted=false;}
                                // Navigation cancellation alone permits speculative GETs; intercept callbacks at the request boundary.
                                const bool allowed=callback || (main && self->native->htmlPending && target==QUrl("about:blank")) || navigation(target,main);
                                if (!allowed) {
                                    event->put_Cancel(TRUE);
                                    if(main && self) {
                                        UINT64 id=0;event->get_NavigationId(&id);
                                        self->native->navigation=id;self->native->certificatePending=false;
                                    }
                                } else if (main && self) {
                                    UINT64 id=0;event->get_NavigationId(&id);
                                    const bool started=self->native->navigation!=id;
                                    self->native->navigation=id;self->native->htmlPending=false;self->native->certificatePending=false;
                                    if(started)emit self->loadStarted();
                                }
                                return S_OK;
                            });
                        };
                        EventRegistrationToken token{};
                        HRESULT configured=state->view->add_NavigationStarting(onNavigation(true).Get(),&token);
                        if (SUCCEEDED(configured)) configured=state->view->add_FrameNavigationStarting(onNavigation(false).Get(),&token);
                        if (SUCCEEDED(configured)) configured=state->view->add_SourceChanged(Callback<ICoreWebView2SourceChangedEventHandler>([self](ICoreWebView2 *view,ICoreWebView2SourceChangedEventArgs *)->HRESULT {
                            if(self){LPWSTR text=nullptr;view->get_Source(&text);self->native->current=QUrl(takeString(text));emit self->urlChanged(self->native->current);}return S_OK;
                        }).Get(),&token);
                        if (SUCCEEDED(configured)) configured=state->view->add_NavigationCompleted(Callback<ICoreWebView2NavigationCompletedEventHandler>([self,navigation](ICoreWebView2 *,ICoreWebView2NavigationCompletedEventArgs *event)->HRESULT {
                            UINT64 id=0;event->get_NavigationId(&id);
                            if (self && self->native->navigation==id) {
                                BOOL okay=FALSE;event->get_IsSuccess(&okay);
                                COREWEBVIEW2_WEB_ERROR_STATUS error=COREWEBVIEW2_WEB_ERROR_STATUS_UNKNOWN;event->get_WebErrorStatus(&error);
                                // WebView2 reports TLS failure before asking the host to evaluate the certificate.
                                if (!okay && error>=COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_COMMON_NAME_IS_INCORRECT && error<=COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_IS_INVALID) {
                                    self->native->certificatePending=true;return S_OK;
                                }
                                self->native->navigation.reset();
                                if(self->native->callbackIntercepted) {
                                    ComPtr<ICoreWebView2NavigationCompletedEventArgs2> completed;int status=0;
                                    if(SUCCEEDED(event->QueryInterface(IID_PPV_ARGS(&completed))))completed->get_HttpStatusCode(&status);
                                    const auto original=std::exchange(self->native->callbackNavigation,std::nullopt);
                                    self->native->callbackIntercepted=false;
                                    if(status==CallbackResponseStatus && original)QTimer::singleShot(0,self,[self,navigation,original]{if(self)navigation(*original,true);});
                                }
                                emit self->loadFinished(okay);
                            }return S_OK;
                        }).Get(),&token);
                        if (SUCCEEDED(configured)) configured=modernView->add_ServerCertificateErrorDetected(Callback<ICoreWebView2ServerCertificateErrorDetectedEventHandler>([self,callbackUrl,tls](ICoreWebView2 *,ICoreWebView2ServerCertificateErrorDetectedEventArgs *event)->HRESULT {
                            LPWSTR text=nullptr;event->get_RequestUri(&text);const QUrl target(takeString(text));
                            ComPtr<ICoreWebView2Certificate> certificate;event->get_ServerCertificate(&certificate);
                            COREWEBVIEW2_WEB_ERROR_STATUS error=COREWEBVIEW2_WEB_ERROR_STATUS_UNKNOWN;event->get_ErrorStatus(&error);
                            const bool overridable=error!=COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_REVOKED && error!=COREWEBVIEW2_WEB_ERROR_STATUS_CLIENT_CERTIFICATE_CONTAINS_ERRORS;
                            const bool okay=overridable && ((!tls.verify && BrowserOrigin::same(target,callbackUrl)) || (certificate && trusted(certificate.Get(),tls.caPem,target.host())));
                            event->put_Action(okay?COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_ALWAYS_ALLOW:COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL);
                            if (!okay && self) {
                                emit self->certificateRejected();
                                if (self && self->native->certificatePending) {
                                    self->native->certificatePending=false;self->native->navigation.reset();emit self->loadFinished(false);
                                }
                            }return S_OK;
                        }).Get(),&token);
                        if (SUCCEEDED(configured)) {
                            configured=modernView->AddWebResourceRequestedFilterWithRequestSourceKinds(L"*",COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL);
                            if (SUCCEEDED(configured)) configured=state->view->add_WebResourceRequested(Callback<ICoreWebView2WebResourceRequestedEventHandler>([self,callbackUrl,tls,fail](ICoreWebView2 *,ICoreWebView2WebResourceRequestedEventArgs *event)->HRESULT {
                                if(!self)return S_OK;
                                ComPtr<ICoreWebView2WebResourceRequest> request;event->get_Request(&request);LPWSTR text=nullptr;request->get_Uri(&text);const QUrl target(takeString(text));
                                const bool callback=BrowserOrigin::sameEndpoint(target,callbackUrl);
                                if (callback || (!tls.verify && BrowserOrigin::escapesCertificateScope(target,callbackUrl))) {
                                    ComPtr<ICoreWebView2WebResourceResponse> response;
                                    HRESULT status=self->native->storage->environment->CreateWebResourceResponse(nullptr,callback?CallbackResponseStatus:403,
                                        callback?L"OK":L"Forbidden",L"Content-Type: text/html\r\nContent-Length: 0\r\n",&response);
                                    if(SUCCEEDED(status))status=event->put_Response(response.Get());
                                    if(FAILED(status)){self->native->controller->Close();fail();return status;}
                                    if(callback) {
                                        COREWEBVIEW2_WEB_RESOURCE_CONTEXT context;
                                        const bool document=SUCCEEDED(event->get_ResourceContext(&context)) && context==COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT;
                                        // Only a recorded main-frame navigation supplies the callback, including its fragment.
                                        const auto original=self->native->callbackNavigation;
                                        qCDebug(browserLog)<<"callback resource"<<document<<bool(original);
                                        if(document && original && target.query(QUrl::FullyEncoded)==original->query(QUrl::FullyEncoded)) {
                                            self->native->callbackIntercepted=true;
                                        }
                                    }
                                }return S_OK;
                            }).Get(),&token);
                        }
                        if (SUCCEEDED(configured)) configured=state->view->add_NewWindowRequested(Callback<ICoreWebView2NewWindowRequestedEventHandler>([](ICoreWebView2 *,ICoreWebView2NewWindowRequestedEventArgs *event)->HRESULT {return event->put_Handled(TRUE);}).Get(),&token);
                        if (SUCCEEDED(configured)) configured=controller->add_AcceleratorKeyPressed(Callback<ICoreWebView2AcceleratorKeyPressedEventHandler>([self](ICoreWebView2Controller *,ICoreWebView2AcceleratorKeyPressedEventArgs *event)->HRESULT {
                            COREWEBVIEW2_KEY_EVENT_KIND kind;event->get_KeyEventKind(&kind);UINT key=0;event->get_VirtualKey(&key);
                            if (self && (kind==COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN || kind==COREWEBVIEW2_KEY_EVENT_KIND_SYSTEM_KEY_DOWN)) {
                                if ((GetKeyState(VK_CONTROL)&0x8000) && key=='L') {event->put_Handled(TRUE);emit self->addressFocusRequested();}
                                else if (key==VK_F5) {event->put_Handled(TRUE);self->reload();}
                                else if ((GetKeyState(VK_MENU)&0x8000) && (key==VK_LEFT || key==VK_RIGHT)) {event->put_Handled(TRUE);if(key==VK_LEFT)self->back();else self->forward();}
                            }return S_OK;
                        }).Get(),&token);
                        if (SUCCEEDED(configured)) configured=controller->add_MoveFocusRequested(Callback<ICoreWebView2MoveFocusRequestedEventHandler>([self](ICoreWebView2Controller *,ICoreWebView2MoveFocusRequestedEventArgs *event)->HRESULT {
                            if (self) {
                                COREWEBVIEW2_MOVE_FOCUS_REASON reason;event->get_Reason(&reason);
                                event->put_Handled(TRUE);self->focusNextPrevChild(reason==COREWEBVIEW2_MOVE_FOCUS_REASON_NEXT);
                            }return S_OK;
                        }).Get(),&token);
                        if (FAILED(configured)) {fail();return S_OK;}
                        state->resize(reinterpret_cast<HWND>(self->winId()));controller->put_IsVisible(self->isVisible());
                        qCDebug(browserLog)<<"controller ready"<<self->isVisible()<<state->pending.isEmpty();
                        if(state->htmlPending)self->setHtml(state->html);else if(!state->pending.isEmpty())self->load(state->pending);
                        return S_OK;
                    }).Get());
                if(FAILED(result))fail();return S_OK;
            }).Get());
        if (FAILED(result)) fail();
    });
}
SignInBrowser::~SignInBrowser() {disconnect(this,nullptr,nullptr,nullptr);}
void SignInBrowser::load(const QUrl &target) {
    qCDebug(browserLog)<<"load requested"<<bool(native->view)<<target.isEmpty();
    native->pending=target;native->htmlPending=false;
    if(native->failed){QTimer::singleShot(0,this,[this]{emit initializationFailed();emit loadFinished(false);});return;}
    if(native->view && FAILED(native->view->Navigate(QString::fromLatin1(target.toEncoded()).toStdWString().c_str())))emit loadFinished(false);
}
QUrl SignInBrowser::url() const {return native->current;}
void SignInBrowser::back() {if(native->view)native->view->GoBack();}
void SignInBrowser::forward() {if(native->view)native->view->GoForward();}
void SignInBrowser::reload() {if(native->view)native->view->Reload();}
void SignInBrowser::setHtml(const QString &html) {
    native->html=html;native->htmlPending=true;
    if(native->view && FAILED(native->view->NavigateToString(html.toStdWString().c_str())))emit loadFinished(false);
}
void SignInBrowser::runJavaScript(const QString &script,std::function<void(const QVariant &)> result) {
    if(!native->view){result({});return;}
    const QPointer<SignInBrowser> self(this);
    const HRESULT started=native->view->ExecuteScript(script.toStdWString().c_str(),Callback<ICoreWebView2ExecuteScriptCompletedHandler>([self,result](HRESULT status,LPCWSTR json)->HRESULT {
        if(self){const auto document=QJsonDocument::fromJson("["+QString::fromWCharArray(json).toUtf8()+"]");result(SUCCEEDED(status) && !document.array().isEmpty()?document.array().first().toVariant():QVariant());}return S_OK;
    }).Get());
    if (FAILED(started) && self) {qCDebug(browserLog)<<"script start failed"<<Qt::hex<<started;result({});}
}
void SignInBrowser::resizeEvent(QResizeEvent *) {native->resize(reinterpret_cast<HWND>(winId()));}
void SignInBrowser::showEvent(QShowEvent *) {if(native->controller)native->controller->put_IsVisible(TRUE);}
void SignInBrowser::hideEvent(QHideEvent *) {if(native->controller)native->controller->put_IsVisible(FALSE);}
void SignInBrowser::focusInEvent(QFocusEvent *event) {
    if(native->controller)native->controller->MoveFocus(event->reason()==Qt::TabFocusReason?COREWEBVIEW2_MOVE_FOCUS_REASON_NEXT
        :event->reason()==Qt::BacktabFocusReason?COREWEBVIEW2_MOVE_FOCUS_REASON_PREVIOUS:COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
}
