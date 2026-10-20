#include "application/connectionsession.h"
#include "tests/credentialstorefixture.h"
#include "application/applicationlogger.h"
#include "application/systemproxysession.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "presentation/coordinators/authdialogcoordinator.h"
#include "presentation/coordinators/connectionuicontroller.h"
#include "presentation/dialogs/authinfowindow/authinfowindow.h"
#include "presentation/dialogs/ssologinwebview/ssologinwebview.h"
#include "coreabi/proxycheck.h"

#include <QApplication>
#include <QAction>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSettings>
#include <QSemaphore>
#include <QTemporaryDir>
#include <QTimer>
#include <QUuid>
#include <QTcpServer>
#include <QTcpSocket>
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <atomic>

using ProxyCheck::check;
template<class Predicate> static void until(Predicate done) {
    QElapsedTimer elapsed;
    elapsed.start();
    while (!done() && elapsed.elapsed() < 10000)
        QApplication::processEvents(QEventLoop::AllEvents, 10);
    check(done(), "Qt UI operation timed out");
}
static QDialog *challenge(QWidget &parent) {
    for (auto *dialog : parent.findChildren<QDialog *>())
        if (dialog->isVisible()) return dialog;
    check(false, "authentication dialog is visible");
    return nullptr;
}
static void enterCode(QWidget &parent, const QString &value) {
    auto *dialog = challenge(parent);
    auto *code = dialog->findChild<QLineEdit *>("authCodeEdit");
    check(code != nullptr, "structured code challenge");
    code->setText(value);
    dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();
}
class QueryEngine : public CoreEngine {
public:
    ConnectionProfile profile;
    Operation operation = Operation::Connect;
    int stops = 0,starts=0;
    bool start(const ConnectionProfile &p, Operation op) override { ++starts;profile = p; operation = op; return true; }
    void stop() override { ++stops; }
    void respond(const QJsonObject &) override { check(false, "query never takes interactive input"); }
};
class ProxyBackend : public SystemProxyBackend {
public:
    std::atomic<int> checks = 0, applied = 0;
    bool block = false;
    SystemProxyCheck checkResult;
    QSemaphore entered, proceed;
    SystemProxyCheck check(const SystemProxyConfig &) override {
        ++checks;
        if (block) { entered.release(); proceed.acquire(); }
        return checkResult;
    }
    PlatformOperationResult apply(const SystemProxyConfig &) override { ++applied; return {}; }
    PlatformOperationResult clear() override { return {}; }
};
static void proxyWaitsForReady() {
    QTemporaryDir directory;
    QSettings settings(directory.filePath("profile.ini"), QSettings::IniFormat);
    settings.setValue("JustConnect/ServerAddress", "vpn.example.invalid");
    settings.setValue("JustConnect/ServerPort",443);
    settings.setValue("JustConnect/AuthType", "psw");
    settings.setValue("Credential/Username", "fixture-user");
    settings.setValue("Credential/Password", QByteArray("fixture-password").toBase64());
    settings.setValue("Common/AutoSetProxy", true);
    QWidget parent;
    QPushButton connectButton(&parent), proxyButton(&parent);
    QAction trayAction(&parent);
    auto *engine = new QueryEngine;
    ConnectionSession session(engine);
    auto backend = std::make_unique<ProxyBackend>();
    auto *proxy = backend.get();
    SystemProxySession systemProxy(std::move(backend));
    AuthDialogCoordinator dialogs(&parent);
    ApplicationLogger logger;
    CredentialAccess credentials(std::make_unique<MemoryCredentialStore>());
    ConnectionUiController controller(&parent, &connectButton, &proxyButton, &trayAction,
        &session, &systemProxy, &dialogs, &logger, &credentials, [&] { return &settings; },
        [&] {return CredentialAccess::source(settings,{});},
        [](const QString &, const QString &, QSystemTrayIcon::MessageIcon) {});
    connectButton.click();
    until([&] {return session.state()==ConnectionState::Starting;});
    check(session.state() == ConnectionState::Starting && proxyButton.isHidden() && proxy->checks == 0,
        "connect button waits for actual ready before applying automatic proxy");
    proxyButton.click();
    check(proxy->checks == 0, "early proxy requests cannot change system state");
    emit engine->connectionEstablished();
    until([&] { return systemProxy.isEnabled(); });
    check(proxy->applied == 1 && !proxyButton.isHidden(), "ready enables the configured automatic proxy once");
    systemProxy.disable();
    until([&] { return !systemProxy.isBusy(); });
    session.stop();
    emit engine->finished(ConnectionError::NONE);
    proxy->block = true;
    connectButton.click();
    until([&] {return session.state()==ConnectionState::Starting;});
    emit engine->connectionEstablished();
    check(proxy->entered.tryAcquire(1, 1000), "conflict check is asynchronous");
    session.stop();
    proxy->proceed.release();
    until([&] { return !systemProxy.isBusy(); });
    check(proxy->applied == 1, "late conflict result cannot apply a proxy to a stopping connection");
    emit engine->finished(ConnectionError::NONE);
    proxy->block = false;
    proxy->checkResult.result = {PlatformOperationResult::Status::PermissionDenied, "fixture query denial"};
    bool shown = false;
    QTimer dismiss;
    QObject::connect(&dismiss, &QTimer::timeout, [&] {
        for (auto *widget : QApplication::topLevelWidgets()) {
            if (auto *message = qobject_cast<QMessageBox *>(widget)) {
                check(message->text().contains("权限被拒绝"), "UI displays structured query failure");
                shown = true; message->accept();
            }
        }
    });
    dismiss.start(1);
    connectButton.click(); until([&] {return session.state()==ConnectionState::Starting;}); emit engine->connectionEstablished();
    until([&] { return shown && !systemProxy.isBusy(); });
    check(proxy->applied == 1, "failed conflict query cannot write system proxy");
    dismiss.stop(); session.stop(); emit engine->finished(ConnectionError::NONE);
}
static void manualCredentialsAndLateResults() {
    QTemporaryDir folder;QSettings settings(folder.filePath("manual.ini"),QSettings::IniFormat);
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");settings.setValue("JustConnect/ServerPort",443);
    settings.setValue("JustConnect/AuthType","psw");settings.setValue("Credential/Username","alice");
    QWidget parent;QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);
    auto *engine=new QueryEngine;ConnectionSession session(engine);SystemProxySession proxy(std::make_unique<ProxyBackend>());
    AuthDialogCoordinator dialogs(&parent);ApplicationLogger logger;QString logs;
    QObject::connect(&logger,&ApplicationLogger::entryAdded,[&](const QString &entry){logs+=entry;});
    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,&dialogs,&logger,
        &access,[&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},
        [](const QString &,const QString &,QSystemTrayIcon::MessageIcon){});
    auto login=[&](bool save,const QString &name) {
        connectButton.click();until([&]{
            for (auto *dialog:parent.findChildren<QDialog *>())
                if (dialog->isVisible() && dialog->findChild<QLineEdit *>("usernameLineEdit")) return true;
            return false;
        });
        auto *dialog=challenge(parent);dialog->findChild<QLineEdit *>("usernameLineEdit")->setText(name);
        dialog->findChild<QLineEdit *>("passwordLineEdit")->setText("manual-secret");
        dialog->findChild<QCheckBox *>("saveLoginDetailCheckBox")->setChecked(save);
        dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();
        until([&]{return session.state()==ConnectionState::Starting;});
    };
    auto finish=[&]{session.stop();emit engine->finished(ConnectionError::NONE);};
    login(false,"temporary");
    check(engine->profile.credentials.username=="temporary" && engine->profile.credentials.password=="manual-secret"
        && settings.value("Credential/Username")=="alice" && store->values.isEmpty(),"unchecked remember uses memory only");finish();
    login(true,"remembered");
    ConnectionCredentials loaded;ProfileCredentials vault(*store);const auto source=CredentialAccess::source(settings,{});
    check(settings.value("Credential/Username")=="remembered" && vault.load(source.scope,source.profile,loaded).succeeded()
        && loaded.password=="manual-secret" && !settings.contains("Credential/Password"),"checked remember stores account and native credentials without plaintext fallback");finish();
    int warnings=0;QTimer dismiss;
    QStringList expectedWarnings{
        "系统凭据存储权限被拒绝，请检查授权。\n本次仍可手动登录。",
        "系统凭据存储权限被拒绝，请检查授权。\n本次仍可手动登录。"
    };
    QObject::connect(&dismiss,&QTimer::timeout,[&] {
        for (auto *widget:QApplication::topLevelWidgets()) if (auto *message=qobject_cast<QMessageBox *>(widget);message && message->isVisible()) {
            // macOS ignores QMessageBox titles; assert the actual warning and available action.
            check(warnings<expectedWarnings.size() && message->text()==expectedWarnings.at(warnings)
                && message->icon()==QMessageBox::Warning && message->standardButtons()==QMessageBox::Ok,
                "only the expected native failure and manual-login action are shown");
            ++warnings;message->button(QMessageBox::Ok)->click();
        }
    });dismiss.start(1);store->failure=CredentialStatus::PermissionDenied;
    login(true,"unsaved");
    check(warnings==2 && engine->profile.credentials.username=="unsaved" && engine->profile.credentials.password=="manual-secret"
        && settings.value("Credential/Username")=="remembered" && !settings.contains("Credential/Password"),"native read/save failure still permits manual login and preserves public account binding");
    finish();dismiss.stop();store->failure=CredentialStatus::Success;
    QSemaphore entered,resume;store->beforeRead=[&]{entered.release();check(resume.tryAcquire(1,5000),"release blocked UI native read");};
    const auto starts=engine->starts;connectButton.click();check(entered.tryAcquire(1,1000),"pending UI native read");
    controller.cancelPendingCredentials();resume.release();until([&]{return !access.isBusy(settings.fileName());});
    check(engine->starts==starts && connectButton.text()=="连接服务器","cancelled read cannot start a late connection");
    connectButton.click();check(entered.tryAcquire(1,1000),"fresh pending native read");
    settings.setValue("JustConnect/TLSVerify",false);settings.setValue("JustConnect/TLSCAPEM","new policy");settings.sync();resume.release();
    until([&]{return session.state()==ConnectionState::Starting;});
    check(!engine->profile.tls.verify && engine->profile.tls.caPem=="new policy","connection reads current public TLS policy after native I/O");finish();
    connectButton.click();check(entered.tryAcquire(1,1000),"account switch while loading");
    settings.setValue("Credential/Username","bob");settings.sync();resume.release();until([&]{return !access.isBusy(settings.fileName());});
    check(engine->starts==starts+1 && !session.isActive(),"late account read does not start or deliver old account secrets");
    store->beforeRead={};
    settings.remove("JustConnect/TLSCAPEM");settings.setValue(ProfileCredentials::ScopeSetting,"invalid-existing-namespace");settings.sync();
    warnings=0;expectedWarnings={"配置或凭据已变化，请重新打开设置或重试。\n本次仍可手动登录。"};
    dismiss.start(1);login(false,"manual-without-storage");
    check(engine->profile.credentials.username=="manual-without-storage" && settings.value(ProfileCredentials::ScopeSetting)=="invalid-existing-namespace"
        && !settings.contains("Credential/Password"),"invalid storage namespace still permits explicit manual login without overwriting the namespace");
    finish();dismiss.stop();
    settings.setValue(ProfileCredentials::ScopeSetting,source.scope);settings.setValue("Credential/Username","remembered");settings.sync();
    auto totpOnly=source.profile;totpOnly.credentials.password.clear();totpOnly.credentials.totpSecret="JBSWY3DPEHPK3PXP";
    check(vault.save(source.scope,totpOnly).succeeded(),"native TOTP without a password");
    connectButton.click();until([&]{
        for (auto *dialog:parent.findChildren<QDialog *>())
            if (dialog->isVisible() && dialog->findChild<QLineEdit *>("usernameLineEdit")) return true;
        return false;
    });
    settings.setValue(ProfileCredentials::ScopeSetting,QUuid::createUuid().toString(QUuid::WithoutBraces));settings.sync();
    auto *dialog=challenge(parent);dialog->findChild<QLineEdit *>("passwordLineEdit")->setText("manual-secret");
    dialog->findChild<QCheckBox *>("saveLoginDetailCheckBox")->setChecked(false);
    dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();
    until([&]{return session.state()==ConnectionState::Starting;});
    check(engine->profile.credentials.totpSecret.isEmpty() && engine->profile.credentials.password=="manual-secret",
        "explicit manual login does not reuse native TOTP after the storage namespace changes");finish();
    check(vault.load(source.scope,totpOnly,loaded).succeeded() && loaded.totpSecret=="JBSWY3DPEHPK3PXP","manual input never deletes another namespace's native credentials");
    check(!logs.contains("manual-secret") && !logs.contains("fixture-password") && !logs.contains("JBSWY3DPEHPK3PXP"),"credential values never appear in UI logs");
}
static void browserCookiesStayInLoginDialog() {
    QList<bool> cookies;
    QTcpServer server;
    check(server.listen(QHostAddress::LocalHost),"isolated SSO cookie server");
    QObject::connect(&server,&QTcpServer::newConnection,&server,[&] {
        while (auto *socket=server.nextPendingConnection()) {
            QObject::connect(socket,&QTcpSocket::readyRead,&server,[socket,&cookies] {
                if (socket->property("handled").toBool()) return;
                const auto request=socket->property("request").toByteArray()+socket->readAll();
                socket->setProperty("request",request);
                if (!request.contains("\r\n\r\n")) return;
                socket->setProperty("handled",true);
                const auto path=request.split(' ').value(1);
                if (path=="/echo") {
                    bool present=false;
                    for (const auto &line:request.split('\n'))
                        if (line.toLower().startsWith("cookie:") && line.contains("jc_scope=first")) present=true;
                    cookies.append(present);
                }
                const QByteArray body="<html><body>fixture</body></html>";
                QByteArray response="HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nCache-Control: no-store\r\n";
                if (path=="/first") response+="Set-Cookie: jc_scope=first; Path=/; SameSite=Lax\r\n";
                response+="Content-Length: "+QByteArray::number(body.size())+"\r\n\r\n"+body;
                socket->write(response);socket->disconnectFromHost();
            });
            QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
        }
    });
    const auto base="http://127.0.0.1:"+QString::number(server.serverPort());
    const auto visit=[&](SsoLoginWebView *dialog,const QString &path) {
        auto *view=dialog->findChild<QWebEngineView *>();
        bool done=false,okay=false;
        const auto connection=QObject::connect(view,&QWebEngineView::loadFinished,view,[&](bool success){okay=success;done=true;});
        dialog->setInitialUrl(QUrl(base+path));until([&]{return done;});QObject::disconnect(connection);
        check(okay,"actual SSO page loads from controlled HTTP server");
    };
    auto *first=new SsoLoginWebView(nullptr,QUrl(base+"/passport/v1/auth/cas"));first->show();visit(first,"/first");visit(first,"/echo");
    check(cookies.size()==1 && cookies[0],"cookie works within the current login dialog");
    auto *second=new SsoLoginWebView(nullptr,QUrl(base+"/passport/v1/auth/cas"));second->show();visit(second,"/echo");
    check(cookies.size()==2 && !cookies[1],"another SSO dialog cannot reuse the first login's cookie");
    check(first->findChild<QWebEngineView *>()->page()->profile()->isOffTheRecord()
        && second->findChild<QWebEngineView *>()->page()->profile()->isOffTheRecord(),"login browser data remains in memory");
    delete second;delete first;
}

static void browserValidatesCallbackNavigation() {
    ApplicationLogger logger;QString logs;
    QObject::connect(&logger,&ApplicationLogger::entryAdded,[&](const QString &entry){logs+=entry;});
    QTcpServer server;check(server.listen(QHostAddress::LocalHost),"isolated SSO callback server");
    const auto base="http://127.0.0.1:"+QString::number(server.serverPort());int callbackRequests=0;
    QObject::connect(&server,&QTcpServer::newConnection,&server,[&] {
        while (auto *socket=server.nextPendingConnection()) {
            QObject::connect(socket,&QTcpSocket::readyRead,&server,[&,socket] {
                if (socket->property("handled").toBool()) return;
                const auto request=socket->property("request").toByteArray()+socket->readAll();socket->setProperty("request",request);
                if (!request.contains("\r\n\r\n")) return;
                socket->setProperty("handled",true);const auto path=request.split(' ').value(1);
                if (path.startsWith("/passport/v1/auth/")) ++callbackRequests;
                QByteArray response;
                if (path=="/redirect-unrelated" || path=="/redirect-oauth") {
                    const auto target=path=="/redirect-unrelated" ? "/unrelated?code=fixture" : "/passport/v1/auth/httpsOauth2?code=fixture";
                    response="HTTP/1.1 302 Found\r\nLocation: "+base.toUtf8()+target+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                } else {
                    const QByteArray body=path=="/frame" ? "<html><body><script>window.fixtureConsole=true;console.error('private-console-token');</script><iframe srcdoc='<p>local frame</p>'></iframe><iframe src='/passport/v1/auth/httpsOauth2?code=frame'></iframe></body></html>" : "<html><body>fixture</body></html>";
                    response="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: "+QByteArray::number(body.size())+"\r\n\r\n"+body;
                }
                socket->write(response);socket->disconnectFromHost();
            });QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
        }
    });
    auto *dialog=new SsoLoginWebView(nullptr,QUrl(base+"/passport/v1/auth/httpsOauth2"));dialog->setAttribute(Qt::WA_DeleteOnClose,false);dialog->show();
    auto *view=dialog->findChild<QWebEngineView *>();int responses=0;QString callback;
    QObject::connect(dialog,&SsoLoginWebView::loginCompleted,[&](const QString &value){++responses;callback=value;});
    auto visit=[&](const QString &path) {
        bool done=false;const auto connection=QObject::connect(view,&QWebEngineView::loadFinished,[&](bool){done=true;});
        dialog->setInitialUrl(QUrl(base+path));until([&]{return done || responses>0;});QObject::disconnect(connection);
    };
    visit("/redirect-unrelated");check(responses==0 && dialog->isVisible() && view->url().path()=="/unrelated","a same-origin redirect to another path cannot complete SSO");
    visit("/frame");check(responses==0 && dialog->isVisible() && callbackRequests==0,"iframe callbacks neither complete SSO nor consume the callback in the browser");
    bool localFrame=false;
    view->page()->runJavaScript("window.fixtureConsole===true && document.querySelector('iframe').contentDocument.body.textContent==='local frame'",[&](const QVariant &value){localFrame=value.toBool();});
    until([&]{return localFrame;});
    check(!logs.contains("private-console-token"),"identity provider console output cannot enter application logs");
    auto *warning=dialog->findChild<QLabel *>("navigationWarningLabel");
    for (const auto &path:QStringList{"/passport/v1/auth/httpsOauth2?code=a&code=b","/passport/v1/auth/httpsOauth2?code=fixture#fragment"}) {
        visit(path);check(responses==0 && warning->isVisible() && callbackRequests==0,"ambiguous, fragment or other-method callbacks remain rejected");
    }
    dialog->setInitialUrl(QUrl(base+"/passport/v1/auth/cas?ticket=wrong-kind"));
    check(responses==0 && warning->isVisible() && callbackRequests==0,"another authentication method is rejected before loading");
    const auto current=view->url();
    for (const auto &url:QStringList{"file:///etc/hosts","javascript:alert(1)","data:text/html,fixture","http://127.0.0.1:1/other","https://other.example.invalid/passport/v1/auth/httpsOauth2?code=fixture"}) {
        dialog->setInitialUrl(QUrl(url));QApplication::processEvents();
        check(warning->isVisible() && view->url()==current && responses==0,"unsafe initial navigation does not replace the login page");
    }
    visit("/redirect-oauth");check(responses==1 && callback==base+"/passport/v1/auth/httpsOauth2?code=fixture" && callbackRequests==0,"valid OAuth redirect is delivered once and intercepted before HTTP submission");delete dialog;
    dialog=new SsoLoginWebView(nullptr,QUrl(base+"/passport/v1/auth/cas"));dialog->setAttribute(Qt::WA_DeleteOnClose,false);dialog->show();view=dialog->findChild<QWebEngineView *>();responses=0;
    QObject::connect(dialog,&SsoLoginWebView::loginCompleted,[&](const QString &value){++responses;callback=value;});
    auto *address=dialog->findChild<QLineEdit *>("addressLineEdit");address->setText(base+"/passport/v1/auth/cas?ticket=fixture");
    check(QMetaObject::invokeMethod(address,"returnPressed"),"submit a main-frame callback from the address bar");until([&]{return responses==1;});
    check(responses==1 && callback==base+"/passport/v1/auth/cas?ticket=fixture" && callbackRequests==0,"CAS uses its own exact callback path and ticket");delete dialog;
}

static void uiContracts() {
    QWidget parent;
    AuthDialogCoordinator dialogs(&parent);
    QJsonObject submitted;
    int responses = 0;
    QObject::connect(&dialogs, &AuthDialogCoordinator::responseSubmitted, [&](const QJsonObject &response) {
        submitted = response; ++responses;
    });
    for (const QString &kind : {"sms", "totp", "radius"}) {
        QJsonObject request{{"schema_version", 1}, {"generation", "9007199254740993"}, {"request_id", "17"},
            {"challenge", QJsonObject{{"kind", kind}, {"can_skip_secondary_auth", kind != "totp"}}}};
        dialogs.requestAuthentication(request, QUrl("https://vpn.example.invalid"));
        auto *skip = challenge(parent)->findChild<QCheckBox *>("skipSecondaryAuthCheckBox");
        skip->setChecked(true);
        enterCode(parent, "验证码-$123");
        check(submitted["generation"] == request["generation"] && submitted["request_id"] == "17"
            && submitted["code"] == "验证码-$123" && submitted["skip_secondary_auth"].toBool() == (kind != "totp"),
            "Unicode code, capability and full-width identity reach response unchanged");
        const int before = responses;
        dialogs.requestAuthentication(request, {});
        challenge(parent)->reject();
        check(responses == before + 1 && submitted["action"] == "cancel" && !submitted.contains("code"),
            "cancel is an identified response without placeholder credentials");
        dialogs.requestAuthentication(request, {});
        dialogs.closeAuthentication();
        check(responses == before + 1, "programmatic invalidation does not send a new cancellation");
    }
    for (const QString &kind : {"cas", "oauth2"}) {
        const QJsonObject request{{"schema_version", 1}, {"generation", "2"}, {"request_id", "4"},
            {"challenge", QJsonObject{{"kind", kind}, {"login_url", "https://idp.example.invalid/login"}}}};
        dialogs.requestAuthentication(request, QUrl("https://vpn.example.invalid"));
        auto *web = qobject_cast<SsoLoginWebView *>(challenge(parent));
        check(web != nullptr, "external login uses the challenge URL");
        const auto callback=kind=="cas" ? "https://vpn.example.invalid/passport/v1/auth/cas?ticket=private-callback"
            : "https://vpn.example.invalid/passport/v1/auth/httpsOauth2?code=private-callback";
        emit web->loginCompleted(callback);
        web->accept();
        check(submitted["callback_url"] == callback
            && submitted["request_id"] == "4", "external callback retains request identity");
        const int before = responses;
        dialogs.requestAuthentication(request, {});
        challenge(parent)->close();
        check(responses == before + 1 && submitted["action"] == "cancel", "closing external login cancels once");
    }
    auto *fake = new QueryEngine;
    auto *query = new AuthInfoWindow(&parent, fake);
    ConnectionProfile queryProfile; queryProfile.endpoint.server="vpn.example.invalid"; queryProfile.endpoint.port=8443;
    queryProfile.credentials.password="must-not-be-queried"; queryProfile.tls={false,"query CA"};
    query->fetchAuthInfo(queryProfile);
    check(fake->operation == CoreEngine::Operation::AuthMethods && fake->profile.endpoint.port == 8443 && fake->profile.credentials.password.isEmpty() && !fake->profile.tls.verify && fake->profile.tls.caPem=="query CA",
        "query uses the engine port and configured server");
    emit fake->authMethodsReady({QJsonObject{{"type", "auth/cas"}, {"domain", "campus"}, {"name", "校园登录"}, {"login_url", "https://vpn.example.invalid/login"}}});
    auto *list = query->findChild<QListWidget *>();
    check(list->count() == 0, "query results are buffered until cleanup succeeds");
    bool selected = false;
    QObject::connect(query, &AuthInfoWindow::finishAuthInfo, [&](const QJsonObject &method) {
        selected = method["type"] == "auth/cas" && method["domain"] == "campus" && method["login_url"] == "https://vpn.example.invalid/login";
    });
    auto *ok = query->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok);
    check(!ok->isEnabled(), "method selection waits for query cleanup before releasing the global slot");
    emit fake->finished(ConnectionError::NONE);
    check(list->count()==1,"successful query delivers its methods");
    list->setCurrentRow(0);
    check(ok->isEnabled(), "completed query can be selected");
    query->accept();
    check(selected, "selection preserves all method fields");
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    auto *fudanEngine = new QueryEngine;
    auto *fudan = new AuthInfoWindow(&parent,fudanEngine);
    queryProfile.endpoint.server="configured.example.invalid"; queryProfile.endpoint.port=443;
    fudan->fetchAuthInfo(queryProfile,true);
    emit fudanEngine->authMethodsReady({
        QJsonObject{{"type","auth/psw"},{"name","Password"}},
        QJsonObject{{"type","auth/httpsOauth2"},{"name","Other OAuth2"},{"domain","other"}},
        QJsonObject{{"type","auth/httpsOauth2"},{"name","Fudan UIS"},{"auth_id","selected-opaque-id"},{"sub_type","https"},{"domain","returned-domain"},{"login_url","https://returned.example.invalid/uis"}}
    });
    check(fudan->findChild<QListWidget *>()->count()==0,"preferred query also waits for terminal cleanup");
    emit fudanEngine->finished(ConnectionError::NONE);
    auto *preferred=fudan->findChild<QListWidget *>()->currentItem();
    const auto choice=preferred ? preferred->data(Qt::UserRole).toJsonObject() : QJsonObject{};
    check(choice["domain"]=="returned-domain" && choice["login_url"]=="https://returned.example.invalid/uis"
        && choice["auth_id"]=="selected-opaque-id" && choice["sub_type"]=="https","Fudan selection retains complete returned identity");
    fudan->reject(); QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    auto *cancelEngine=new QueryEngine;
    auto *cancelled=new AuthInfoWindow(&parent,cancelEngine);
    cancelled->fetchAuthInfo(queryProfile); cancelled->reject();
    emit cancelEngine->authMethodsReady({QJsonObject{{"type","auth/psw"},{"domain","late"}}});
    emit cancelEngine->finished(ConnectionError::NONE);
    check(cancelled->findChild<QListWidget *>()->count()==0,"closed query rejects late results");
    QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    auto *failedEngine=new QueryEngine;
    auto *failed=new AuthInfoWindow(&parent,failedEngine);
    failed->fetchAuthInfo(queryProfile);
    emit failedEngine->authMethodsReady({QJsonObject{{"type","auth/psw"}}});
    emit failedEngine->finished(ConnectionError::CLIENT_FAILED);
    check(failed->findChild<QListWidget *>()->count()==0 && !failed->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->isEnabled(),"failed cleanup discards partial query results");
    failed->reject(); QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);

}
static void browserTlsPolicy(const ConnectionProfile &gatewayProfile) {
    QUrl target;target.setScheme("https");target.setHost(gatewayProfile.endpoint.server);target.setPort(gatewayProfile.endpoint.port);target.setPath("/browser");
    QString foreignUrl;
    for (const auto &policy:QList<TlsOptions>{{},{true,gatewayProfile.tls.caPem},{},{false,{}}}) {
        QWidget parent;auto *engine=new QueryEngine;ConnectionSession session(engine);AuthDialogCoordinator dialogs(&parent);
        QObject::connect(&session,&ConnectionSession::authenticationRequired,&dialogs,&AuthDialogCoordinator::requestAuthentication);
        auto profile=gatewayProfile;profile.tls=policy;check(session.start(profile,{}),"start immutable browser TLS policy context");profile.tls={};
        auto loginTarget=target;if(!policy.verify)loginTarget.setQuery("scope=unsafe");
        const QJsonObject request{{"schema_version",1},{"generation","1"},{"request_id","1"},
            {"challenge",QJsonObject{{"kind","oauth2"},{"login_url",loginTarget.toString()}}}};
        emit engine->authenticationRequired(request);
        auto *dialog=qobject_cast<SsoLoginWebView *>(challenge(parent));check(dialog!=nullptr,"SSO uses the active session browser");
        auto *view=dialog->findChild<QWebEngineView *>();bool done=false,okay=false;
        auto connection=QObject::connect(view,&QWebEngineView::loadFinished,[&](bool success){done=true;okay=success;});
        until([&]{return done;});QObject::disconnect(connection);
        const bool trusted=!policy.verify || !policy.caPem.isEmpty();
        check(okay==trusted,"browser honors the active session CA and verification policy without changing another profile");
        check(view->page()->profile()->isOffTheRecord(),"custom browser trust keeps all authentication data in memory");
        if (okay) {
            bool content=false;
            view->page()->runJavaScript("document.getElementById('fixture').textContent==='browser TLS fixture' && getComputedStyle(document.getElementById('fixture')).getPropertyValue('--scope-proof').trim()==='allowed'",[&](const QVariant &value){content=value.toBool();});until([&]{return content;});
            foreignUrl.clear();view->page()->runJavaScript("document.getElementById('otherOrigin').href",[&](const QVariant &value){foreignUrl=value.toString();});until([&]{return !foreignUrl.isEmpty();});
        }
        if (!policy.verify) {
            check(!foreignUrl.isEmpty() && QUrl(foreignUrl).port()!=target.port(),"different browser origin supplied by the TLS fixture");
            auto otherHost=QUrl(foreignUrl);otherHost.setHost("localhost");
            for (const auto &foreign:{QUrl(foreignUrl),otherHost}) {
                done=false;okay=true;connection=QObject::connect(view,&QWebEngineView::loadFinished,[&](bool success){done=true;okay=success;});
                view->load(foreign);until([&]{return done;});QObject::disconnect(connection);
                check(!okay,"an explicit gateway TLS bypass does not apply to another port or host");
            }
        }
        dialogs.closeAuthentication();session.stop();emit engine->finished(ConnectionError::NONE);QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    }
    std::cout<<"PASS: browser TLS policy, isolated trust and resource origin checks\n";
}

static void gateway(const QJsonObject &config) {
    QWidget parent;
    AuthDialogCoordinator dialogs(&parent);
    auto *engine = new EmbeddedCoreEngine;
    ConnectionSession session(engine);
    ConnectionProfile p;
    const auto server = config["server"].toObject();
    const auto auth = config["auth"].toObject();
    p.tls.caPem=config["tls"].toObject()["ca_pem"].toString();
    const auto listeners = config["listeners"].toObject();
    p.endpoint.server = server["host"].toString();
    p.endpoint.port = server["port"].toInt();
    p.endpoint.authType = auth["method"].toString().mid(QString("auth/").size());
    p.endpoint.phone = auth["phone"].toString();
    p.endpoint.loginDomain = auth["domain"].toString();
    p.proxy.socksBind = listeners["socks"].toString();
    p.proxy.httpBind = listeners["http"].toString();
    auto *untrustedEngine=new EmbeddedCoreEngine;
    auto *untrustedQuery=new AuthInfoWindow(&parent,untrustedEngine);
    bool trustFailure=false;
    QObject::connect(untrustedEngine,&CoreEngine::finished,[&](ConnectionError error){trustFailure=error==ConnectionError::TLS_TRUST;});
    auto untrustedProfile=p; untrustedProfile.tls.caPem.clear();
    untrustedQuery->fetchAuthInfo(untrustedProfile);
    until([&]{return trustFailure;});
    check(untrustedQuery->findChild<QLabel *>("label")->text().contains("证书")
        && untrustedQuery->findChild<QListWidget *>()->count()==0,"real query reports certificate failure without delivering methods");
    untrustedQuery->close(); QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    auto *queryWindow = new AuthInfoWindow(&parent);
    bool selected = false;
    QObject::connect(queryWindow, &AuthInfoWindow::finishAuthInfo,
        [&](const QJsonObject &method) {
            p.endpoint.authType = method["type"].toString().mid(QString("auth/").size());
            p.endpoint.loginDomain = method["domain"].toString();
            p.endpoint.authId=method["auth_id"].toString(); p.endpoint.authSubType=method["sub_type"].toString();
            selected = method["type"] == "auth/smsCheckCode" && method["domain"] == "fixture"
                && p.endpoint.authId=="fixture-primary" && p.endpoint.authSubType=="sms";
        });
    queryWindow->fetchAuthInfo(p);
    queryWindow->show();
    auto *methodsList = queryWindow->findChild<QListWidget *>();
    until([&] { return methodsList->count() != 0; });
    methodsList->setCurrentRow(0);
    auto *selectMethod = queryWindow->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok);
    until([&] { return selectMethod->isEnabled(); });
    selectMethod->click();
    check(selected, "actual query selection supplies authentication settings");
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    int responses = 0, completed = 0, ticks = 0;
    QObject::connect(&session, &ConnectionSession::authenticationRequired, &dialogs,
        &AuthDialogCoordinator::requestAuthentication);
    QObject::connect(&dialogs, &AuthDialogCoordinator::responseSubmitted, &session, [&](const QJsonObject &response) {
        ++responses; session.submitResponse(response);
    });
    QObject::connect(&session, &ConnectionSession::finished, [&](ConnectionError error) {
        check(error == ConnectionError::NONE, "Qt protocol operation succeeds"); ++completed;
    });
    QObject::connect(&session, &ConnectionSession::stateChanged, &dialogs, [&](ConnectionState state) {
        if (state != ConnectionState::Starting) dialogs.closeAuthentication();
    });
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; });
    heartbeat.start(1);
    check(session.start(p, {}), "Qt connection start");
    until([&] { return parent.findChild<QLineEdit *>("authCodeEdit") != nullptr; });
    until([&] { return ticks > 5; });
    check(session.state() == ConnectionState::Starting, "authentication wait leaves GUI responsive");
    enterCode(parent, "fixture-code");
    until([&] { return session.state() == ConnectionState::Running; });
    check(responses == 1, "actual UI code reaches production protocol once");
    ProxyCheck::exercise(listeners, [&] {
        session.stop();
        until([&] { return completed == 1; });
    });
    bool methods = false, queryDone = false;
    QObject::connect(engine, &CoreEngine::authMethodsReady, [&](const QJsonArray &list) { methods = !list.isEmpty(); });
    QObject::connect(engine, &CoreEngine::finished, [&](ConnectionError error) {
        check(error == ConnectionError::NONE, "query restart succeeds"); queryDone = true;
    });
    check(engine->start(p, CoreEngine::Operation::AuthMethods), "query restarts same engine after connection cleanup");
    until([&] { return methods && queryDone; });
    browserTlsPolicy(p);
    std::cout << "PASS: native protocol session through Qt UI, SMS, SOCKS/HTTP, active stop and query restart\n";
}
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    if (argc == 3 && QByteArray(argv[1]) == "--gateway") gateway(QJsonDocument::fromJson(argv[2]).object());
    else { browserCookiesStayInLoginDialog(); browserValidatesCallbackNavigation(); uiContracts(); proxyWaitsForReady(); manualCredentialsAndLateResults(); }
}
