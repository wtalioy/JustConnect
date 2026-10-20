#include "application/connectionsession.h"
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
    int stops = 0;
    bool start(const ConnectionProfile &p, Operation op) override { profile = p; operation = op; return true; }
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
    ConnectionUiController controller(&parent, &connectButton, &proxyButton, &trayAction,
        &session, &systemProxy, &dialogs, &logger, [&] { return &settings; },
        [](const QString &, const QString &, QSystemTrayIcon::MessageIcon) {});
    connectButton.click();
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
    connectButton.click(); emit engine->connectionEstablished();
    until([&] { return shown && !systemProxy.isBusy(); });
    check(proxy->applied == 1, "failed conflict query cannot write system proxy");
    dismiss.stop(); session.stop(); emit engine->finished(ConnectionError::NONE);
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
    auto *first=new SsoLoginWebView;first->show();visit(first,"/first");visit(first,"/echo");
    check(cookies.size()==1 && cookies[0],"cookie works within the current login dialog");
    auto *second=new SsoLoginWebView;second->show();visit(second,"/echo");
    check(cookies.size()==2 && !cookies[1],"another SSO dialog cannot reuse the first login's cookie");
    check(first->findChild<QWebEngineView *>()->page()->profile()->isOffTheRecord()
        && second->findChild<QWebEngineView *>()->page()->profile()->isOffTheRecord(),"login browser data remains in memory");
    delete second;delete first;
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
            {"challenge", QJsonObject{{"kind", kind}, {"login_url", "http://127.0.0.1:1/login"}}}};
        dialogs.requestAuthentication(request, QUrl("https://vpn.example.invalid"));
        auto *web = qobject_cast<SsoLoginWebView *>(challenge(parent));
        check(web != nullptr, "external login uses the challenge URL");
        emit web->loginCompleted("https://vpn.example.invalid/callback?ticket=private-callback");
        web->accept();
        check(submitted["callback_url"] == "https://vpn.example.invalid/callback?ticket=private-callback"
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
    std::cout << "PASS: native protocol session through Qt UI, SMS, SOCKS/HTTP, active stop and query restart\n";
}
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    if (argc == 3 && QByteArray(argv[1]) == "--gateway") gateway(QJsonDocument::fromJson(argv[2]).object());
    else { browserCookiesStayInLoginDialog(); uiContracts(); proxyWaitsForReady(); }
}
