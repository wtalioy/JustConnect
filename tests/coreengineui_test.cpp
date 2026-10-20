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
    settings.setValue("JustConnect/Protocol", "atrust");
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
    query->fetchAuthInfo("vpn.example.invalid", 8443);
    check(fake->operation == CoreEngine::Operation::AuthMethods && fake->profile.endpoint.port == 8443,
        "query uses the engine port and configured server");
    emit fake->authMethodsReady({QJsonObject{{"type", "auth/cas"}, {"domain", "campus"}, {"name", "校园登录"}, {"login_url", "https://vpn.example.invalid/login"}}});
    auto *list = query->findChild<QListWidget *>();
    check(list->count() == 1, "structured methods populate the list");
    bool selected = false;
    QObject::connect(query, &AuthInfoWindow::finishAuthInfo, [&](const QString &type, const QString &domain, const QString &url) {
        selected = type == "auth/cas" && domain == "campus" && url == "https://vpn.example.invalid/login";
    });
    list->setCurrentRow(0);
    auto *ok = query->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok);
    check(!ok->isEnabled(), "method selection waits for query cleanup before releasing the global slot");
    emit fake->finished(ConnectionError::NONE);
    check(ok->isEnabled(), "completed query can be selected");
    query->accept();
    check(selected && fake->stops == 1, "selection preserves all method fields and cancels the query lifetime");
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
}
static void gateway(const QJsonObject &config) {
    QWidget parent;
    AuthDialogCoordinator dialogs(&parent);
    auto *engine = new EmbeddedCoreEngine;
    ConnectionSession session(engine);
    ConnectionProfile p;
    const auto server = config["server"].toObject();
    const auto auth = config["auth"].toObject();
    const auto listeners = config["listeners"].toObject();
    p.endpoint.protocol = "atrust";
    p.endpoint.server = server["host"].toString();
    p.endpoint.port = server["port"].toInt();
    p.endpoint.authType = auth["method"].toString().mid(QString("auth/").size());
    p.endpoint.phone = auth["phone"].toString();
    p.endpoint.loginDomain = auth["domain"].toString();
    p.proxy.socksBind = listeners["socks"].toString();
    p.proxy.httpBind = listeners["http"].toString();
    auto *queryWindow = new AuthInfoWindow(&parent);
    bool selected = false;
    QObject::connect(queryWindow, &AuthInfoWindow::finishAuthInfo,
        [&](const QString &type, const QString &domain, const QString &) {
            p.endpoint.authType = type.mid(QString("auth/").size());
            p.endpoint.loginDomain = domain;
            selected = type == "auth/smsCheckCode" && domain == "fixture";
        });
    queryWindow->fetchAuthInfo(p.endpoint.server, p.endpoint.port);
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
    else { uiContracts(); proxyWaitsForReady(); }
}
