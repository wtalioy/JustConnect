#include "application/connectionsession.h"
#include "application/networkprotection.h"
#include "application/networkpolicysession.h"
#include "presentation/dialogs/networkpolicywindow.h"
#include <QTreeWidget>
#include "tests/credentialstorefixture.h"
#include "application/applicationlogger.h"
#include "application/defaultsettings.h"
#include "application/systemproxysession.h"
#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/dns/dnssnapshot.h"
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
#include <QFile>
#include <QSemaphore>
#include <QThreadPool>
#include <QTemporaryDir>
#include <QTimer>
#include <QtConcurrent>
#include <limits>
#include <QUuid>
#include <QTcpServer>
#include <QTcpSocket>
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineCookieStore>
#include <QWebEngineLoadingInfo>
#include <QNetworkCookie>
#include <atomic>

using ProxyCheck::check;
static std::optional<bool> noOfficialClient(){return false;}
template<class Predicate> static void waitUntil(const char *file, int line, Predicate done) {
    QElapsedTimer elapsed;
    elapsed.start();
    while (!done() && elapsed.elapsed() < 10000)
        QApplication::processEvents(QEventLoop::AllEvents, 10);
    if (!done()) {
        std::cerr << file << ':' << line << ": ";
        check(false, "Qt UI operation timed out");
    }
}
#define until(...) waitUntil(__FILE__, __LINE__, __VA_ARGS__)
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
    std::atomic<int> checks = 0, applied = 0, clears = 0;
    bool block = false,blockApply=false;
    SystemProxyCheck checkResult;
    PlatformOperationResult clearResult,applyResult;
    SystemProxyConfig checkedConfig,appliedConfig;
    QSemaphore entered, proceed,applyEntered,applyProceed;
    SystemProxyCheck check(const SystemProxyConfig &config) override {
        checkedConfig=config;++checks;
        if (block) { entered.release(); proceed.acquire(); }
        return checkResult;
    }
    PlatformOperationResult apply(const SystemProxyConfig &config) override {
        appliedConfig=config;++applied;
        if(blockApply){applyEntered.release();applyProceed.acquire();}
        return applyResult;
    }
    PlatformOperationResult clear() override { ++clears;return clearResult; }
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
    settings.setValue("JustConnect/HTTPPort",13081);settings.setValue("JustConnect/SOCKS5Port",13080);
    QWidget parent;
    QPushButton connectButton(&parent), proxyButton(&parent);
    QAction trayAction(&parent);
    auto *engine = new QueryEngine;
    ConnectionSession session(engine);
    auto backend = std::make_unique<ProxyBackend>();
    auto *proxy = backend.get();
    SystemProxySession systemProxy(std::move(backend));
    QObject::connect(&systemProxy,&SystemProxySession::operationFinished,&parent,[&](bool,const PlatformOperationResult &result) {
        if(result.succeeded())return;
        QMessageBox message(QMessageBox::Warning,"proxy failure","fixture failure",QMessageBox::Ok,&parent);
        QTimer::singleShot(0,&message,&QDialog::accept);message.exec();
    });
    AuthDialogCoordinator dialogs(&parent);
    ApplicationLogger logger;
    CredentialAccess credentials(std::make_unique<MemoryCredentialStore>());
    ConnectionUiController controller(&parent, &connectButton, &proxyButton, &trayAction,
        &session, &systemProxy, nullptr, &dialogs, &logger, &credentials, [&] { return &settings; },
        [&] {return CredentialAccess::source(settings,{});},
        [](const QString &, const QString &, QSystemTrayIcon::MessageIcon) {},nullptr,noOfficialClient);
    connectButton.click();
    until([&] {return session.state()==ConnectionState::Starting;});
    check(session.state() == ConnectionState::Starting && proxyButton.isHidden() && proxy->checks == 0,
        "connect button waits for actual ready before applying automatic proxy");
    proxyButton.click();
    check(proxy->checks == 0, "early proxy requests cannot change system state");
    settings.setValue("JustConnect/HTTPPort",23081);settings.setValue("JustConnect/SOCKS5Port",23080);
    emit engine->connectionEstablished();
    until([&] { return systemProxy.isEnabled(); });
    check(proxy->checkedConfig.httpPort==13081 && proxy->appliedConfig.httpPort==13081 && proxy->appliedConfig.socksPort==13080,
        "system proxy must use active listeners when the public configuration changes");
    check(proxy->applied == 1 && !proxyButton.isHidden(), "ready enables the configured automatic proxy once");
    proxy->clearResult={PlatformOperationResult::Status::PermissionDenied,"fixture restore denial",true};
    session.stop();emit engine->finished(ConnectionError::NONE);
    check(session.start(engine->profile,{}),"new session while original proxy restoration is pending");emit engine->connectionEstablished();
    until([&]{return !systemProxy.isBusy();});QApplication::processEvents();
    check(!systemProxy.isBusy() && proxy->clears==1 && systemProxy.needsCleanup(),
        "failed restoration retains ownership without an automatic retry loop");
    proxy->clearResult={};
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
    connectButton.click();until([&]{return session.state()==ConnectionState::Starting;});emit engine->connectionEstablished();
    check(proxy->entered.tryAcquire(1,1000),"second delayed conflict query");
    session.stop();emit engine->finished(ConnectionError::NONE);
    settings.setValue("JustConnect/HTTPPort",33081);settings.setValue("JustConnect/SOCKS5Port",33080);
    connectButton.click();until([&]{return session.state()==ConnectionState::Starting;});emit engine->connectionEstablished();
    const int oldChecks=proxy->checks;
    proxy->block=false;proxy->proceed.release();until([&]{return systemProxy.isEnabled() && !systemProxy.isBusy();});
    check(proxy->applied==2 && proxy->checks==oldChecks+1 && proxy->appliedConfig.httpPort==33081 && proxy->appliedConfig.socksPort==33080,
        "new running session uses a fresh conflict check and its own active listeners");
    systemProxy.disable();until([&]{return !systemProxy.isBusy();});
    session.stop();emit engine->finished(ConnectionError::NONE);
    settings.setValue("Common/AutoSetProxy",false);
    connectButton.click();until([&]{return session.state()==ConnectionState::Starting;});emit engine->connectionEstablished();
    proxy->checkResult.conflict=true;
    bool confirmed=false;QTimer confirm;
    QObject::connect(&confirm,&QTimer::timeout,[&]{
        for(auto *widget:QApplication::topLevelWidgets())if(auto *message=qobject_cast<QMessageBox *>(widget)) {
            if(!message->text().contains("当前已存在系统代理"))continue;
            confirm.stop();message->checkBox()->setChecked(true);
            session.stop();emit engine->finished(ConnectionError::NONE);
            check(session.start(engine->profile,{}),"another session starts while override confirmation is open");
            emit engine->connectionEstablished();
            confirmed=true;message->done(QMessageBox::Yes);
        }
    });
    confirm.start(1);proxyButton.click();until([&]{return confirmed && !systemProxy.isBusy();});
    check(proxy->applied==2 && !settings.value("Common/SuppressProxyOverrideWarning",false).toBool(),
        "late override confirmation cannot change another running session or its preferences");
    session.stop();emit engine->finished(ConnectionError::NONE);
    settings.setValue("Common/AutoSetProxy",true);proxy->checkResult.conflict=false;
    bool shown = false;
    QString expectedWarning="权限被拒绝";
    QTimer dismiss;
    QObject::connect(&dismiss, &QTimer::timeout, [&] {
        for (auto *widget : QApplication::topLevelWidgets()) {
            if (auto *message = qobject_cast<QMessageBox *>(widget)) {
                check(message->text().contains(expectedWarning), "UI displays the actionable proxy failure");
                shown = true; message->accept();
            }
        }
    });
    dismiss.start(1);
    for (bool changed : {false,true}) {
        shown=false;
        proxy->checkResult.result={PlatformOperationResult::Status::PermissionDenied,"fixture query denial",changed};
        connectButton.click(); until([&] {return session.state()==ConnectionState::Starting;}); emit engine->connectionEstablished();
        until([&] { return shown && !systemProxy.isBusy(); });
        check(proxy->applied==2 && systemProxy.needsCleanup()==changed,
              "failed conflict query must show its error, retain recovery responsibility and prevent a new apply");
        if (changed) {systemProxy.disable();until([&]{return !systemProxy.isBusy();});}
        session.stop();emit engine->finished(ConnectionError::NONE);
    }
    settings.setValue("JustConnect/HTTPPort",0);shown=false;expectedWarning="同时启用";
    const int previousChecks=proxy->checks;
    connectButton.click();until([&]{return session.state()==ConnectionState::Starting;});emit engine->connectionEstablished();
    until([&]{return shown;});
    check(proxy->checks==previousChecks && proxy->applied==2 && engine->profile.proxy.httpBind.isEmpty(),
        "disabled active listener blocks system proxy changes before the backend query");
    dismiss.stop(); session.stop(); emit engine->finished(ConnectionError::NONE);
    settings.setValue("JustConnect/HTTPPort",44081);proxy->checkResult={};proxy->blockApply=true;
    for(bool partial:{false,true}) {
        proxy->applyResult=partial?PlatformOperationResult{PlatformOperationResult::Status::PermissionDenied,"partial native apply",true}:PlatformOperationResult{};
        connectButton.click();until([&]{return session.state()==ConnectionState::Starting;});emit engine->connectionEstablished();
        until([&]{return proxy->applyEntered.available()>0;});
        check(proxy->applyEntered.tryAcquire(),"proxy apply reached its controlled wait");
        const int priorClears=proxy->clears;
        session.stop();emit engine->finished(ConnectionError::NONE);
        check(systemProxy.isBusy() && proxy->clears==priorClears,"stop waits for the in-flight proxy mutation before restoration");
        proxy->applyProceed.release();until([&]{return !systemProxy.isBusy();});
        check(!systemProxy.needsCleanup() && proxy->clears==priorClears+1,
            "finished connection restores successful or partial in-flight proxy changes exactly once");
    }
    settings.setValue("Common/AutoSetProxy",false);settings.setValue("Common/AutoReconnect",true);
    int scheduled=0;
    const auto observer=QObject::connect(&session,&ConnectionSession::reconnectScheduled,&parent,[&](int delay){scheduled=delay;});
    for (const auto &[seconds,expected]:QList<QPair<int,int>>{{std::numeric_limits<int>::max(),30000},{3600,30000},{0,1000},{-1,1000}}) {
        settings.setValue("Common/ReconnectTime",seconds);scheduled=0;
        connectButton.click();until([&]{return session.state()==ConnectionState::Starting;});
        emit engine->finished(ConnectionError::NETWORK_FAILED);
        check(session.state()==ConnectionState::Reconnecting && scheduled==expected,
            "legacy or invalid seconds are bounded before millisecond conversion without overflow");
        session.stop();
    }
    QObject::disconnect(observer);
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
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,nullptr,&dialogs,&logger,
        &access,[&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},
        [](const QString &,const QString &,QSystemTrayIcon::MessageIcon){},nullptr,noOfficialClient);
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
    const auto startsBeforeMalformed=engine->starts;const auto nativeBeforeMalformed=store->values;
    const QByteArray malformed="[unclosed section\n";
    {QFile file(settings.fileName());check(file.open(QIODevice::Append) && file.write(malformed)==malformed.size(),"malformed active configuration");}
    warnings=0;expectedWarnings={"无法读取当前配置，请检查文件权限与内容后重新打开配置。","无法读取当前配置，请检查文件权限与内容后重新打开配置。"};
    dismiss.start(1);connectButton.click();connectButton.click();dismiss.stop();
    check(warnings==2 && engine->starts==startsBeforeMalformed && !session.isActive() && store->values==nativeBeforeMalformed,
        "repeated malformed configuration attempts cannot start authentication or change native credentials");
    check(!logs.contains("manual-secret") && !logs.contains("fixture-password") && !logs.contains("JBSWY3DPEHPK3PXP"),"credential values never appear in UI logs");
}
static void authenticationCacheLifecycle() {
    QTemporaryDir folder;QSettings settings(folder.filePath("cache.ini"),QSettings::IniFormat);
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");settings.setValue("JustConnect/ServerPort",443);
    settings.setValue("JustConnect/AuthType","psw");settings.setValue("Credential/Username","login-alias");
    settings.setValue(DefaultSettings::RememberAuthentication,true);settings.sync();
    QWidget parent;QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);
    auto *engine=new QueryEngine;ConnectionSession session(engine);SystemProxySession proxy(std::make_unique<ProxyBackend>());
    AuthDialogCoordinator dialogs(&parent);ApplicationLogger logger;QString logs;QStringList notices;
    QObject::connect(&logger,&ApplicationLogger::entryAdded,[&](const QString &entry){logs+=entry;});
    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,nullptr,&dialogs,&logger,
        &access,[&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},
        [&](const QString &title,const QString &body,QSystemTrayIcon::MessageIcon){notices.append(title+body);},nullptr,noOfficialClient);
    auto source=CredentialAccess::source(settings,{});ProfileCredentials vault(*store);
    auto totp=source.profile;totp.credentials.totpSecret="private-totp";
    check(vault.save(source.scope,totp).succeeded(),"cache fixture keeps TOTP without storing a password");
    AuthenticationCache cached{"canonical-account","private-cookie"};
    check(vault.saveAuthenticationCache(source.scope,source.profile,cached).succeeded(),"seed bound authentication");
    auto bob=source.profile;bob.credentials.username="bob";
    check(vault.saveAuthenticationCache(source.scope,bob,{"bob-account","bob-cookie"}).succeeded(),"seed other account cache");
    const auto ready=[&]{until([&]{return !access.isBusy(settings.fileName());});};
    const auto finish=[&]{session.stop();emit engine->finished(ConnectionError::NONE);};
    connectButton.click();until([&]{return engine->starts==1;});
    check(engine->profile.authenticationCache.data==cached.data && engine->profile.credentials.password.isEmpty()
        && engine->profile.credentials.totpSecret=="private-totp" && !parent.findChild<QLineEdit *>("usernameLineEdit"),
        "valid authentication is attempted before asking for a missing password");
    emit engine->authenticationCacheUpdated({cached.account,"refreshed-cookie"});ready();
    AuthenticationCache loaded;
    check(vault.loadAuthenticationCache(source.scope,source.profile,loaded).succeeded() && loaded.data=="refreshed-cookie","server refresh reaches the scoped native record");
    store->failure=CredentialStatus::Locked;
    emit engine->authenticationCacheUpdated({cached.account,"unsaved-refresh"});
    emit engine->authenticationCacheUpdated({cached.account,"another-unsaved-refresh"});ready();
    store->failure=CredentialStatus::Success;
    check(session.isActive() && notices.size()==1 && vault.loadAuthenticationCache(source.scope,source.profile,loaded).succeeded()
        && loaded.data=="refreshed-cookie","native save failure keeps the connection and previous record, with one warning");
    finish();
    connectButton.click();until([&]{return engine->starts==2;});
    check(engine->profile.authenticationCache.data=="refreshed-cookie","ordinary disconnect preserves and reloads saved authentication");
    emit engine->authenticationCacheInvalidated();emit engine->finished(ConnectionError::CREDENTIALS_REQUIRED);
    until([&]{auto *edit=parent.findChild<QLineEdit *>("usernameLineEdit");return edit && edit->isVisible();});
    auto *login=challenge(parent);login->findChild<QLineEdit *>("passwordLineEdit")->setText("manual-private-password");
    login->findChild<QCheckBox *>("saveLoginDetailCheckBox")->setChecked(false);
    login->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();
    until([&]{return engine->starts==3;});ready();
    check(engine->profile.authenticationCache.data.isEmpty() && engine->profile.credentials.password=="manual-private-password"
        && engine->profile.credentials.totpSecret=="private-totp" && vault.loadAuthenticationCache(source.scope,source.profile,loaded).status==CredentialStatus::NotFound,
        "definitive rejection clears old cache and asks for one necessary password while preserving scoped TOTP");
    emit engine->authenticationCacheUpdated({cached.account,"fresh-authentication"});ready();
    emit engine->connectionEstablished();
    bool confirmed=false;QTimer confirm;
    QObject::connect(&confirm,&QTimer::timeout,[&]{
        for(auto *widget:QApplication::topLevelWidgets()) if(auto *box=qobject_cast<QMessageBox *>(widget);box && box->isVisible()) {
            check(box->icon()==QMessageBox::Question && box->text().contains("login-alias")
                && box->defaultButton()==box->button(QMessageBox::No),"cache clear identifies the selected account and defaults to cancel");
            confirmed=true;box->button(QMessageBox::Yes)->click();
        }
    });confirm.start(1);controller.clearAuthenticationCache();confirm.stop();
    emit engine->authenticationCacheUpdated({cached.account,"late-authentication"});ready();
    ConnectionCredentials credentials;
    check(confirmed && vault.loadAuthenticationCache(source.scope,source.profile,loaded).status==CredentialStatus::NotFound
        && vault.loadAuthenticationCache(source.scope,bob,loaded).succeeded() && loaded.data=="bob-cookie"
        && vault.load(source.scope,source.profile,credentials).succeeded() && credentials.totpSecret=="private-totp" && credentials.password.isEmpty(),
        "explicit clear rejects late refresh while retaining other accounts and independent secrets");
    finish();
    auto password=source.profile;password.credentials.password="saved-private-password";
    check(vault.save(source.scope,password).succeeded() && vault.saveAuthenticationCache(source.scope,source.profile,cached).succeeded(),"seed opted-out account");
    settings.setValue(DefaultSettings::RememberAuthentication,false);settings.sync();
    connectButton.click();until([&]{return engine->starts==4;});
    emit engine->authenticationCacheUpdated({cached.account,"not-allowed"});ready();
    check(!engine->profile.behavior.rememberAuthentication && engine->profile.authenticationCache.data.isEmpty()
        && vault.loadAuthenticationCache(source.scope,source.profile,loaded).succeeded() && loaded.data==cached.data,
        "disabled consent neither restores nor updates existing authentication");finish();
    settings.setValue(DefaultSettings::RememberAuthentication,true);settings.setValue("JustConnect/AuthType","httpsOauth2");
    settings.setValue("Credential/Username","");settings.sync();
    connectButton.click();until([&]{return engine->starts==5;});
    bool deferredClear=false;QTimer bindingNotice;
    QObject::connect(&bindingNotice,&QTimer::timeout,[&]{
        for(auto *widget:QApplication::topLevelWidgets()) if(auto *box=qobject_cast<QMessageBox *>(widget);box && box->isVisible()) {
            check(box->icon()==QMessageBox::Information && box->text()=="请等待保存完成后再清除认证缓存。",
                "unfinished account binding reports clear as deferred");box->button(QMessageBox::Ok)->click();
        }
    });bindingNotice.start(1);
    const auto bindingObserver=QObject::connect(&access,&CredentialAccess::configurationSaved,[&](const QString &){
        check(controller.isConfigurationSaving(),"configuration remains busy until the initial SSO cache continuation finishes");
        controller.clearAuthenticationCache();deferredClear=true;
    });
    emit engine->authenticationCacheUpdated({"server-confirmed-user","private-sso-cookie"});
    until([&]{
        if (settings.value("Credential/Username")!="server-confirmed-user" || access.isBusy(settings.fileName())) return false;
        const auto current=CredentialAccess::source(settings,{});
        return vault.loadAuthenticationCache(current.scope,current.profile,loaded).succeeded();
    });
    QObject::disconnect(bindingObserver);bindingNotice.stop();
    check(!controller.isConfigurationSaving(),"completed SSO binding releases configuration operations");
    source=CredentialAccess::source(settings,{});
    check(deferredClear && vault.loadAuthenticationCache(source.scope,source.profile,loaded).succeeded() && loaded.account=="server-confirmed-user"
        && loaded.data=="private-sso-cookie","first SSO binds the server-confirmed public account before storing authentication");
    const auto noticesBeforeMismatch=notices.size();
    emit engine->authenticationCacheUpdated({"different-user","must-not-reassign"});ready();
    check(vault.loadAuthenticationCache(source.scope,source.profile,loaded).succeeded() && loaded.account=="server-confirmed-user"
        && loaded.data=="private-sso-cookie" && notices.size()==noticesBeforeMismatch+1,"different SSO account cannot replace the selected account's cache");finish();
    check(!logs.contains("private-cookie") && !logs.contains("manual-private-password") && !logs.contains("private-totp")
        && !logs.contains("private-sso-cookie"),"authentication cache and credentials do not enter application logs");
}

static void onlineExpiryOffersOneReauthentication() {
    QTemporaryDir folder;QSettings settings(folder.filePath("online-expiry.ini"),QSettings::IniFormat);
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");settings.setValue("JustConnect/ServerPort",443);
    settings.setValue("JustConnect/AuthType","psw");settings.setValue("Credential/Username","alice");
    settings.setValue(DefaultSettings::RememberAuthentication,true);settings.setValue("Common/AutoReconnect",true);settings.sync();
    class ReauthEngine final:public QueryEngine {
    public:
        int responses=0;
        void respond(const QJsonObject &response) override {
            check(response["code"]=="123456" && response["generation"]=="2","new MFA response belongs to the new session");
            ++responses;emit responseAccepted();emit connectionEstablished();
        }
    };
    QWidget parent;QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);
    auto *engine=new ReauthEngine;ConnectionSession session(engine);SystemProxySession proxy(std::make_unique<ProxyBackend>());
    AuthDialogCoordinator dialogs(&parent);ApplicationLogger logger;
    QObject::connect(&session,&ConnectionSession::authenticationRequired,&dialogs,&AuthDialogCoordinator::requestAuthentication);
    QObject::connect(&dialogs,&AuthDialogCoordinator::responseSubmitted,&session,&ConnectionSession::submitResponse);
    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    int notices=0,finishes=0;
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,nullptr,&dialogs,&logger,
        &access,[&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},
        [&](const QString &,const QString &,QSystemTrayIcon::MessageIcon){++notices;},nullptr,noOfficialClient);
    QObject::connect(&session,&ConnectionSession::finished,[&](ConnectionError){++finishes;});
    const auto source=CredentialAccess::source(settings,{});ProfileCredentials vault(*store);
    check(vault.saveAuthenticationCache(source.scope,source.profile,{"alice","expired-cookie"}).succeeded(),"seed online session authentication");
    connectButton.click();until([&]{return engine->starts==1;});emit engine->connectionEstablished();
    int errors=0;QTimer dismiss;
    QObject::connect(&dismiss,&QTimer::timeout,[&] {
        for (auto *widget:QApplication::topLevelWidgets()) if (auto *box=qobject_cast<QMessageBox *>(widget);box && box->isVisible()) {
            check(box->text().contains("重新认证"),"online expiry explains the manual reauthentication action");++errors;box->accept();
        }
    });dismiss.start(1);
    emit engine->authenticationCacheInvalidated();emit engine->finished(ConnectionError::SESSION_INVALID);
    emit engine->authenticationCacheInvalidated();emit engine->finished(ConnectionError::SESSION_INVALID);
    dismiss.stop();until([&]{return !access.isBusy();});
    AuthenticationCache cached;
    check(session.state()==ConnectionState::Failed && session.phase()==ConnectionPhase::ReauthenticationRequired
        && engine->starts==1 && engine->stops==0 && finishes==1 && errors==1 && notices==1
        && vault.loadAuthenticationCache(source.scope,source.profile,cached).status==CredentialStatus::NotFound,
        "online expiry completes once, clears authentication and never silently relogs in");
    connectButton.click();until([&]{auto *edit=parent.findChild<QLineEdit *>("usernameLineEdit");return edit && edit->isVisible();});
    auto *login=challenge(parent);login->findChild<QLineEdit *>("passwordLineEdit")->setText("manual-after-expiry");
    login->findChild<QCheckBox *>("saveLoginDetailCheckBox")->setChecked(false);
    login->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();until([&]{return engine->starts==2;});
    check(engine->profile.authenticationCache.data.isEmpty(),"manual reauthentication cannot restore the expired cache");
    emit engine->authenticationRequired({{"schema_version",1},{"generation","2"},{"request_id","2"},{"challenge",QJsonObject{{"kind","sms"}}}});
    enterCode(parent,"123456");
    check(engine->responses==1 && session.state()==ConnectionState::Running,"one manual MFA flow restores transport readiness");
    session.stop();emit engine->finished(ConnectionError::NONE);
}

static void officialClientWarningIsReadOnlyAndDropsCancelledResults() {
    QTemporaryDir folder;QSettings settings(folder.filePath("official-client.ini"),QSettings::IniFormat);
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");settings.setValue("JustConnect/AuthType","httpsOauth2");settings.sync();
    QWidget parent;QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);
    auto *engine=new QueryEngine;ConnectionSession session(engine);SystemProxySession proxy(std::make_unique<ProxyBackend>());
    AuthDialogCoordinator dialogs(&parent);ApplicationLogger logger;CredentialAccess access(std::make_unique<MemoryCredentialStore>());
    QSemaphore release;std::atomic<int> scans=0;int warnings=0;
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,nullptr,&dialogs,&logger,
        &access,[&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},
        [&](const QString &title,const QString &text,QSystemTrayIcon::MessageIcon icon){
            check(title.contains("aTrust") && text.contains("DNS") && text.contains("不会结束") && icon==QSystemTrayIcon::Warning,
                "official client warning explains a possible conflict without claiming an authenticated connection");++warnings;
        },nullptr,[&]() -> std::optional<bool>{++scans;release.acquire();return true;});
    struct FinishProbe{QSemaphore &release;~FinishProbe(){release.release(4);QThreadPool::globalInstance()->waitForDone(1000);}} finish{release};
    connectButton.click();until([&]{return scans==1;});until([&]{return engine->starts==1;});
    check(warnings==0,"slow advisory probe never blocks credentials or the core");
    connectButton.click();emit engine->finished(ConnectionError::NONE);release.release();
    check(QThreadPool::globalInstance()->waitForDone(1000),"cancelled advisory probe finishes");QApplication::processEvents();
    check(warnings==0 && engine->starts==1,"cancelled probe neither warns nor restarts a connection");
    release.release();connectButton.click();until([&]{return warnings==1 && engine->starts==2;});
    check(scans==2 && session.isActive() && engine->stops==1,"one warning per explicit attempt leaves connection and process control unchanged");
    session.stop();emit engine->finished(ConnectionError::NONE);
}

static void authenticationSurvivesTunnelFailure() {
    QTemporaryDir folder;QSettings settings(folder.filePath("failed-tunnel-cache.ini"),QSettings::IniFormat);
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");settings.setValue("JustConnect/ServerPort",443);
    settings.setValue("JustConnect/AuthType","httpsOauth2");settings.setValue(DefaultSettings::RememberAuthentication,true);settings.sync();
    QWidget parent;QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);
    auto *engine=new QueryEngine;ConnectionSession session(engine);SystemProxySession proxy(std::make_unique<ProxyBackend>());
    AuthDialogCoordinator dialogs(&parent);ApplicationLogger logger;
    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,nullptr,&dialogs,&logger,
        &access,[&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},
        [](const QString &,const QString &,QSystemTrayIcon::MessageIcon){},nullptr,noOfficialClient);
    connectButton.click();until([&]{return engine->starts==1;});
    bool errorShown=false;QTimer closeError;
    QObject::connect(&closeError,&QTimer::timeout,[&]{
        for(auto *widget:QApplication::topLevelWidgets()) if(auto *box=qobject_cast<QMessageBox *>(widget);box && box->isVisible()) {
            check(box->text().contains("服务器证书"),"tunnel certificate rejection remains visible");
            errorShown=true;box->accept();
        }
    });closeError.start(1);
    emit engine->authenticationCacheUpdated({"authenticated-user","private-before-tunnel"});
    emit engine->finished(ConnectionError::TLS_TRUST);closeError.stop();
    AuthenticationCache saved;ProfileCredentials vault(*store);
    until([&]{
        const auto source=CredentialAccess::source(settings,{});
        return !access.isBusy() && !controller.isConfigurationSaving() && vault.loadAuthenticationCache(source.scope,source.profile,saved).succeeded();
    });
    check(errorShown && saved.account=="authenticated-user" && saved.data=="private-before-tunnel",
        "terminal tunnel failure retains authorized first SSO account binding and native authentication");
    connectButton.click();until([&]{return engine->starts==2;});
    check(engine->profile.authenticationCache.account==saved.account && engine->profile.authenticationCache.data==saved.data,
        "retry restores the authenticated account instead of starting with an empty cache");
    emit engine->finished(ConnectionError::NONE);
}

static void quitWaitsForAuthenticationQueryWithoutBlockingTheGui() {
    QTemporaryDir folder;QSettings settings(folder.filePath("query-quit.ini"),QSettings::IniFormat);DefaultSettings::reset(settings);settings.sync();
    QWidget parent;QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);
    auto *engine=new QueryEngine;ConnectionSession session(engine);SystemProxySession proxy(std::make_unique<ProxyBackend>());
    AuthDialogCoordinator dialogs(&parent);ApplicationLogger logger;CredentialAccess access(std::make_unique<MemoryCredentialStore>());
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,nullptr,&dialogs,&logger,&access,
        [&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},[](const QString &,const QString &,QSystemTrayIcon::MessageIcon){},nullptr,noOfficialClient);
    auto *queryEngine=new QueryEngine;QPointer<QueryEngine> guarded=queryEngine;
    auto *window=new AuthInfoWindow(&parent,queryEngine);window->fetchAuthInfo({});window->show();window->close();
    QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    check(guarded && guarded->stops==1,"closing a query cancels it without destroying its running thread");
    int ready=0;QObject::connect(&controller,&ConnectionUiController::readyToQuit,[&]{++ready;});
    controller.prepareForQuit();controller.prepareForQuit();QApplication::processEvents();
    check(!ready && guarded->stops==1,"exit waits for an already cancelled query without repeated stop");
    emit queryEngine->finished(ConnectionError::NONE);until([&]{return ready==1;});
    QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    check(!guarded,"query owner is destroyed only after its cleanup completes");
}

static void quitWaitsForNetworkInspectionWithoutBlockingTheGui() {
    class SnapshotEngine : public QueryEngine {
        void readSnapshot(Snapshot kind, const QString &generation) override {
            const QJsonObject value=kind==Snapshot::Network
                ? QJsonObject{{"interfaces",QJsonArray{}},{"routes",QJsonArray{}}}
                : QJsonObject{{"ip_resources",QJsonArray{}},{"dns_records",QJsonObject{}},{"campus_dns",""}};
            emit snapshotReady(kind,generation,{{kind==Snapshot::Network ? "network" : "resources",value}},RequestStatus::Success);
        }
    };
    QTemporaryDir folder;QSettings settings(folder.filePath("network-quit.ini"),QSettings::IniFormat);DefaultSettings::reset(settings);
    QWidget parent;QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);
    auto *engine=new SnapshotEngine;ConnectionSession session(engine);SystemProxySession proxy(std::make_unique<ProxyBackend>());
    QSemaphore entered,resume;
    NetworkPolicySession networkPolicy(engine,[&] {
        entered.release();check(resume.tryAcquire(1,2000),"release owned network query before its deadline");return DnsSnapshot{{},{}};
    });
    AuthDialogCoordinator dialogs(&parent);ApplicationLogger logger;CredentialAccess access(std::make_unique<MemoryCredentialStore>());
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,&networkPolicy,&dialogs,&logger,&access,
        [&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},[](const QString &,const QString &,QSystemTrayIcon::MessageIcon){},nullptr,noOfficialClient);
    int ready=0;QObject::connect(&controller,&ConnectionUiController::readyToQuit,[&]{++ready;});
    check(session.start({},{}),"start network inspection exit fixture");
    emit engine->sessionStarted("1");emit engine->connectionEstablished();
    check(entered.tryAcquire(1,1000),"network query runs outside the GUI thread");
    controller.prepareForQuit();emit engine->finished(ConnectionError::NONE);
    // Platform event dispatch can consume a full poll interval.
    QTimer::singleShot(0,&parent,[]{QThread::msleep(40);});
    int ticks=0;QTimer heartbeat;
    QObject::connect(&heartbeat,&QTimer::timeout,&parent,[&]{++ticks;});heartbeat.start(1);
    QElapsedTimer elapsed;elapsed.start();
    until([&]{return ticks>1 && elapsed.elapsed()>=30;});
    check(!ready && engine->stops==1 && ticks>1,"ordered exit remains responsive while its cancelled network query finishes");
    resume.release();until([&]{return ready==1;});
    check(!networkPolicy.isBusy() && networkPolicy.model().isEmpty(),"late network result cannot republish after ordered exit");
}

static void quitWaitsForInitialSsoCache() {
    QTemporaryDir folder;QSettings settings(folder.filePath("quit-cache.ini"),QSettings::IniFormat);
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");settings.setValue("JustConnect/ServerPort",443);
    settings.setValue("JustConnect/AuthType","httpsOauth2");settings.setValue(DefaultSettings::RememberAuthentication,true);settings.sync();
    QWidget parent;QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);
    auto *engine=new QueryEngine;ConnectionSession session(engine);SystemProxySession proxy(std::make_unique<ProxyBackend>());
    AuthDialogCoordinator dialogs(&parent);ApplicationLogger logger;
    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&proxy,nullptr,&dialogs,&logger,
        &access,[&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},
        [](const QString &,const QString &,QSystemTrayIcon::MessageIcon){check(false,"exit preserves authorized SSO cache persistence");},nullptr,noOfficialClient);
    int ready=0;
    QObject::connect(&controller,&ConnectionUiController::readyToQuit,[&]{
        const auto source=CredentialAccess::source(settings,{});AuthenticationCache saved;ProfileCredentials vault(*store);
        check(!access.isBusy() && vault.loadAuthenticationCache(source.scope,source.profile,saved).succeeded()
            && saved.account=="exit-account" && saved.data=="private-exit-cookie","quit becomes ready only after the chained native cache write is verified");
        ++ready;
    });
    bool requested=false;
    QObject::connect(&access,&CredentialAccess::configurationSaved,[&](const QString &){
        check(!access.isBusy(),"account binding exposes the completed public batch before its continuation");
        controller.prepareForQuit();controller.prepareForQuit();
        check(!ready && engine->stops==1,"repeated exit stops once and waits for the active core");
        emit engine->finished(ConnectionError::NONE);
        check(!ready,"core cleanup alone cannot finish before the SSO cache continuation");requested=true;
    });
    connectButton.click();until([&]{return engine->starts==1;});
    emit engine->authenticationCacheUpdated({"exit-account","private-exit-cookie"});
    until([&]{return ready==1;});connectButton.click();QApplication::processEvents();
    check(requested && ready==1 && engine->starts==1,"shutdown cannot start another connection or signal readiness twice");
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
    QWidget parent;
    AuthDialogCoordinator dialogs(&parent);
    dialogs.requestAuthentication({{"schema_version",1},{"generation","1"},{"request_id","1"},
        {"challenge",QJsonObject{{"kind","cas"},{"login_url",base+"/first"}}}},QUrl(base));
    auto *first=qobject_cast<SsoLoginWebView *>(challenge(parent));
    check(first!=nullptr,"coordinator opens the initial SSO page");
    auto *store=first->findChild<QWebEngineView *>()->page()->profile()->cookieStore();
    bool initialCookie=false;
    const auto observed=QObject::connect(store,&QWebEngineCookieStore::cookieAdded,[&](const QNetworkCookie &cookie) {
        initialCookie |= cookie.name()=="jc_scope" && cookie.value()=="first";
    });
    store->loadAllCookies();
    until([&]{return initialCookie;});QObject::disconnect(observed);
    visit(first,"/echo");
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
    const QJsonObject deviceRequest{{"schema_version",1},{"generation","3"},{"request_id","19"},
        {"challenge",QJsonObject{{"kind","trusted_device"}}}};
    for (bool confirm:{false,true}) {
        const auto before=responses;
        dialogs.requestAuthentication(deviceRequest,{});
        auto *dialog=challenge(parent);
        auto *buttons=dialog->findChild<QDialogButtonBox *>();
        check(responses==before && buttons->button(QDialogButtonBox::Cancel)->isDefault()
            && !buttons->button(QDialogButtonBox::Ok)->isDefault(),"trusted device never confirms on opening or by default");
        buttons->button(confirm?QDialogButtonBox::Ok:QDialogButtonBox::Cancel)->click();
        check(responses==before+1 && submitted["action"]==(confirm?"confirm":"cancel")
            && submitted["generation"]=="3" && submitted["request_id"]=="19" && !submitted.contains("code"),"explicit device decision retains request identity");
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
    queryProfile.behavior.rememberAuthentication=true;queryProfile.authenticationCache={"private-account","private-cache"};
    query->fetchAuthInfo(queryProfile);
    check(fake->operation == CoreEngine::Operation::AuthMethods && fake->profile.endpoint.port == 8443 && fake->profile.credentials.password.isEmpty()
        && fake->profile.authenticationCache.data.isEmpty() && fake->profile.authenticationCache.account.isEmpty() && !fake->profile.behavior.rememberAuthentication
        && !fake->profile.tls.verify && fake->profile.tls.caPem=="query CA",
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
    for (const auto &policy:QList<TlsOptions>{{},{true,gatewayProfile.tls.caPem},{true,{},true},{false,{}}}) {
        std::cout << "CHECK: browser TLS verify=" << policy.verify << ", custom CA=" << !policy.caPem.isEmpty()
                  << ", unverified nodes=" << policy.allowUnverifiedNodes << '\n';
        QWidget parent;auto *engine=new QueryEngine;ConnectionSession session(engine);AuthDialogCoordinator dialogs(&parent);
        QObject::connect(&session,&ConnectionSession::authenticationRequired,&dialogs,&AuthDialogCoordinator::requestAuthentication);
        auto profile=gatewayProfile;profile.tls=policy;check(session.start(profile,{}),"start immutable browser TLS policy context");profile.tls={};
        auto loginTarget=target;if(!policy.verify)loginTarget.setQuery("scope=unsafe");
        const QJsonObject request{{"schema_version",1},{"generation","1"},{"request_id","1"},
            {"challenge",QJsonObject{{"kind","oauth2"},{"login_url",""}}}};
        emit engine->authenticationRequired(request);
        auto *dialog=qobject_cast<SsoLoginWebView *>(challenge(parent));check(dialog!=nullptr,"SSO uses the active session browser");
        auto *view=dialog->findChild<QWebEngineView *>();bool done=false,okay=false;
        auto connection=QObject::connect(view,&QWebEngineView::loadFinished,[&](bool success){done=true;okay=success;});
        QElapsedTimer loadElapsed;loadElapsed.start();
        QObject::connect(view->page(),&QWebEnginePage::loadingChanged,view,[&](const QWebEngineLoadingInfo &info) {
            std::cout << "CHECK: browser load status=" << info.status() << ", error domain=" << info.errorDomain()
                      << ", error code=" << info.errorCode() << ", elapsed_ms=" << loadElapsed.elapsed() << std::endl;
        });
        QObject::connect(view->page(),&QWebEnginePage::renderProcessTerminated,view,
            [](QWebEnginePage::RenderProcessTerminationStatus status,int code) {
                std::cout << "CHECK: browser renderer status=" << status << ", exit=" << code << std::endl;
            });
        // Subscribe before navigation; a rejected certificate can finish while the dialog opens.
        dialog->setInitialUrl(loginTarget);
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
    p.behavior.rememberAuthentication=true;
    p.proxy.socksBind = listeners["socks"].toString();
    p.proxy.httpBind = listeners["http"].toString();
    auto *untrustedEngine=new EmbeddedCoreEngine;
    auto *untrustedQuery=new AuthInfoWindow(&parent,untrustedEngine);
    bool trustFailure=false;
    QStringList trustDiagnostics;
    QObject::connect(untrustedEngine,&CoreEngine::diagnostic,[&](const QString &code){trustDiagnostics.append(code);});
    QObject::connect(untrustedEngine,&CoreEngine::finished,[&](ConnectionError error){trustFailure=error==ConnectionError::TLS_TRUST;});
    auto untrustedProfile=p; untrustedProfile.tls.caPem.clear();
    untrustedProfile.tls.allowUnverifiedNodes=true;
    untrustedQuery->fetchAuthInfo(untrustedProfile);
    until([&]{return trustFailure;});
    check(untrustedQuery->findChild<QLabel *>("label")->text().contains("证书")
        && untrustedQuery->findChild<QListWidget *>()->count()==0,"real query reports certificate failure without delivering methods");
    check(trustDiagnostics==QStringList{"tls_authentication_failed","tls_unknown_authority","tls_peer_chain_leaf_only","tls_peer_self_signed"},
        "real ABI delivers bounded certificate diagnostics before the trust failure");
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
    QString generation;
    int networkSnapshots=0, resourceSnapshots=0;

    QJsonObject initialProtection, readyResources;
    CoreEngine::RequestStatus resourceStatus=CoreEngine::RequestStatus::Unavailable;
    QObject::connect(engine,&CoreEngine::sessionStarted,[&](const QString &value){generation=value;});
    QObject::connect(engine,&CoreEngine::initialProtectionApplied,[&](const QJsonObject &policy) {
        check(QThread::currentThread()==QApplication::instance()->thread() && policy["generation"]==generation
            && policy["revision"]=="0", "initial protection belongs to the GUI session generation");
        initialProtection=policy;
    });
    const auto snapshotObserver=QObject::connect(engine,&CoreEngine::snapshotReady,[&](CoreEngine::Snapshot kind,const QString &value,const QJsonObject &snapshot,CoreEngine::RequestStatus status){
        check(QThread::currentThread()==QApplication::instance()->thread() && value==generation,"real snapshots reach their GUI session generation");
        if(status!=CoreEngine::RequestStatus::Success) check(snapshot.isEmpty(),"pending or failed snapshot cannot expose old data");
        if(kind==CoreEngine::Snapshot::Resources) {
            resourceStatus=status;++resourceSnapshots;
            if(status==CoreEngine::RequestStatus::Success) {
                check(snapshot["resources"].toObject()["domain_resources"].toObject().contains("campus.test"),"Qt receives actual parsed campus permissions");
                readyResources=snapshot["resources"].toObject();
            }
        } else {
            check(status==CoreEngine::RequestStatus::Success && !snapshot["network"].toObject()["interfaces"].toArray().isEmpty(),"Qt receives the actual native network snapshot");
            ++networkSnapshots;
        }
    });
    AuthenticationCache savedCache;
    QObject::connect(engine,&CoreEngine::authenticationCacheUpdated,[&](const AuthenticationCache &cache) {
        check(QThread::currentThread()==QApplication::instance()->thread(),"cache arrives on the GUI thread");savedCache=cache;
    });
    QObject::connect(engine,&CoreEngine::authenticationCacheInvalidated,[&]{check(false,"fresh authentication is not invalidated");});
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
    QTemporaryDir profileFolder;QSettings settings(profileFolder.filePath("gateway.ini"),QSettings::IniFormat);
    DefaultSettings::reset(settings);
    settings.setValue("JustConnect/ServerAddress",p.endpoint.server);settings.setValue("JustConnect/ServerPort",p.endpoint.port);
    settings.setValue("JustConnect/AuthType",p.endpoint.authType);settings.setValue("JustConnect/AuthID",p.endpoint.authId);
    settings.setValue("JustConnect/AuthSubType",p.endpoint.authSubType);settings.setValue("JustConnect/LoginDomain",p.endpoint.loginDomain);
    settings.setValue("JustConnect/PhoneCountryCode",p.endpoint.phone.section('-',0,0));settings.setValue("JustConnect/PhoneNumber",p.endpoint.phone.section('-',1));
    settings.setValue("JustConnect/TLSCAPEM",p.tls.caPem);settings.setValue(DefaultSettings::RememberAuthentication,true);
    settings.setValue("JustConnect/SOCKS5Port",QUrl("http://"+p.proxy.socksBind).port());
    settings.setValue("JustConnect/HTTPPort",QUrl("http://"+p.proxy.httpBind).port());settings.sync();
    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    QPushButton connectButton(&parent),proxyButton(&parent);QAction trayAction(&parent);ApplicationLogger logger;
    SystemProxySession systemProxy(std::make_unique<ProxyBackend>());
    NetworkPolicySession networkPolicy(engine, readSystemDnsSnapshot);
    ConnectionUiController controller(&parent,&connectButton,&proxyButton,&trayAction,&session,&systemProxy,&networkPolicy,&dialogs,&logger,
        &access,[&]{return &settings;},[&]{return CredentialAccess::source(settings,{});},
        [](const QString &,const QString &,QSystemTrayIcon::MessageIcon){check(false,"real gateway authentication cache must save successfully");},nullptr,noOfficialClient);
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; });
    heartbeat.start(1);
    connectButton.click();
    until([&] { return parent.findChild<QLineEdit *>("authCodeEdit") != nullptr; });
    until([&] { return ticks > 5; });
    check(session.state() == ConnectionState::Starting, "authentication wait leaves GUI responsive");
    engine->readSnapshot(CoreEngine::Snapshot::Resources,generation);
    until([&]{return resourceSnapshots==1;});
    check(resourceStatus==CoreEngine::RequestStatus::Pending,"Qt distinguishes resources pending authentication from missing capability");
    enterCode(parent, "fixture-code");
    until([&] {for (auto *dialog:parent.findChildren<QDialog *>()) if(dialog->isVisible() && dialog->findChild<QDialogButtonBox *>() && !dialog->findChild<QLineEdit *>("authCodeEdit"))return true;return false;});
    check(responses==1 && session.state()==ConnectionState::Starting,"device registration waits for a second explicit UI action");
    challenge(parent)->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();
    until([&] { return session.state() == ConnectionState::Running; });
    until([&]{return resourceSnapshots==2 && networkSnapshots==1 && networkPolicy.status()==CoreEngine::RequestStatus::Success;});
    check(resourceStatus==CoreEngine::RequestStatus::Success,"Qt receives ready resources without another authentication");
    const auto originalTargets=networkPolicy.model()["targets"].toArray();
    const auto conflicts=campusProtectionConflicts(originalTargets,readyResources);
    check(conflicts.has_value(),"actual parsed campus resources produce a complete conflict model");
    auto overlappingTargets=originalTargets;
    const auto campusAddress=readyResources["dns_records"].toObject()["campus.test"].toArray().first().toString();
    overlappingTargets.append(QJsonObject{{"prefix",campusAddress+"/32"}});
    const auto overlapping=campusProtectionConflicts(overlappingTargets,readyResources);
    check(overlapping.has_value(),"actual campus records accept an explicit overlap fixture");
    bool explained=false;
    for(const auto &value:*overlapping) {
        const auto conflict=value.toObject();
        if(conflict["kind"]=="dns_record" && conflict["domain"]=="campus.test"
            && conflict["target"]==overlappingTargets.size()-1) explained=true;
    }
    check(explained,"actual campus fixture explains the explicitly overlapping original target");
    check(responses == 2, "SMS and explicit device confirmation each reach the production protocol once");
    check(session.phase()==ConnectionPhase::TransportReady
        && session.observation("authentication").result=="succeeded"
        && session.observation("authentication").observedAt.isValid()
        && session.observation("library").result=="succeeded"
        && !session.observation("renewal").observedAt.isValid(),
        "formal ABI observations distinguish authentication, transport and unknown renewal");
    NetworkPolicyWindow inspection(&networkPolicy, &parent);
    inspection.show();
    auto *targets=inspection.findChild<QTreeWidget *>("networkPolicyTargets");
    check(targets && targets->topLevelItemCount()==originalTargets.size(), "real Qt network inspection displays the collected native scopes");
    const auto namespaces=originalDnsNamespaces(networkPolicy.model()["dns"].toObject());
    const auto nameModel=originalDnsProtection(networkPolicy.model()["dns"].toObject());
    check(nameModel && networkPolicy.model()["name_targets"].toArray()==(*nameModel)["targets"].toArray(),
          "Actual Qt session lost normalized name targets or their original sources");
    const auto *dnsTree=inspection.findChild<QTreeWidget *>("networkPolicyDnsNamespaces");
    check(!networkPolicy.model()["dns"].toObject().isEmpty() && namespaces
          && networkPolicy.model()["dns_namespaces"].toArray()==*namespaces
          && dnsTree && dnsTree->topLevelItemCount()==namespaces->size()+1
          && dnsTree->topLevelItem(dnsTree->topLevelItemCount()-1)->text(0)=="localhost",
          "real native DNS facts join the same Qt session model and inspection without another authentication");
    bool nativeSourceShown=false;
    for(const auto &value:networkPolicy.model()["network"].toObject()["interfaces"].toArray()) {
        const auto interface=value.toObject();
        if(interface["addresses"].toArray().isEmpty() || interface["name"].toString().isEmpty()) continue;
        for(int row=0;row<targets->topLevelItemCount();++row)
            nativeSourceShown |= targets->topLevelItem(row)->text(1).contains(interface["name"].toString());
    }
    check(nativeSourceShown,"real Qt inspection explains at least one actual native interface source");
    bool loopbackAuthorized = false;
    for (const auto &value : readyResources["ip_resources"].toArray()) {
        const auto resource = value.toObject();
        loopbackAuthorized |= resource["ip_min"] == "127.0.0.1" && resource["ip_max"] == "127.0.0.1";
    }
    check(loopbackAuthorized && readyResources["domain_resources"].toObject().contains("localhost"),
        "controlled campus permissions overlap the native address and name");
    check(initialProtection["protected_names"].toArray().contains(QJsonObject{{"kind", "suffix"}, {"value", "localhost"}}),
        "initial native name protection is confirmed before traffic");
    QSemaphore nativeListening;
    quint16 nativePort = 0;
    const QByteArray nativeReply("original-network");
    auto nativeServer = QtConcurrent::run([&] {
        QTcpServer server;
        check(server.listen(QHostAddress::LocalHost, 0), "owned native protection server");
        nativePort = server.serverPort();
        nativeListening.release();
        for (int i = 0; i < 5; ++i) {
            check(server.waitForNewConnection(5000), "protected request reaches its original native server");
            auto *socket = server.nextPendingConnection();
            check(socket->write(nativeReply) == nativeReply.size()
                && (socket->bytesToWrite() == 0 || socket->waitForBytesWritten(5000)), "original-network reply");
            socket->disconnectFromHost();
            if (socket->state() != QAbstractSocket::UnconnectedState) socket->waitForDisconnected(5000);
        }
    });
    check(nativeListening.tryAcquire(1, 5000), "native protection server became ready");
    auto connectProtected = [&](QTcpSocket &socket, bool name) {
        ProxyCheck::connectProxy(socket, listeners["socks"].toString());
        check(socket.write(QByteArray::fromHex("050100")) == 3
            && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(5000)), "protected SOCKS greeting");
        check(ProxyCheck::receive(socket, 2) == QByteArray::fromHex("0500"), "protected SOCKS authentication");
        auto destination = name ? QByteArray::fromHex("0501000309") + "localhost" : QByteArray::fromHex("050100017f000001");
        destination.append(char(nativePort >> 8)); destination.append(char(nativePort & 0xff));
        check(socket.write(destination) == destination.size()
            && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(5000)), "protected SOCKS destination");
        check(ProxyCheck::receive(socket, 10).startsWith(QByteArray::fromHex("05000001")), "protected SOCKS connection");
    };
    int preference = 0;
    for (const bool campus : {false, true, false}) {
        if (preference++ != 0) {
            check(networkPolicy.setCampusAddress("127.0.0.1", campus), "Request exact campus/original preference");
            until([&] { return !networkPolicy.isBusy(); });
            check(networkPolicy.policyStatus() == CoreEngine::RequestStatus::Success, "Real core confirms the requested preference");
        }
        if (preference <= 2) {
            QTcpSocket nativeName;
            connectProtected(nativeName, true);
            check(ProxyCheck::receive(nativeName, nativeReply.size()) == nativeReply,
                "Initial name protection survives address updates and overrides hostile campus DNS");
            nativeName.close();
        }
        QTcpSocket protectedSocket;
        connectProtected(protectedSocket, false);
        if (campus) {
            const QByteArray campusPayload("campus-echo");
            check(protectedSocket.write(campusPayload) == campusPayload.size()
                && (protectedSocket.bytesToWrite() == 0 || protectedSocket.waitForBytesWritten(5000)), "Explicit campus payload");
            check(ProxyCheck::receive(protectedSocket, campusPayload.size()) == campusPayload, "Exact choice uses the campus tunnel");
        } else check(ProxyCheck::receive(protectedSocket, nativeReply.size()) == nativeReply,
            "Initial protection and returning to original preserve the actual native server");
        protectedSocket.close();
    }
    check(networkPolicy.setCampusName("LOCALHOST.", true), "Request a concrete campus name exception");
    until([&] { return !networkPolicy.isPolicyUpdating(); });
    check(networkPolicy.policyStatus()==CoreEngine::RequestStatus::Success
          && networkPolicy.campusNames()==QJsonArray{"localhost"} && networkPolicy.campusAddresses().isEmpty(),
          "Real core confirms only the concrete campus name");
    {
        QTcpSocket chosenName;
        connectProtected(chosenName, true);
        const QByteArray payload("campus-name-echo");
        check(chosenName.write(payload)==payload.size()
              && (chosenName.bytesToWrite()==0 || chosenName.waitForBytesWritten(5000)), "Explicit campus name payload");
        check(ProxyCheck::receive(chosenName,payload.size())==payload,
              "Explicit name uses the authorized campus resource despite protected native addresses");
    }
    check(networkPolicy.setCampusName("localhost", false), "Restore the owned original name");
    until([&] { return !networkPolicy.isPolicyUpdating(); });
    check(networkPolicy.policyStatus()==CoreEngine::RequestStatus::Success && networkPolicy.campusNames().isEmpty(),
          "Real core confirms name recovery");
    {
        QTcpSocket restoredName;
        connectProtected(restoredName, true);
        check(ProxyCheck::receive(restoredName,nativeReply.size())==nativeReply,
              "Restored name returns to the actual original server");
    }
    nativeServer.waitForFinished();
    check(networkPolicy.campusAddresses().isEmpty(), "Returning to original removed the confirmed campus exception");
    std::cout << "PASS: initial native address/name protection and live exact campus/original choices\n";
    until([&]{return !access.isBusy(settings.fileName());});
    ProxyCheck::exercise(listeners, [&] {
        session.stop();
        until([&] { return completed == 1; });
    });
    check(networkPolicy.model().isEmpty() && targets->topLevelItemCount()==0, "real stop clears collected scopes and their visible rows");
    inspection.close();
    QObject::disconnect(snapshotObserver);
    check(savedCache.account=="fixture-user" && !savedCache.data.isEmpty(),"Qt receives server-confirmed cache after authentication");
    const auto source=CredentialAccess::source(settings,{});ProfileCredentials vault(*store);AuthenticationCache nativeCache;
    check(vault.loadAuthenticationCache(source.scope,source.profile,nativeCache).succeeded() && nativeCache.data==savedCache.data,
        "production Qt workflow verifies its scoped native record");
    {
        QSettings restartedSettings(settings.fileName(),QSettings::IniFormat);
        ConnectionSession restarted(new EmbeddedCoreEngine);AuthDialogCoordinator restoredDialogs(&parent);
        SystemProxySession restoredProxy(std::make_unique<ProxyBackend>());
        QPushButton restoredConnect(&parent),restoredProxyButton(&parent);QAction restoredTray(&parent);
        ConnectionUiController restoredController(&parent,&restoredConnect,&restoredProxyButton,&restoredTray,&restarted,&restoredProxy,nullptr,
            &restoredDialogs,&logger,&access,[&]{return &restartedSettings;},[&]{return CredentialAccess::source(restartedSettings,{});},
            [](const QString &,const QString &,QSystemTrayIcon::MessageIcon){check(false,"restored native cache remains usable");},nullptr,noOfficialClient);
        bool done=false;
        QObject::connect(&restarted,&ConnectionSession::authenticationRequired,[&](const QJsonObject &,const QUrl &,const TlsOptions &){check(false,"native cache must avoid another authentication prompt");});
        QObject::connect(&restarted,&ConnectionSession::finished,[&](ConnectionError error){check(error==ConnectionError::NONE,"restored Qt connection stops normally");done=true;});
        restoredConnect.click();until([&]{return restarted.state()==ConnectionState::Running && !access.isBusy(settings.fileName());});
        restarted.stop();until([&]{return done;});
    }
    std::cout<<"PASS: native cache restoration\n";
    bool methods = false, queryDone = false;
    QObject::connect(engine, &CoreEngine::authMethodsReady, [&](const QJsonArray &list) { methods = !list.isEmpty(); });
    QObject::connect(engine, &CoreEngine::finished, [&](ConnectionError error) {
        check(error == ConnectionError::NONE, "query restart succeeds"); queryDone = true;
    });
    auto queryProfile=p;queryProfile.keepAlive={"target","ssh://invalid-for-traffic.example.invalid:22"};
    check(engine->start(queryProfile, CoreEngine::Operation::AuthMethods), "authentication queries omit unrelated traffic keepalive configuration");
    until([&] { return methods && queryDone; });
    browserTlsPolicy(p);
    std::cout << "PASS: native protocol session through Qt UI, SMS, SOCKS/HTTP, active stop and query restart\n";
}
int main(int argc, char **argv) {
    // Offscreen runners have no usable graphics context; Chromium's flag covers only its renderer.
    if (qEnvironmentVariable("QT_QPA_PLATFORM")=="offscreen" && qEnvironmentVariableIsEmpty("QT_QUICK_BACKEND"))
        qputenv("QT_QUICK_BACKEND", "software");
    QApplication app(argc, argv);
    if (argc == 3 && QByteArray(argv[1]) == "--gateway") gateway(QJsonDocument::fromJson(argv[2]).object());
    else { browserCookiesStayInLoginDialog(); browserValidatesCallbackNavigation(); uiContracts(); proxyWaitsForReady(); manualCredentialsAndLateResults(); authenticationCacheLifecycle(); onlineExpiryOffersOneReauthentication(); officialClientWarningIsReadOnlyAndDropsCancelledResults(); authenticationSurvivesTunnelFailure(); quitWaitsForInitialSsoCache(); quitWaitsForAuthenticationQueryWithoutBlockingTheGui(); quitWaitsForNetworkInspectionWithoutBlockingTheGui(); }
}
