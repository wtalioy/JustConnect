// Sign-in callback boundary on Linux: a navigation into the callback endpoint
// completes sign-in only when WebKitGTK confirms it as the main frame, and any
// classification that stays ambiguous fails closed to a frame load. The
// scenarios drive a real WebKitGTK view against a local HTTP origin: a
// top-level 302 redirect completes sign-in, while direct, redirected, and
// nested iframes reaching the callback endpoint are refused without
// completing it.
#include <QApplication>
#include <QByteArray>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>
#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>

#include "presentation/browser/origin.h"
#include "presentation/browser/signinbrowser.h"

namespace {

bool waitFor(const std::function<bool()> &done, int timeoutMs)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (!done() && elapsed.elapsed() < timeoutMs)
        QApplication::processEvents(QEventLoop::AllEvents, 50);
    return done();
}

// Local HTTP origin that answers every scenario path on one port, exactly like
// a campus portal issuing redirects into the passport callback.
class CallbackServer {
public:
    CallbackServer()
    {
        if (!server.listen(QHostAddress::LocalHost, 0)) {
            std::cerr << "FAIL: the local HTTP origin did not start\n";
            std::exit(1);
        }
        origin = QByteArray("http://127.0.0.1:") + QByteArray::number(server.serverPort());
        QObject::connect(&server, &QTcpServer::newConnection, [this] {
            while (auto *socket = server.nextPendingConnection()) {
                QObject::connect(socket, &QTcpSocket::readyRead, [this, socket] { route(socket); });
                QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
            }
        });
    }

    QUrl url(const QString &pathAndQuery) const
    {
        return QUrl(QStringLiteral("http://127.0.0.1:%1%2").arg(server.serverPort()).arg(pathAndQuery));
    }

private:
    void route(QTcpSocket *socket)
    {
        const auto request = socket->readAll();
        const auto lineEnd = request.indexOf("\r\n");
        if (lineEnd < 0) return;
        const auto parts = request.left(lineEnd).split(' ');
        serve(socket, parts.size() > 1 ? parts.at(1) : QByteArray("/"));
    }

    void reply(QTcpSocket *socket, const QByteArray &head, const QByteArray &body)
    {
        socket->write(head + "Content-Length: " + QByteArray::number(body.size())
            + "\r\nConnection: close\r\n\r\n" + body);
        socket->flush();
        socket->disconnectFromHost();
    }

    void redirect(QTcpSocket *socket, const QByteArray &location)
    {
        reply(socket, "HTTP/1.1 302 Found\r\nLocation: " + origin + location + "\r\n", {});
    }

    void page(QTcpSocket *socket, const QByteArray &html)
    {
        reply(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n", html);
    }

    void serve(QTcpSocket *socket, const QByteArray &target)
    {
        const auto query = target.indexOf('?');
        const auto path = query >= 0 ? target.left(query) : target;
        std::cerr << "SERVER req " << target.constData() << "\n";
        if (path == "/start") return redirect(socket, "/cb?ticket=TOP");
        if (path == "/jump") return redirect(socket, "/cb?ticket=NESTED");
        if (path == "/frame-host")
            return page(socket, R"(<html><body><iframe src="/cb?ticket=DIRECT"></iframe></body></html>)");
        if (path == "/jump-host")
            return page(socket, R"(<html><body><iframe src="/jump"></iframe></body></html>)");
        if (path == "/nest-host")
            return page(socket, R"(<html><body><iframe src="/mid"></iframe></body></html>)");
        if (path == "/mid")
            return page(socket, R"(<html><body><iframe src="/cb?ticket=DEEP"></iframe></body></html>)");
        if (path == "/js-host")
            return page(socket, R"(<html><body><script>location.replace("/cb?ticket=JS")</script></body></html>)");
        if (path == "/js-frame-host")
            return page(socket, R"(<html><body><iframe src="/js-frame"></iframe></body></html>)");
        if (path == "/js-frame")
            return page(socket, R"(<html><body><script>location.replace("/cb?ticket=JSFRAME")</script></body></html>)");
        if (path.startsWith("/cb"))
            return reply(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n", "callback-served");
        return reply(socket, "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n", "missing");
    }

    QTcpServer server;
    QByteArray origin;
};

struct Navigation {
    QUrl url;
    bool mainFrame;
};

struct Run {
    QList<Navigation> navigations;
    bool login = false;
};

bool atCallback(const Run &run, const QUrl &callback)
{
    return std::any_of(run.navigations.cbegin(), run.navigations.cend(),
        [&callback](const Navigation &nav) { return BrowserOrigin::sameEndpoint(nav.url, callback); });
}

void dump(const Run &run)
{
    for (const auto &nav : run.navigations)
        std::cerr << "  main=" << nav.mainFrame << " " << qPrintable(nav.url.toString()) << "\n";
}

// Drives one sign-in attempt against the local origin. The navigation policy
// mirrors SsoLoginWebView: navigations away from the callback endpoint stay
// allowed, while the callback endpoint completes sign-in only on a confirmed
// main frame and is blocked in every other case.
Run runScenario(const QUrl &callback, const QUrl &start, const std::function<bool(const Run &)> &done)
{
    Run run;
    auto browser = std::make_unique<SignInBrowser>(nullptr, callback, TlsOptions{},
        [&run, &callback](const QUrl &url, bool mainFrame) {
            run.navigations.append({url, mainFrame});
            if (!BrowserOrigin::sameEndpoint(url, callback)) return true;
            if (mainFrame && url.path(QUrl::FullyEncoded) == callback.path(QUrl::FullyEncoded)) run.login = true;
            return false; // The dialog blocks the callback endpoint either way.
        });
    bool runtimeFailed = false;
    QObject::connect(browser.get(), &SignInBrowser::initializationFailed,
        browser.get(), [&runtimeFailed] { runtimeFailed = true; });
    browser->resize(900, 700);
    browser->show();
    browser->load(start);
    if (!waitFor([&] { return runtimeFailed || done(run); }, 30000)) {
        std::cerr << "FAIL: the scenario did not reach its outcome; recorded navigations:\n";
        dump(run);
        std::exit(1);
    }
    if (runtimeFailed) {
        std::cerr << "FAIL: the WebKitGTK runtime is unavailable on this session\n";
        std::exit(1);
    }
    return run;
}

int run(int argc, char *argv[])
{
    QApplication app(argc, argv);
    if (QGuiApplication::platformName() != QLatin1String("xcb")) {
        std::cerr << "FAIL: the sign-in callback frame test needs an X11 session (Qt platform "
            << qPrintable(QGuiApplication::platformName()) << ")\n";
        return 1;
    }

    CallbackServer server;
    const auto callback = server.url("/cb");
    const auto callbackLoads = [](const Run &run, const QUrl &callback) {
        QList<Navigation> hits;
        for (const auto &nav : run.navigations)
            if (BrowserOrigin::sameEndpoint(nav.url, callback)) hits.append(nav);
        return hits;
    };

    // A top-level 302 redirect into the callback completes sign-in, and every
    // callback navigation on the way was confirmed as the main frame.
    const auto top = runScenario(callback, server.url("/start"), [](const Run &run) { return run.login; });
    const auto topHits = callbackLoads(top, callback);
    if (!top.login || topHits.isEmpty()
        || !std::all_of(topHits.cbegin(), topHits.cend(), [](const Navigation &nav) { return nav.mainFrame; })) {
        std::cerr << "FAIL: a top-level redirect did not complete sign-in as a confirmed main frame\n";
        dump(top);
        return 1;
    }
    std::cerr << "top-level redirect completed sign-in as the main frame\n";

    // A frame reaching the callback endpoint must not complete sign-in, and
    // each of the frame shapes reports as a frame load (fail closed).
    const std::initializer_list<std::pair<const char *, const char *>> frameScenarios{
        {"/frame-host", "direct iframe at the callback"},
        {"/jump-host", "redirected iframe at the callback"},
        {"/nest-host", "nested iframe at the callback"},
        {"/js-frame-host", "script-redirected iframe at the callback"},
    };
    for (const auto &[startPath, label] : frameScenarios) {
        const auto run = runScenario(callback, server.url(startPath),
            [&callback](const Run &attempt) { return atCallback(attempt, callback); });
        const auto hits = callbackLoads(run, callback);
        if (run.login || hits.isEmpty()
            || !std::all_of(hits.cbegin(), hits.cend(), [](const Navigation &nav) { return !nav.mainFrame; })) {
            std::cerr << "FAIL: " << label << " was not refused as a frame load\n";
            dump(run);
            return 1;
        }
        std::cerr << label << " refused as a frame load\n";
    }

    // A top-level script redirect is ambiguous by itself; on a page without
    // any iframe no subframe can host the navigation, so the census confirms
    // the main frame and sign-in completes.
    const auto scripted = runScenario(callback, server.url("/js-host"), [](const Run &run) { return run.login; });
    const auto scriptedHits = callbackLoads(scripted, callback);
    if (!scripted.login || scriptedHits.isEmpty()
        || !std::all_of(scriptedHits.cbegin(), scriptedHits.cend(), [](const Navigation &nav) { return nav.mainFrame; })) {
        std::cerr << "FAIL: a top-level script redirect did not complete sign-in on an iframe-free page\n";
        dump(scripted);
        return 1;
    }
    std::cerr << "top-level script redirect completed sign-in as the main frame\n";
    return 0;
}

} // namespace

int main(int argc, char *argv[])
{
    const int status = run(argc, argv);
    // The browser owns GTK/X11 state; leaving through exit() avoids interleaving
    // the Qt and GTK teardown paths.
    std::exit(status);
}
