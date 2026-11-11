#include <QApplication>
#include <QTimer>
#include <QVariant>
#include "presentation/browser/signinbrowser.h"
#include "tests/uiwait.h"

#include <iostream>

int main(int argc, char *argv[])
{
    std::cerr << "Starting system sign-in browser runtime check\n";
    QApplication app(argc, argv);
    std::cerr << "Creating system sign-in browser view\n";
    SignInBrowser view(nullptr,{},TlsOptions{},[](const QUrl &,bool){return true;});
    view.show();
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, &app, [&app]() {
        std::cerr << "system sign-in browser page load timed out\n";
        app.exit(1);
    });
    QObject::connect(&view, &SignInBrowser::loadFinished, &app, [&](bool ok) {
        if (!ok)
        {
            std::cerr << "system sign-in browser page load failed\n";
            app.exit(1);
            return;
        }
        view.runJavaScript("document.title", [&app](const QVariant &value) {
            const bool matched = value.toString() == "JustConnect 42";
            if (!matched)
            {
                std::cerr << "system sign-in browser JavaScript result mismatch\n";
            }
            app.exit(matched ? 0 : 1);
        });
    });
    timeout.start(UiWait::BrowserStartupTimeoutMs);
    std::cerr << "Loading HTML and JavaScript\n";
    view.setHtml("<!doctype html><title>JustConnect</title>"
                 "<script>document.title += ' ' + (6 * 7);</script>");
    return app.exec();
}
