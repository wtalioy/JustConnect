#include <QApplication>
#include <QTimer>
#include <QVariant>
#include <QWebEnginePage>
#include <QWebEngineView>

#include <iostream>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QWebEngineView view;
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, &app, [&app]() {
        std::cerr << "WebEngine page load timed out\n";
        app.exit(1);
    });
    QObject::connect(&view, &QWebEngineView::loadFinished, &app, [&](bool ok) {
        if (!ok)
        {
            std::cerr << "WebEngine page load failed\n";
            app.exit(1);
            return;
        }
        view.page()->runJavaScript("document.title", [&app](const QVariant &value) {
            const bool matched = value.toString() == "JustConnect 42";
            if (!matched)
            {
                std::cerr << "WebEngine JavaScript result mismatch\n";
            }
            app.exit(matched ? 0 : 1);
        });
    });
    timeout.start(15000);
    view.setHtml("<!doctype html><title>JustConnect</title>"
                 "<script>document.title += ' ' + (6 * 7);</script>");
    return app.exec();
}
