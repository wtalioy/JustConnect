#include "infrastructure/systemproxy/proxychanges.h"
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QSaveFile>
#include <QTemporaryDir>
#include <QThread>
#include <functional>

static void check(bool value, const char *message) { if (!value) qFatal("%s", message); }
static void until(const std::function<bool()> &ready) {
    QElapsedTimer timer; timer.start();
    while (!ready() && timer.elapsed() < 2000) { QCoreApplication::processEvents(); QThread::msleep(1); }
    check(ready(), "proxy source change was not observed");
}
int main(int argc, char **argv) {
    QTemporaryDir config;
    check(config.isValid(), "private configuration fixture");
    qputenv("XDG_CONFIG_HOME", config.path().toUtf8());
    QCoreApplication app(argc, argv);
    ProxyChanges changes;
    int events = 0;
    QObject::connect(&changes, &ProxyChanges::changed, [&] { ++events; });
    const auto path = config.filePath("kioslaverc");
    auto save = [&](const QByteArray &value) {
        QSaveFile file(path);
        check(file.open(QIODevice::WriteOnly) && file.write(value) == value.size() && file.commit(), "atomic proxy source replacement");
    };
    save("first"); until([&] { return events > 0; });
    const auto first = events;
    save("second"); until([&] { return events > first; });
    const auto second = events;
    check(QFile::remove(path), "remove private source"); until([&] { return events > second; });
    const auto removed = events;
    save("third"); until([&] { return events > removed; });
    const auto recreated = events;
    check(QDir(config.path()).mkpath("dconf"), "create private dconf directory");
    QFile dconf(config.filePath("dconf/user"));
    check(dconf.open(QIODevice::WriteOnly) && dconf.write("private") == 7, "create previously absent source");
    dconf.close(); until([&] { return events > recreated; });
}
