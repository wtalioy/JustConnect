#include "infrastructure/networkaccess/linux/networkaccess.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
class Engine : public CoreEngine
{
public:
    int starts = 0, stops = 0;
    bool start(const ConnectionProfile &, Operation) override { ++starts; return true; }
    void stop() override { ++stops; emit finished(ConnectionError::NONE); }
    void respond(const QJsonObject &) override {}
};

int main(int argc, char **argv) try
{
    QTemporaryDir data;
    check(data.isValid(), "private application data fixture");
    qputenv("XDG_DATA_HOME", data.path().toUtf8());
    QCoreApplication app(argc, argv);
    app.setApplicationName("networkaccess-test");
    auto *engine = new Engine;
    NetworkPolicySession policy(engine, [] { return DnsSnapshot{}; });
    ConnectionSession first(engine, nullptr, new LinuxNetworkAccess(engine, &policy, 1400));
    auto *other = new Engine;
    NetworkPolicySession otherPolicy(other, [] { return DnsSnapshot{}; });
    ConnectionSession second(other, nullptr, new LinuxNetworkAccess(other, &otherPolicy, 1400));
    check(first.start({}, {}) && engine->starts == 1, "prepare without privileged writes before core startup");
    const QDir hints(data.path() + "/networkaccess-test/network-owners");
    const auto locks = hints.entryList({"*.lock"}, QDir::Files);
    check(locks.size() == 1, "one process owns the namespace lock");
    auto hintPath = hints.filePath(locks.first());
    hintPath.chop(5);
    check(second.start({}, {}) && other->starts == 0 && !second.isActive(), "another GUI cannot replace live ownership");
    first.stop();first.stop();
    check(!first.isActive() && engine->stops == 1 && !QFileInfo::exists(hintPath), "pre-activation stop releases only its own lock");
    check(second.start({}, {}) && other->starts == 1, "rejected contender did not remove the live lock");
    second.stop();
    check(!second.isActive(), "second prepared connection stops");

    QFile invalid(hintPath);
    const QByteArray malformed(36, 'x');
    check(invalid.open(QIODevice::WriteOnly) && invalid.write(malformed) == malformed.size(), "seed invalid private hint");
    invalid.close();
    check(first.start({}, {}) && engine->starts == 1 && first.isActive(), "unknown recovery hint blocks a new core");
    first.stop();
    check(first.isActive() && invalid.open(QIODevice::ReadOnly) && invalid.readAll() == malformed,
          "recovery does not guess or erase an unknown hint");
    invalid.close();
    check(invalid.remove(), "remove only fixture-owned malformed data");
    first.stop();
    check(!first.isActive() && engine->stops == 1, "explicit retry completes after fixture repair without stopping an unstarted core");

    QFile target(data.filePath("foreign"));
    check(target.open(QIODevice::WriteOnly) && target.write(malformed) == malformed.size(), "symlink target fixture");
    target.close();
    check(QFile::link(target.fileName(), hintPath), "seed symlink hint");
    check(first.start({}, {}) && engine->starts == 1 && first.isActive(), "symlink hint never enters authorization");
    check(QFile::remove(hintPath), "remove only the test link");
    first.stop();
    check(!first.isActive() && target.open(QIODevice::ReadOnly) && target.readAll() == malformed, "foreign target retained");
    check(first.start({}, {}) && engine->starts == 2, "prepare again after settled recovery");
    emit engine->connectionEstablished();
    check(!first.isActive() && engine->stops == 2 && first.state() == ConnectionState::Failed,
          "missing complete policy never becomes campus-ready and leaves no ownership");
    std::cout << "PASS: namespace exclusion, pre-activation stop, malformed/symlink recovery hints and missing policy\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
