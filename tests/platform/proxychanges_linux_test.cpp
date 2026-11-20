#include "infrastructure/systemproxy/proxychanges.h"
#include <QByteArray>
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QEventLoop>
#include <iostream>
#include <stdexcept>

// The CI image has no dconf session, so ProxyChanges cannot bind to a live
// GSettings watch there. The movement-detection rules are still testable by
// injecting a snapshot reader and driving notifications directly.
namespace {
void check(bool okay, const char *message) { if (!okay) throw std::runtime_error(message); }
}

int main(int argc, char **argv) try {
    QCoreApplication app(argc, argv);
    ProxyChanges silent;
    int silentEvents = 0;
    QObject::connect(&silent, &ProxyChanges::changed, [&] { ++silentEvents; });
    silent.handleSignal(); // No session and no reader: must never report anything.
    check(silentEvents == 0, "Session-less watcher reported a proxy change");

    ProxyChanges watched;
    int events = 0;
    QObject::connect(&watched, &ProxyChanges::changed, [&] { ++events; });
    auto snapshot = QByteArray("org.gnome.system.proxy/mode='none'\n");
    watched.setSnapshotReader([&] { return snapshot; });
    watched.handleSignal();
    check(events == 1, "First observed snapshot did not report the current proxy");
    watched.handleSignal();
    check(events == 1, "Unchanged snapshot reported a proxy change");
    // A burst of notifications (mode plus per-protocol keys written together)
    // collapses into a single emission.
    snapshot = "org.gnome.system.proxy/mode='manual'\n"
        "org.gnome.system.proxy.http/host=proxy.example\n";
    watched.handleSignal(); watched.handleSignal(); watched.handleSignal();
    check(events == 2, "Notification burst reported more than one change");
    // A transient read failure (empty snapshot) never reports a proxy change.
    snapshot.clear();
    watched.handleSignal();
    check(events == 2, "Transient read failure reported a proxy change");
    // Values restored after the failure are not movement either.
    snapshot = "org.gnome.system.proxy/mode='manual'\n"
        "org.gnome.system.proxy.http/host=proxy.example\n";
    watched.handleSignal();
    check(events == 2, "Snapshot restored after a read failure reported a proxy change");
    // A real move after a failure is still reported.
    snapshot = "org.gnome.system.proxy/mode='manual'\n"
        "org.gnome.system.proxy.http/host=proxy2.example\n";
    watched.handleSignal();
    check(events == 3, "Change after a failed read was not reported");

    // The real notification path batches a write burst before reading: the
    // burst opens one window and collapses into a single read and emission.
    snapshot = "org.gnome.system.proxy/mode='none'\n";
    watched.noteSignal(); watched.noteSignal(); watched.noteSignal();
    QDeadlineTimer deadline(2000);
    while (events < 4 && !deadline.hasExpired())
        app.processEvents(QEventLoop::AllEvents, 20);
    check(events == 4, "A batched notification burst reported more than one change");
    check(!deadline.hasExpired(), "The batched notification burst was never delivered");
    std::cout << "proxychanges_linux_test passed" << std::endl;
    return 0;
} catch (const std::exception &error) {
    std::cerr << "FAILED: " << error.what() << std::endl;
    return 1;
}
