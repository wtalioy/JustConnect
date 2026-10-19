#include "../probe.h"

#include <QApplication>
#include <QLibrary>
#include <QSysInfo>
#include <QThread>
#include <QTimer>
#include <QVariant>
#include <QWebEnginePage>
#include <QWebEngineView>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

static void check(bool ok, const char *message)
{
    if (!ok) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

#ifdef PROBE_SHARED
template<typename T> static T resolve(QLibrary &library, const char *name)
{
    auto result = reinterpret_cast<T>(library.resolve(name));
    check(result != nullptr, name);
    return result;
}
#endif

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    std::cout << "Qt " << qVersion() << ", host " << QSysInfo::buildCpuArchitecture().toStdString()
              << ", C++ " << __cplusplus << '\n';
#ifdef PROBE_SHARED
    QLibrary library(QCoreApplication::applicationDirPath() + "/probe.dll");
    library.setLoadHints(QLibrary::PreventUnloadHint);
    check(library.load(), qPrintable(library.errorString()));
    const auto abi = resolve<decltype(&jc_probe_abi)>(library, "jc_probe_abi");
    const auto create = resolve<decltype(&jc_probe_create)>(library, "jc_probe_create");
    const auto read = resolve<decltype(&jc_probe_read)>(library, "jc_probe_read");
    const auto destroy = resolve<decltype(&jc_probe_destroy)>(library, "jc_probe_destroy");
    const auto live = resolve<decltype(&jc_probe_live)>(library, "jc_probe_live");
#else
    const auto abi = jc_probe_abi;
    const auto create = jc_probe_create;
    const auto read = jc_probe_read;
    const auto destroy = jc_probe_destroy;
    const auto live = jc_probe_live;
#endif
    check(abi() == 1 && live() == 0, "Go initialization/ABI");
    check(create(nullptr, 1) == 0 && create(nullptr, 65537) == 0, "invalid input accepted");
    uint32_t length = 0;
    check(read(0, nullptr, 0, &length) == -1 && destroy(0) == -1, "invalid handle accepted");
    auto empty = create(nullptr, 0);
    check(empty && read(empty, nullptr, 0, &length) == 0 && length == 0, "empty buffer");
    check(destroy(empty) == 0, "empty destroy");
    auto abandoned = create(nullptr, 0);
    check(abandoned && destroy(abandoned) == 0, "destroy before worker starts");

    auto exercise = [&](uint32_t size) {
        std::vector<uint8_t> input(size, 0xC3);
        input[size / 2] = 0; // Embedded NUL must not truncate bytes.
        const auto expected = input;
        const auto handle = create(input.data(), size);
        check(handle != 0, "create");
        std::fill(input.begin(), input.end(), 0);
        uint32_t needed = 0;
        std::vector<uint8_t> output(size + 2, 0xA5);
        check(read(handle, nullptr, 0, &needed) == -2 && needed == size, "size query");
        check(read(handle, output.data() + 1, size - 1, &needed) == -2, "short buffer");
        check(output[1] == 0xA5, "short buffer was modified");
        check(read(handle, nullptr, size, &needed) == -1, "null output accepted");
        check(read(handle, output.data(), size, nullptr) == -1, "null length accepted");
        check(read(handle, output.data() + 1, size, &needed) == 0 && needed == size, "read");
        check(output.front() == 0xA5 && output.back() == 0xA5, "buffer overrun");
        check(std::equal(expected.begin(), expected.end(), output.begin() + 1), "borrowed input retained");
        check(destroy(handle) == 0 && destroy(handle) == -1, "double destroy");
        check(read(handle, nullptr, 0, &needed) == -1, "stale handle accepted");
        check(std::equal(expected.begin(), expected.end(), output.begin() + 1), "output ownership");
    };
    exercise(65536);

    int finished = 0;
    int ticks = 0;
    bool pageLoaded = false;
    const auto finish = [&]() {
        if (finished == 4 && pageLoaded) {
            check(ticks > 0 && live() == 0, "GUI heartbeat or leaked instances");
            std::cout << "PASS: main thread + 4 QThreads, 257 buffer/lifecycle rounds, "
                         "Go GC/workers, live handles=0, WebEngine JavaScript, heartbeat=" << ticks << '\n';
            app.quit();
        }
    };
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, &app, [&]() { ++ticks; });
    heartbeat.start(1);
    QTimer::singleShot(45000, &app, []() { check(false, "probe timed out"); });
    std::array<std::unique_ptr<QThread>, 4> workers;
    for (auto &worker : workers) {
        worker.reset(QThread::create([&]() {
            check(QThread::currentThread() != app.thread(), "worker is GUI thread");
            for (int i = 0; i < 64; ++i)
                exercise(127);
        }));
        QObject::connect(worker.get(), &QThread::finished, &app, [&]() { ++finished; finish(); });
        worker->start();
    }
    QWebEngineView view;
    QObject::connect(&view, &QWebEngineView::loadFinished, &app, [&](bool ok) {
        check(ok, "WebEngine page load");
        view.page()->runJavaScript("document.title", [&](const QVariant &value) {
            check(value.toString() == "JustConnect 42", "WebEngine JavaScript");
            pageLoaded = true;
            finish();
        });
    });
    view.setHtml("<!doctype html><title>JustConnect</title><script>document.title += ' ' + (6 * 7);</script>");
    const int result = app.exec();
    for (auto &worker : workers)
        worker->wait();
    return result;
}
