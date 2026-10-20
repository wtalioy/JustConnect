#include "justconnect.h"
#include <QApplication>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QLibrary>
#include <QThread>
#include <QTcpServer>
#include <QTcpSocket>
#include <QHostAddress>
#include <QTimer>
#include <QWebEnginePage>
#include <QWebEngineView>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

extern "C" int32_t jc_c_header_smoke(uint32_t (*query)(void));
static void check(bool ok, const char *message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
#define ABI_FUNCTIONS(X) X(jc_abi_version) X(jc_build_info) X(jc_session_create) X(jc_session_start) \
    X(jc_session_read) X(jc_session_respond) X(jc_session_stop) X(jc_session_destroy)
struct API {
#define MEMBER(name) decltype(&::name) name;
    ABI_FUNCTIONS(MEMBER)
#undef MEMBER
    QLibrary library;
    API() {
#ifdef ABI_SHARED
        library.setFileName(QCoreApplication::applicationDirPath() + "/" + QString::fromUtf8(ABI_LIBRARY_NAME));
        library.setLoadHints(QLibrary::PreventUnloadHint);
        check(library.load(), "load executable-directory ABI library");
#define LOAD(name) name = reinterpret_cast<decltype(name)>(library.resolve(#name)); check(name != nullptr, #name);
#else
#define LOAD(name) name = &::name;
#endif
        ABI_FUNCTIONS(LOAD)
#undef LOAD
    }
};

static QJsonObject json(const std::vector<uint8_t> &bytes, uint32_t length) {
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(QByteArray(reinterpret_cast<const char *>(bytes.data() + 1), length), &error);
    check(error.error == QJsonParseError::NoError && doc.isObject(), "valid UTF-8 JSON output");
    check(!doc.toJson().contains("private-"), "password redaction");
    return doc.object();
}

static QJsonObject read(API &api, uint64_t handle) {
    uint32_t length = 0;
    check(api.jc_session_read(handle, JC_MAX_WAIT_MS, nullptr, 0, &length) == JC_BUFFER_TOO_SMALL && length > 0,
          "query event without consuming");
    std::vector<uint8_t> output(length + 2, 0x5a);
    uint32_t required = 0;
    check(api.jc_session_read(handle, 0, output.data() + 1, length - 1, &required) == JC_BUFFER_TOO_SMALL &&
          required == length, "short buffer preserves event");
    for (auto byte : output) check(byte == 0x5a, "short buffer did not write");
    check(api.jc_session_read(handle, 0, nullptr, 1, &required) == JC_INVALID_ARGUMENT && required == 0,
          "null output does not consume");
    check(api.jc_session_read(handle, 1000, output.data() + 1, length, &required) == JC_OK &&
          required == length && output.front() == 0x5a && output.back() == 0x5a, "output bounds");
    return json(output, length);
}

static void authentication(API &api) {
    uint64_t h = 0, other = 0, generation = 0;
    QString requestID;
    check(api.jc_session_create(JC_ABI_VERSION, &h) == JC_OK &&
          api.jc_session_create(JC_ABI_VERSION, &other) == JC_OK, "fixture handles");
    const std::string config = R"({"schema_version":1,"server":{"host":"vpn.example.invalid","port":443},"auth":{"password":"private-password"}})";
    auto start = [&] {
        std::vector<uint8_t> input(config.begin(), config.end());
        check(api.jc_session_start(h, input.data(), static_cast<uint32_t>(input.size()), &generation) == JC_OK, "fixture start");
        std::fill(input.begin(), input.end(), 0);
    };
    auto respond = [&](uint64_t gen, const char *action, const char *code) {
        auto bytes = QJsonDocument(QJsonObject{
            {"schema_version", 1}, {"generation", QString::number(gen)}, {"request_id", requestID},
            {"action", action}, {"code", code}}).toJson(QJsonDocument::Compact);
        auto status = api.jc_session_respond(h, reinterpret_cast<const uint8_t *>(bytes.data()),
                                           static_cast<uint32_t>(bytes.size()));
        bytes.fill('\0');
        return status;
    };
    start();
    check(read(api, h)["state"] == "starting", "fixture starting");
    auto challenge = read(api, h);
    check(challenge["type"] == "authentication" && challenge["request_id"] == "1" &&
          challenge["challenge"].toObject()["kind"] == "sms", "real ABI authentication event");
    requestID = challenge["request_id"].toString();
    uint64_t unused = 0;
    check(api.jc_session_start(other, reinterpret_cast<const uint8_t *>(config.data()),
          static_cast<uint32_t>(config.size()), &unused) == JC_BUSY && unused == 0, "one active VPN slot across handles");
    check(respond(generation + 1, "submit", "private-password") == JC_STALE_REQUEST, "late generation rejected");
    check(respond(generation, "submit", "") == JC_INVALID_ARGUMENT, "empty code rejected");
    check(respond(generation, "submit", "private-password") == JC_OK, "authentication response copied");
    check(respond(generation, "submit", "private-password") == JC_STALE_REQUEST, "duplicate response rejected");
    check(read(api, h)["state"] == "ready", "test driver used both copied credentials");
    int32_t blockedStatus = JC_INTERNAL;
    std::thread reader([&] {
        uint32_t required = 0;
        blockedStatus = api.jc_session_read(h, JC_MAX_WAIT_MS, nullptr, 0, &required);
    });
    check(api.jc_session_stop(h, 1000) == JC_OK, "stop fixture waiting on host");
    reader.join();
    check(blockedStatus == JC_CANCELLED || blockedStatus == JC_BUFFER_TOO_SMALL, "blocked host reader woke");
    check(read(api, h)["status"].toInt() == JC_CANCELLED, "single cancellation terminal");
    start();
    check(generation == 2, "restart generation increment");
    read(api, h);
    challenge = read(api, h);
    check(challenge["generation"] == "2" && challenge["request_id"] == "2", "new authentication identity");
    requestID = challenge["request_id"].toString();
    check(respond(generation - 1, "cancel", "") == JC_STALE_REQUEST, "old response cannot affect new session");
    check(respond(generation, "cancel", "") == JC_OK, "host authentication cancellation");
    check(read(api, h)["status"].toInt() == JC_CANCELLED, "cancelled authentication terminal");
    check(api.jc_session_destroy(h, 1000) == JC_OK && api.jc_session_destroy(other, 1000) == JC_OK, "fixture cleanup");
    std::cout << "PASS: real C ABI authentication, owned buffers, busy, stale/duplicate replies, cancel and restart\n";
}

static QJsonObject protocolEvent(API &api, uint64_t handle) {
    auto event = read(api, handle);
    while (event["type"] == "diagnostic") event = read(api, handle);
    return event;
}

static QByteArray receive(QTcpSocket &socket, qsizetype size) {
    QByteArray data;
    while (data.size() < size) {
        if (!socket.bytesAvailable()) check(socket.waitForReadyRead(5000), "proxy receive deadline");
        data += socket.read(size - data.size());
    }
    return data;
}

static void nativeProtocol(API &api, const QByteArray &input) {
    auto config = QJsonDocument::fromJson(input).object();
    uint64_t handle = 0, generation = 0;
    check(api.jc_session_create(JC_ABI_VERSION, &handle) == JC_OK, "native protocol create");
    const auto start = [&] {
        auto bytes = QJsonDocument(config).toJson(QJsonDocument::Compact);
        check(api.jc_session_start(handle, reinterpret_cast<const uint8_t *>(bytes.constData()),
              static_cast<uint32_t>(bytes.size()), &generation) == JC_OK, "native protocol start");
        bytes.fill('\0');
        check(protocolEvent(api, handle)["state"] == "starting", "native protocol starting");
    };
    start();
    auto challenge = protocolEvent(api, handle);
    check(challenge["type"] == "authentication" && challenge["challenge"].toObject()["kind"] == "sms", "gateway SMS challenge");
    auto response = QJsonDocument(QJsonObject{{"schema_version", 1}, {"generation", QString::number(generation)},
        {"request_id", challenge["request_id"]}, {"action", "submit"}, {"code", "fixture-code"}}).toJson(QJsonDocument::Compact);
    check(api.jc_session_respond(handle, reinterpret_cast<const uint8_t *>(response.constData()),
          static_cast<uint32_t>(response.size())) == JC_OK, "native gateway SMS response");
    response.fill('\0');
    check(protocolEvent(api, handle)["state"] == "ready", "real protocol ready");
    const auto connectProxy = [&](QTcpSocket &socket, const QString &address) {
        const auto port = address.mid(address.lastIndexOf(':') + 1).toUShort();
        socket.connectToHost(QHostAddress::LocalHost, port);
        check(socket.waitForConnected(5000), "connect owned loopback listener");
    };
    const auto verifyPayload = [&](QTcpSocket &socket) {
        const QByteArray payload(65536, 'j');
        check(socket.write(payload) == payload.size() && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(5000)), "proxy payload write");
        check(receive(socket, payload.size()) == payload, "actual tunnel payload returned");
    };
    auto listeners = config["listeners"].toObject();
    QTcpSocket socks;
    connectProxy(socks, listeners["socks"].toString());
    check(socks.write(QByteArray::fromHex("050100")) == 3 && (socks.bytesToWrite() == 0 || socks.waitForBytesWritten(5000)), "SOCKS greeting");
    check(receive(socks, 2) == QByteArray::fromHex("0500"), "SOCKS authentication");
    const auto destination = QByteArray::fromHex("05010001c000020a0050");
    check(socks.write(destination) == destination.size() && (socks.bytesToWrite() == 0 || socks.waitForBytesWritten(5000)), "SOCKS destination");
    check(receive(socks, 10).startsWith(QByteArray::fromHex("0500")), "SOCKS tunnel established");
    verifyPayload(socks);
    QTcpSocket http;
    connectProxy(http, listeners["http"].toString());
    const QByteArray request("CONNECT 192.0.2.10:80 HTTP/1.1\r\nHost: 192.0.2.10:80\r\n\r\n");
    check(http.write(request) == request.size() && (http.bytesToWrite() == 0 || http.waitForBytesWritten(5000)), "HTTP CONNECT write");
    QByteArray header;
    while (!header.endsWith("\r\n\r\n")) header += receive(http, 1);
    check(header.startsWith("HTTP/1.1 200"), "HTTP tunnel established");
    verifyPayload(http);
    check(api.jc_session_stop(handle, 5000) == JC_OK && api.jc_session_stop(handle, 1000) == JC_OK, "native protocol idempotent stop");
    auto terminal = protocolEvent(api, handle);
    check(terminal["type"] == "terminal" && terminal["status"].toInt() == JC_CANCELLED, "native protocol stopped terminal");
    for (auto *socket : {&socks, &http}) {
        if (socket->state() != QAbstractSocket::UnconnectedState) socket->waitForDisconnected(5000);
        check(socket->state() == QAbstractSocket::UnconnectedState, "active proxy closed on stop");
    }
    config["operation"] = "auth_methods";
    start();
    check(generation == 2, "native restart generation");
    auto methods = protocolEvent(api, handle);
    check(methods["type"] == "auth_methods" && !methods["methods"].toArray().isEmpty(), "real authentication method query");
    check(protocolEvent(api, handle)["status"].toInt() == JC_OK, "query terminal");
    check(api.jc_session_destroy(handle, 1000) == JC_OK && api.jc_session_destroy(handle, 1000) == JC_OK, "native protocol destroy");
    std::cout << "PASS: native protocol session, SMS, SOCKS/HTTP tunnel payloads, active stop and query restart\n";
}

int main(int argc, char **argv) {
    QApplication application(argc, argv);
    API api;
    if (argc == 3 && QByteArray(argv[1]) == "--gateway") { nativeProtocol(api, QByteArray(argv[2])); return 0; }
    check(api.jc_abi_version() == JC_ABI_VERSION && jc_c_header_smoke(api.jc_abi_version) == JC_OK, "C and C++ ABI");
    uint32_t length = 7;
    check(api.jc_build_info(JC_ABI_VERSION + 1, nullptr, 0, &length) == JC_ABI_MISMATCH && length == 0, "ABI mismatch");
    check(api.jc_build_info(JC_ABI_VERSION, nullptr, 0, nullptr) == JC_INVALID_ARGUMENT, "missing length pointer");
    check(api.jc_build_info(JC_ABI_VERSION, nullptr, JC_MAX_OUTPUT + 1, &length) == JC_INVALID_ARGUMENT && length == 0, "output limit");
    check(api.jc_build_info(JC_ABI_VERSION, nullptr, 0, &length) == JC_BUFFER_TOO_SMALL, "metadata length");
    std::vector<uint8_t> metadata(length + 2, 0x5a);
    check(api.jc_build_info(JC_ABI_VERSION, metadata.data() + 1, length, &length) == JC_OK, "metadata copy");
    auto info = json(metadata, length);
    check(info["abi_version"].toInt() == JC_ABI_VERSION, "metadata ABI version");
    auto build = info["build"].toObject();
    check(build["revision"].toString().size() == 40 && build["upstream_commit"].toString().size() == 40 &&
          !build["local_version"].toString().isEmpty(), "source provenance");
    check(build["source_state"] == "clean" || build["source_state"] == "dirty", "actual source state");
    check(info["capabilities"].toObject()["embedded_vpn"].toBool() == !info["test_driver"].toBool(),
          "protocol capability identifies production and fixture drivers");
    check(metadata.front() == 0x5a && metadata.back() == 0x5a, "metadata bounds");
#ifdef ABI_FIXTURE
    check(info["test_driver"].toBool(), "fixture build must identify itself");
    authentication(api);
    return 0;
#else
    check(!info["test_driver"].toBool(true), "production library must exclude the fixture driver");
#endif
    uint64_t invalid = 99;
    check(api.jc_session_create(JC_ABI_VERSION + 1, &invalid) == JC_ABI_MISMATCH && invalid == 0, "create ABI mismatch");
    check(api.jc_session_create(JC_ABI_VERSION, nullptr) == JC_INVALID_ARGUMENT, "missing handle pointer");
    QTcpServer reserve;
    check(reserve.listen(QHostAddress::LocalHost, 0), "reserve loopback failure endpoint");
    const auto failedPort = reserve.serverPort();
    reserve.close();
    const auto configBytes = QJsonDocument(QJsonObject{{"schema_version", 1},
        {"server", QJsonObject{{"host", "127.0.0.1"}, {"port", failedPort}}},
        {"auth", QJsonObject{{"password", "private-password"}}}}).toJson(QJsonDocument::Compact);
    const std::string config(configBytes.constData(), static_cast<size_t>(configBytes.size()));
    for (int round = 0; round < 257; ++round) {
        uint64_t handle = 0, generation = 99;
        check(api.jc_session_create(JC_ABI_VERSION, &handle) == JC_OK && handle != 0, "create");
        check(api.jc_session_read(handle, 0, nullptr, 0, &length) == JC_TIMEOUT && length == 0, "idle poll");
        check(api.jc_session_start(handle, nullptr, 1, &generation) == JC_INVALID_ARGUMENT && generation == 0, "null input");
        check(api.jc_session_start(handle, reinterpret_cast<const uint8_t *>(config.data()), JC_MAX_INPUT + 1, &generation) ==
              JC_INVALID_ARGUMENT && generation == 0, "input size bound");
        std::vector<uint8_t> input(config.begin(), config.end());
        check(api.jc_session_start(handle, input.data(), static_cast<uint32_t>(input.size()), &generation) == JC_OK &&
              generation == 1, "async start accepted");
        std::fill(input.begin(), input.end(), 0);
        check(api.jc_session_stop(handle, 1000) == JC_OK, "cancel production invocation");
        uint64_t busyGeneration = 99;
        check(api.jc_session_start(handle, reinterpret_cast<const uint8_t *>(config.data()), static_cast<uint32_t>(config.size()),
              &busyGeneration) == JC_BUSY && busyGeneration == 0, "unread events prevent restart");
        auto starting = read(api, handle);
        check(starting["type"] == "state" && starting["state"] == "starting" &&
              starting["generation"] == "1" && starting["sequence"] == "1", "starting event");
        auto terminal = read(api, handle);
        while (terminal["type"] == "diagnostic") terminal = read(api, handle);
        check(terminal["type"] == "terminal" &&
              (terminal["status"].toInt() == JC_INTERNAL || terminal["status"].toInt() == JC_CANCELLED) &&
              terminal["generation"] == "1", "production failure or cancellation completes cleanup");
        check(api.jc_session_read(handle, 0, nullptr, 0, &length) == JC_END && length == 0, "end of event stream");
        const std::string response = R"({"schema_version":1,"generation":"1","request_id":"1","action":"cancel"})";
        check(api.jc_session_respond(handle, reinterpret_cast<const uint8_t *>(response.data()),
              static_cast<uint32_t>(response.size())) == JC_STALE_REQUEST, "no invented authentication request");
        check(api.jc_session_stop(handle, 1000) == JC_OK && api.jc_session_stop(handle, 1000) == JC_OK, "idempotent stop");
        check(api.jc_session_destroy(handle, 1000) == JC_OK && api.jc_session_destroy(handle, 1000) == JC_OK, "idempotent destroy");
        check(api.jc_session_read(handle, 0, nullptr, 0, &length) == JC_INVALID_HANDLE, "stale handle");
    }
    check(api.jc_session_destroy(0, 0) == JC_INVALID_HANDLE, "invalid zero handle");
    int finished = 0, ticks = 0;
    bool pageLoaded = false;
    std::vector<std::unique_ptr<QThread>> workers;
    const auto finish = [&] {
        if (finished == 4 && pageLoaded) {
            check(ticks > 0, "GUI event loop heartbeat");
            application.quit();
        }
    };
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, &application, [&] { ++ticks; });
    heartbeat.start(1);
    QTimer::singleShot(45000, &application, [] { check(false, "ABI/GUI coexistence timed out"); });
    for (int i = 0; i < 4; ++i) {
        workers.emplace_back(QThread::create([&] {
            check(QThread::currentThread() != application.thread(), "ABI worker is not GUI thread");
            for (int round = 0; round < 64; ++round) {
                uint64_t h = 0;
                check(api.jc_session_create(JC_ABI_VERSION, &h) == JC_OK, "concurrent create");
                check(api.jc_session_stop(h, 1000) == JC_OK, "concurrent idle stop");
                check(api.jc_session_destroy(h, 1000) == JC_OK, "concurrent destroy");
            }
        }));
        QObject::connect(workers.back().get(), &QThread::finished, &application, [&] { ++finished; finish(); });
        workers.back()->start();
    }
    QWebEngineView view;
    QObject::connect(&view, &QWebEngineView::loadFinished, &application, [&](bool ok) {
        check(ok, "WebEngine page load");
        view.page()->runJavaScript("document.title", [&](const QVariant &value) {
            check(value.toString() == "JustConnect 42", "WebEngine JavaScript");
            pageLoaded = true;
            finish();
        });
    });
    view.setHtml("<!doctype html><title>JustConnect</title><script>document.title += ' ' + (6 * 7);</script>");
    const int result = application.exec();
    for (auto &worker : workers) worker->wait();
    std::cout << "PASS: production C ABI v1, provenance, 257 lifecycles, buffers, four QThreads, "
                 "WebEngine JavaScript, heartbeat=" << ticks << '\n';
    return result;
}
