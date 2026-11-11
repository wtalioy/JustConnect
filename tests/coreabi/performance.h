#pragma once
#include <QElapsedTimer>
#include <QUdpSocket>
#ifdef Q_OS_WIN
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

static QJsonObject resources() {
#ifdef Q_OS_WIN
    FILETIME created, exited, kernel, user;
    PROCESS_MEMORY_COUNTERS memory{};
    check(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) &&
          K32GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof(memory)), "process resource counters");
    const auto ticks = [](FILETIME t) { return (quint64(t.dwHighDateTime) << 32) | t.dwLowDateTime; };
    return {{"cpu_ms", double(ticks(kernel) + ticks(user)) / 10000}, {"peak_rss_bytes", double(memory.PeakWorkingSetSize)}};
#else
    rusage usage{};
    check(getrusage(RUSAGE_SELF, &usage) == 0, "process resource counters");
    const auto ms = [](timeval t) { return double(t.tv_sec) * 1000 + double(t.tv_usec) / 1000; };
#ifdef Q_OS_DARWIN
    constexpr double rssUnit = 1;
#else
    constexpr double rssUnit = 1024;
#endif
    return {{"cpu_ms", ms(usage.ru_utime) + ms(usage.ru_stime)}, {"peak_rss_bytes", double(usage.ru_maxrss) * rssUnit}};
#endif
}

// One outstanding echo measures application payload goodput, not link capacity.
template<class Echo> static QJsonObject traffic(Echo echo, int bytes, int count) {
    QJsonArray latency;
    for (int i = 0; i < 16; ++i) {
        QElapsedTimer timer; timer.start();
        echo(QByteArray(32, char(i)));
        latency.append(double(timer.nsecsElapsed()) / 1e6);
    }
    QElapsedTimer timer; timer.start();
    for (int i = 0; i < count; ++i) echo(QByteArray(bytes, char(i)));
    const double elapsed = double(timer.nsecsElapsed()) / 1e6;
    check(elapsed > 0, "positive transfer duration");
    return {{"rtt_ms", latency}, {"payload_bytes", bytes * count}, {"elapsed_ms", elapsed},
            {"mib_per_s", double(bytes) * count / 1048576 / (elapsed / 1000)}};
}

static void performance(API &api, const QByteArray &config) {
    uint32_t length = 0;
    check(api.jc_build_info(JC_ABI_VERSION, nullptr, 0, &length) == JC_BUFFER_TOO_SMALL, "baseline metadata length");
    std::vector<uint8_t> metadata(length + 2, 0x5a);
    check(api.jc_build_info(JC_ABI_VERSION, metadata.data() + 1, length, &length) == JC_OK, "baseline metadata");
    const auto info = json(metadata, length);
    check(!info["test_driver"].toBool(true) && info["capabilities"].toObject()["embedded_vpn"].toBool(), "baseline uses production core");
    std::cout << "BASELINE_READY" << std::endl;
    QElapsedTimer total; total.start();
    QJsonObject report{{"core", info}, {"qt_version", qVersion()}};
    QJsonArray connectTimes, stopTimes, rss;
    const auto listeners = QJsonDocument::fromJson(config).object()["listeners"].toObject();
    uint64_t handle = 0, generation = 0;
    check(api.jc_session_create(JC_ABI_VERSION, &handle) == JC_OK, "baseline create");
    const auto start = [&] {
        check(api.jc_session_start(handle, reinterpret_cast<const uint8_t *>(config.constData()),
              static_cast<uint32_t>(config.size()), &generation) == JC_OK, "baseline start");
        check(protocolEvent(api, handle)["state"] == "starting", "baseline starting");
        auto challenge = protocolEvent(api, handle);
        check(challenge["type"] == "authentication" && challenge["challenge"].toObject()["kind"] == "sms", "baseline actual SMS challenge");
        return challenge;
    };
    const auto stop = [&] {
        QElapsedTimer timer; timer.start();
        check(api.jc_session_stop(handle, 5000) == JC_OK, "baseline bounded stop");
        const auto terminal = protocolEvent(api, handle);
        check(terminal["type"] == "terminal" && terminal["status"].toInt() == JC_CANCELLED, "baseline cancelled terminal");
        const auto elapsed = double(timer.nsecsElapsed()) / 1e6;
        for (const auto name : {"socks", "http"}) {
            const auto address = listeners[name].toString();
            QTcpServer probe;
            check(probe.listen(QHostAddress::LocalHost, address.mid(address.lastIndexOf(':') + 1).toUShort()), "baseline listener released");
        }
        return elapsed;
    };
    for (int round = 0; round < 20; ++round) {
        QElapsedTimer timer; timer.start();
        auto challenge = start();
        auto response = QJsonDocument(QJsonObject{{"schema_version", 1}, {"generation", QString::number(generation)},
            {"request_id", challenge["request_id"]}, {"action", "submit"}, {"code", "fixture-code"}}).toJson(QJsonDocument::Compact);
        check(api.jc_session_respond(handle, reinterpret_cast<const uint8_t *>(response.constData()),
              static_cast<uint32_t>(response.size())) == JC_OK, "baseline SMS response");
        check(protocolEvent(api, handle)["state"] == "ready", "baseline authenticated ready");
        check(generation == uint64_t(round + 1), "baseline reconnect generation");
        connectTimes.append(double(timer.nsecsElapsed()) / 1e6);
        if (round == 0) {
            const double cpu = resources()["cpu_ms"].toDouble();
            QElapsedTimer idle; idle.start(); QThread::msleep(200);
            report["idle_cpu_ms"] = resources()["cpu_ms"].toDouble() - cpu;
            report["idle_wall_ms"] = double(idle.nsecsElapsed()) / 1e6;
            QTcpSocket tcp;
            ProxyCheck::openSocks(tcp, listeners["socks"].toString());
            report["tcp"] = traffic([&](const QByteArray &payload) {
                check(tcp.write(payload) == payload.size() && (tcp.bytesToWrite() == 0 || tcp.waitForBytesWritten(5000)), "baseline TCP write");
                check(ProxyCheck::receive(tcp, payload.size()) == payload, "baseline actual TCP echo");
            }, 65536, 32);
            QTcpSocket control;
            const auto relay = ProxyCheck::openSocks(control, listeners["socks"].toString(), true);
            const auto port = (quint8(relay[8]) << 8) | quint8(relay[9]);
            QUdpSocket udp;
            check(udp.bind(QHostAddress(QHostAddress::LocalHost), quint16(0)), "baseline UDP bind");
            const auto destination = QByteArray::fromHex("00000001c000020a0050");
            report["udp"] = traffic([&](const QByteArray &payload) {
                const auto packet = destination + payload;
                check(udp.writeDatagram(packet, QHostAddress::LocalHost, port) == packet.size(), "baseline UDP send");
                check(udp.hasPendingDatagrams() || udp.waitForReadyRead(5000), "baseline UDP receive deadline");
                QByteArray result(udp.pendingDatagramSize(), '\0');
                QHostAddress peer; quint16 peerPort = 0;
                check(udp.readDatagram(result.data(), result.size(), &peer, &peerPort) == result.size() &&
                      peer == QHostAddress::LocalHost && peerPort == port && result == packet, "baseline actual L3 UDP echo");
            }, 1200, 128);
        }
        stopTimes.append(stop());
        if (round % 5 == 4) rss.append(resources()["peak_rss_bytes"]);
    }
    start();
    report["authentication_cancel_ms"] = stop();
    check(api.jc_session_destroy(handle, 1000) == JC_OK, "baseline destroy");
    report["connect_ms"] = connectTimes; report["stop_ms"] = stopTimes;
    report["reconnect_peak_rss_bytes"] = rss;
    report["resources"] = resources(); report["wall_ms"] = double(total.nsecsElapsed()) / 1e6;
    std::cout << QJsonDocument(report).toJson(QJsonDocument::Compact).constData() << std::endl;
}
