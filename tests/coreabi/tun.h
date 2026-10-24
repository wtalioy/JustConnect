#pragma once

#ifdef Q_OS_LINUX
#include "tuntraffic.h"
#include <fcntl.h>
#include <unistd.h>

static void nativeTUNProtocol(API &api, const QByteArray &config, int descriptor)
{
    check(::getuid() != 0 && ::getuid() == ::geteuid(), "TUN data plane must run as the ordinary caller");
    const int retained = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
    check(retained >= 0, "retain caller-owned test descriptor across session restart");
    const int originalFlags = ::fcntl(retained, F_GETFL);
    check(originalFlags >= 0 && (originalFlags & O_NONBLOCK), "helper delivered nonblocking packet I/O");
    uint64_t handle = 0, generation = 0;
    check(api.jc_session_create(JC_ABI_VERSION, &handle) == JC_OK, "TUN protocol create");
    for (int round = 0; round < 2; ++round) {
        check(api.jc_session_start(handle, reinterpret_cast<const uint8_t *>(config.constData()), uint32_t(config.size()), &generation) == JC_OK,
              "TUN protocol start");
        check(protocolEvent(api, handle)["state"] == "starting", "TUN protocol starting");
        auto challenge = protocolEvent(api, handle);
        check(challenge["type"] == "authentication" && challenge["challenge"].toObject()["kind"] == "sms", "TUN gateway SMS challenge");
        check(api.jc_session_attach_tun(handle, generation, retained, 1400) == JC_BUSY, "TUN cannot attach before protocol readiness");
        auto response = QJsonDocument(QJsonObject{{"schema_version", 1}, {"generation", QString::number(generation)},
            {"request_id", challenge["request_id"]}, {"action", "submit"}, {"code", "fixture-code"}}).toJson(QJsonDocument::Compact);
        check(api.jc_session_respond(handle, reinterpret_cast<const uint8_t *>(response.constData()), uint32_t(response.size())) == JC_OK,
              "TUN gateway SMS response");
        check(protocolEvent(api, handle)["state"] == "ready", "TUN protocol ready");
        check(api.jc_session_attach_tun(handle, generation + 1, retained, 1400) == JC_STALE_REQUEST, "TUN fd is bound to the current generation");
        check(api.jc_session_attach_tun(handle, generation, retained, 1401) == JC_INVALID_ARGUMENT, "TUN MTU must match the kernel device");
        check(api.jc_session_attach_tun(handle, generation, retained, 1400) == JC_OK, "actual TUN fd accepted by formal C ABI");
        check(api.jc_session_attach_tun(handle, generation, retained, 1400) == JC_INVALID_ARGUMENT, "second TUN owner rejected");
        if (round == 0) { ::close(descriptor); descriptor = -1; }
        check(::fcntl(retained, F_GETFL) == originalFlags, "C ABI changed the borrowed descriptor flags");
        exerciseNativeTUNTraffic();
        check(api.jc_session_stop(handle, 5000) == JC_OK, "TUN stop joins blocked device I/O");
        auto terminal = protocolEvent(api, handle);
        check(terminal["type"] == "terminal" && terminal["status"].toInt() == JC_CANCELLED, "TUN stopped terminal");
        check(::fcntl(retained, F_GETFL) == originalFlags, "TUN shutdown closed or changed caller-owned fd");
        check(api.jc_session_attach_tun(handle, generation, retained, 1400) == JC_STALE_REQUEST, "stopped generation cannot consume the TUN fd");
    }
    check(api.jc_session_destroy(handle, 1000) == JC_OK, "TUN protocol destroy");
    ::close(retained);
    std::cout << "PASS: ordinary native TCP/UDP and empty datagrams through kernel TUN, formal C ABI, campus protocol, stop and restart\n";
}
#endif
