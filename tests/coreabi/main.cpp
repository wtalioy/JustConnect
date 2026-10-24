#include "justconnect.h"
#include "proxycheck.h"
#include <QApplication>
#include <QDateTime>
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
#define ABI_FUNCTIONS(X) X(jc_abi_version) X(jc_build_info) X(jc_network_snapshot) X(jc_config_validate) X(jc_session_create) X(jc_session_start) \
    X(jc_session_read) X(jc_session_respond) X(jc_session_update_policy) X(jc_session_resources) X(jc_session_attach_tun) X(jc_session_attach_tun_dns) X(jc_session_ack_dns_routes) X(jc_session_stop) X(jc_session_destroy)
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

static void networkSnapshot(API &api) {
    uint32_t length = 99;
    check(api.jc_network_snapshot(99, nullptr, 0, &length) == JC_ABI_MISMATCH && length == 0, "network snapshot version boundary");
    std::vector<uint8_t> bytes(JC_MAX_OUTPUT + 2, 0x5a);
    check(api.jc_network_snapshot(JC_ABI_VERSION, bytes.data() + 1, JC_MAX_OUTPUT, &length) == JC_OK,
        "native read-only network snapshot through real C ABI");
    const auto snapshot = json(bytes,length);
    const auto network = snapshot["network"].toObject();
    check(!network["interfaces"].toArray().isEmpty() && !network["routes"].toArray().isEmpty()
        && QDateTime::fromString(snapshot["observed_at"].toString(),Qt::ISODateWithMs).isValid(), "actual interfaces, routes and observation time");
    check(bytes.front() == 0x5a && bytes.back() == 0x5a, "network snapshot output bounds");
    if (network["os"] == "linux") {
        bool local = false;
        for (const auto &value : network["policy_rules"].toArray()) {
            const auto rule = value.toObject();
            local |= rule["family"] == 2 && rule["table"] == 255 && rule["action"] == 1 && rule["attributes"].isArray();
        }
        check(local, "native Linux policy rules through actual C ABI");
    } else check(network["policy_rules"].isNull(), "unavailable native policy rules remain explicit");
    std::cout << "PASS: native read-only interface and route snapshot through C ABI\n";
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
    auto updatePolicy = [&](uint64_t gen, const char *revision) {
        auto bytes = QJsonDocument(QJsonObject{{"schema_version",1},{"generation",QString::number(gen)},
            {"revision",revision},{"protected",QJsonArray{"192.0.2.0/24"}},{"campus",QJsonArray{"192.0.2.10"}},
            {"protected_names",QJsonArray{QJsonObject{{"kind","suffix"},{"value","mesh.test"}}}},
            {"campus_names",QJsonArray{"vpn.mesh.test"}}}).toJson(QJsonDocument::Compact);
        uint64_t applied = 99;
        const auto status = api.jc_session_update_policy(h, reinterpret_cast<const uint8_t *>(bytes.constData()), uint32_t(bytes.size()), &applied);
        check(applied == (status == JC_OK ? gen : 0), "policy generation output zeroed on error");
        bytes.fill('\0');
        return status;
    };
    uint64_t applied = 99;
    check(api.jc_session_update_policy(h, nullptr, 1, &applied) == JC_INVALID_ARGUMENT && applied == 0, "policy input pointer boundary");
    check(api.jc_session_update_policy(h, nullptr, 0, nullptr) == JC_INVALID_ARGUMENT, "policy output pointer boundary");
    check(updatePolicy(generation, "18446744073709551615") == JC_OK, "full-width string policy revision");
    check(updatePolicy(generation, "18446744073709551615") == JC_STALE_REQUEST, "duplicate policy revision rejected");
    check(updatePolicy(generation, "1") == JC_STALE_REQUEST, "out-of-order policy rejected");
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
    check(updatePolicy(generation, "18446744073709551615") == JC_STALE_REQUEST, "stopped session rejects policy updates");
    reader.join();
    check(blockedStatus == JC_CANCELLED || blockedStatus == JC_BUFFER_TOO_SMALL, "blocked host reader woke");
    check(read(api, h)["status"].toInt() == JC_CANCELLED, "single cancellation terminal");
    start();
    check(generation == 2, "restart generation increment");
    check(updatePolicy(generation - 1, "2") == JC_STALE_REQUEST, "old policy generation rejected after restart");
    check(updatePolicy(generation, "1") == JC_OK, "policy revision resets only for a new session");
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
    while (event["type"] == "diagnostic" || event["type"] == "observation") event = read(api, handle);
    return event;
}

static void nativeProtocol(API &api, const QByteArray &input) {
    auto config = QJsonDocument::fromJson(input).object();
    config["authentication_cache"] = QJsonObject{{"enabled",true}};
    uint64_t handle = 0, generation = 0;
    check(api.jc_session_create(JC_ABI_VERSION, &handle) == JC_OK, "native protocol create");
    const auto start = [&] {
        if (config["operation"] == "auth_methods") config.remove("protection");
        else config["protection"] = QJsonObject{{"protected", QJsonArray{"192.0.2.0/24"}}, {"campus", QJsonArray{}}};
        auto bytes = QJsonDocument(config).toJson(QJsonDocument::Compact);
        check(api.jc_session_start(handle, reinterpret_cast<const uint8_t *>(bytes.constData()),
              static_cast<uint32_t>(bytes.size()), &generation) == JC_OK, "native protocol start");
        bytes.fill('\0');
        check(protocolEvent(api, handle)["state"] == "starting", "native protocol starting");
    };
    start();
    auto challenge = protocolEvent(api, handle);
    check(challenge["type"] == "authentication" && challenge["challenge"].toObject()["kind"] == "sms", "gateway SMS challenge");
    uint32_t pendingResourceLength=99;
    check(api.jc_session_resources(handle,generation,nullptr,0,&pendingResourceLength)==JC_BUSY && pendingResourceLength==0,
        "campus resources remain unavailable while authentication is pending");
    auto response = QJsonDocument(QJsonObject{{"schema_version", 1}, {"generation", QString::number(generation)},
        {"request_id", challenge["request_id"]}, {"action", "submit"}, {"code", "fixture-code"}}).toJson(QJsonDocument::Compact);
    check(api.jc_session_respond(handle, reinterpret_cast<const uint8_t *>(response.constData()),
          static_cast<uint32_t>(response.size())) == JC_OK, "native gateway SMS response");
    response.fill('\0');
    challenge=protocolEvent(api,handle);
    check(challenge["type"]=="authentication" && challenge["challenge"].toObject()["kind"]=="trusted_device","real ABI device confirmation");
    response=QJsonDocument(QJsonObject{{"schema_version",1},{"generation",QString::number(generation)},
        {"request_id",challenge["request_id"]},{"action","confirm"}}).toJson(QJsonDocument::Compact);
    check(api.jc_session_respond(handle,reinterpret_cast<const uint8_t *>(response.constData()),static_cast<uint32_t>(response.size()))==JC_OK,"explicit ABI device confirmation");
    response.fill('\0');
    const auto cacheEvent=protocolEvent(api,handle);
    const auto cache=cacheEvent["cache"].toObject();
    check(cacheEvent["type"]=="authentication_cache" && cacheEvent["action"]=="save"
        && cache["account"]=="fixture-user" && !cache["data"].toString().isEmpty(),"real C ABI bound cache output");
    check(protocolEvent(api, handle)["state"] == "ready", "real protocol ready");
    std::vector<uint8_t> resourceBytes(JC_MAX_OUTPUT+2,0x5a);
    uint32_t resourceLength=0;
    check(api.jc_session_resources(handle,generation,nullptr,0,&resourceLength)==JC_BUFFER_TOO_SMALL && resourceLength>0,
        "campus resource size query is non-destructive");
    check(api.jc_session_resources(handle,generation+1,resourceBytes.data()+1,JC_MAX_OUTPUT,&resourceLength)==JC_STALE_REQUEST
        && resourceLength==0,"real C ABI rejects resource reads for another session generation");
    check(api.jc_session_resources(handle,generation,resourceBytes.data()+1,JC_MAX_OUTPUT,&resourceLength)==JC_OK
        && resourceBytes.front()==0x5a && resourceBytes.back()==0x5a,"real C ABI bounded campus resource snapshot");
    const auto resources=json(resourceBytes,resourceLength);
    check(resources["generation"]==QString::number(generation)
        && !resources["resources"].toObject()["ip_resources"].toArray().isEmpty()
        && resources["resources"].toObject()["domain_resources"].toObject().contains("campus.test"),"actual protocol resources retain their generation and domain permissions");
    auto policy = QJsonDocument(QJsonObject{{"schema_version",1},{"generation",QString::number(generation)},
        {"revision","1"},{"protected",QJsonArray{"192.0.2.0/24"}},{"campus",QJsonArray{"192.0.2.10"}}}).toJson(QJsonDocument::Compact);
    uint64_t applied = 0;
    check(api.jc_session_update_policy(handle,reinterpret_cast<const uint8_t *>(policy.constData()),uint32_t(policy.size()),&applied)==JC_OK
        && applied==generation,"formal session accepts explicit campus choice before real SOCKS/HTTP traffic");
    ProxyCheck::exercise(config["listeners"].toObject(), [&] {
    check(api.jc_session_stop(handle, 5000) == JC_OK && api.jc_session_stop(handle, 1000) == JC_OK, "native protocol idempotent stop");
    resourceLength=99;
    check(api.jc_session_resources(handle,generation,nullptr,0,&resourceLength)==JC_STALE_REQUEST && resourceLength==0,
        "stopped native protocol cannot expose its previous resources");
    auto terminal = protocolEvent(api, handle);
    check(terminal["type"] == "terminal" && terminal["status"].toInt() == JC_CANCELLED, "native protocol stopped terminal");
    });
    config["authentication_cache"]=QJsonObject{{"enabled",true},{"account",cache["account"]},{"data",cache["data"]}};
    start();
    const auto restored=protocolEvent(api,handle);
    check(restored["type"]=="authentication_cache" && restored["action"]=="save"
        && restored["cache"].toObject()["account"]=="fixture-user","real C ABI restores cache without a second challenge");
    check(protocolEvent(api,handle)["state"]=="ready","restored protocol ready");
    check(api.jc_session_stop(handle,5000)==JC_OK,"restored native protocol stop");
    check(protocolEvent(api,handle)["status"].toInt()==JC_CANCELLED,"restored protocol terminal");
    std::cout<<"PASS: native cache restoration\n";
    config.remove("authentication_cache");
    config["operation"] = "auth_methods";
    start();
    check(generation == 3, "native restart generation");
    auto methods = protocolEvent(api, handle);
    check(methods["type"] == "auth_methods" && !methods["methods"].toArray().isEmpty(), "real authentication method query");
    const auto selected=methods["methods"].toArray().first().toObject();
    check(selected["auth_id"]=="fixture-primary" && selected["sub_type"]=="sms", "C ABI retains actual method identity");
    check(protocolEvent(api, handle)["status"].toInt() == JC_OK, "query terminal");
    check(api.jc_session_destroy(handle, 1000) == JC_OK && api.jc_session_destroy(handle, 1000) == JC_OK, "native protocol destroy");
    std::cout << "PASS: native protocol session, SMS, SOCKS/HTTP tunnel payloads, active stop and query restart\n";
}

#include "performance.h"
#include "tun.h"

int main(int argc, char **argv) {
    QApplication application(argc, argv);
    API api;
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    if (argc == 4 && QByteArray(argv[1]) == "--tun-gateway") {
        bool valid = false;
        const int descriptor = QByteArray(argv[3]).toInt(&valid);
        check(valid && descriptor >= 3, "inherited native TUN fd");
        const int flags = ::fcntl(descriptor, F_GETFD);
        check(flags >= 0 && ::fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0, "native host protects inherited fd across exec");
        nativeTUNProtocol(api, QByteArray(argv[2]), descriptor); return 0;
    }
#endif
    if (argc == 3 && QByteArray(argv[1]) == "--gateway") { nativeProtocol(api, QByteArray(argv[2])); return 0; }
    if (argc == 3 && QByteArray(argv[1]) == "--baseline") { performance(api, QByteArray(argv[2])); return 0; }
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
    check(info["capabilities"].toObject()["policy_update"].toBool(), "policy update capability matches the loaded export");
    check(info["capabilities"].toObject()["initial_protection"].toBool(), "initial protection capability matches validated start input");
    check(info["capabilities"].toObject()["name_protection"].toBool(), "name protection capability matches validated policy input");
    check(info["capabilities"].toObject()["network_snapshot"].toBool(), "native network snapshot capability");
    check(info["capabilities"].toObject()["resource_snapshot"].toBool() == !info["test_driver"].toBool(), "campus resource capability requires the protocol backend");
#if (defined(Q_OS_LINUX) || defined(Q_OS_MACOS)) && !defined(ABI_FIXTURE)
    check(info["capabilities"].toObject()["raw_ipv4_tun_fd"].toBool(), "native fd capability requires the protocol backend");
    check(api.jc_session_attach_tun(0, 1, -1, 1400) == JC_INVALID_ARGUMENT, "invalid borrowed fd is rejected");
    check(api.jc_session_attach_tun_dns(0, 1, -1, 1400) == JC_INVALID_ARGUMENT, "DNS-publishing attach retains fd guards");
    check(api.jc_session_ack_dns_routes(0, 1, 1, 2) == JC_INVALID_ARGUMENT, "DNS publication result is a strict boolean");
    check(api.jc_session_ack_dns_routes(0, 1, 1, 1) == JC_INVALID_HANDLE, "DNS publication acknowledgement validates handle");
#else
    check(!info["capabilities"].toObject()["raw_ipv4_tun_fd"].toBool(), "unsupported platform/driver cannot advertise raw fd attachment");
    check(api.jc_session_attach_tun(0, 1, -1, 1400) == JC_UNSUPPORTED, "unsupported raw fd attachment is explicit");
    check(api.jc_session_attach_tun_dns(0, 1, -1, 1400) == JC_UNSUPPORTED &&
          api.jc_session_ack_dns_routes(0, 1, 1, 1) == JC_UNSUPPORTED, "unsupported DNS publication is explicit");
#endif
    networkSnapshot(api);
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
    check(reserve.listen(QHostAddress::LocalHost, 0), "reserve cancellable loopback endpoint");
    const auto pendingPort = reserve.serverPort();
    const auto configBytes = QJsonDocument(QJsonObject{{"schema_version", 1},
        {"server", QJsonObject{{"host", "127.0.0.1"}, {"port", pendingPort}}},
        {"auth", QJsonObject{{"password", "private-password"}}}}).toJson(QJsonDocument::Compact);
    const std::string config(configBytes.constData(), static_cast<size_t>(configBytes.size()));
    const auto *configInput = reinterpret_cast<const uint8_t *>(config.data());
    check(api.jc_config_validate(JC_ABI_VERSION + 1, configInput, uint32_t(config.size())) == JC_ABI_MISMATCH, "validate ABI mismatch");
    check(api.jc_config_validate(JC_ABI_VERSION, nullptr, 1) == JC_INVALID_ARGUMENT, "validate null input");
    check(api.jc_config_validate(JC_ABI_VERSION, configInput, JC_MAX_INPUT + 1) == JC_INVALID_ARGUMENT, "validate input size limit");
    const std::string invalidConfig = R"({"schema_version":1,"server":{"host":"localhost","port":443},"extra_arguments":"-foo"})";
    check(api.jc_config_validate(JC_ABI_VERSION, reinterpret_cast<const uint8_t *>(invalidConfig.data()), uint32_t(invalidConfig.size())) == JC_INVALID_ARGUMENT, "validate rejects unknown fields");
    auto protectedConfig = QJsonDocument::fromJson(QByteArray::fromStdString(config)).object();
    const QJsonArray originalNames{QJsonObject{{"kind", "suffix"}, {"value", "mesh.test"}}};
    protectedConfig["protection"] = QJsonObject{{"protected", QJsonArray{"192.0.2.0/24"}}, {"campus", QJsonArray{}},
        {"protected_names", originalNames}, {"campus_names", QJsonArray{"vpn.mesh.test"}}};
    auto protectedBytes = QJsonDocument(protectedConfig).toJson(QJsonDocument::Compact);
    check(api.jc_config_validate(JC_ABI_VERSION, reinterpret_cast<const uint8_t *>(protectedBytes.constData()), uint32_t(protectedBytes.size())) == JC_OK,
        "native validation supports initial protection advertised by the loaded library");
    protectedConfig["protection"] = QJsonObject{{"protected", QJsonArray{}}, {"campus", QJsonArray{}},
        {"protected_names", QJsonArray{QJsonObject{{"kind", "suffix"}, {"value", "."}}}}};
    protectedBytes = QJsonDocument(protectedConfig).toJson(QJsonDocument::Compact);
    check(api.jc_config_validate(JC_ABI_VERSION, reinterpret_cast<const uint8_t *>(protectedBytes.constData()), uint32_t(protectedBytes.size())) == JC_INVALID_ARGUMENT,
        "native name protection rejects a root namespace before networking");
    protectedConfig["protection"] = QJsonObject{{"protected", QJsonArray{"192.0.2.1/24"}}, {"campus", QJsonArray{}}};
    protectedBytes = QJsonDocument(protectedConfig).toJson(QJsonDocument::Compact);
    check(api.jc_config_validate(JC_ABI_VERSION, reinterpret_cast<const uint8_t *>(protectedBytes.constData()), uint32_t(protectedBytes.size())) == JC_INVALID_ARGUMENT,
        "native initial protection rejects noncanonical prefixes before networking");
    std::vector<uint64_t> idleHandles(JC_MAX_HANDLES);
    for (auto &h : idleHandles) check(api.jc_session_create(JC_ABI_VERSION, &h) == JC_OK, "reserve idle handles before pure validation");
    for (int i = 0; i < 32; ++i)
        check(api.jc_config_validate(JC_ABI_VERSION, configInput, uint32_t(config.size())) == JC_OK, "validation needs no session or active slot");
    for (auto h : idleHandles) check(api.jc_session_destroy(h, 1000) == JC_OK, "validation leaves idle handles intact");
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
        while (terminal["type"] == "diagnostic" || terminal["type"] == "observation") terminal = read(api, handle);
        check(terminal["type"] == "terminal" &&
              terminal["status"].toInt() == JC_CANCELLED &&
              terminal["generation"] == "1", "cancelled production invocation completes cleanup");
        check(api.jc_session_read(handle, 0, nullptr, 0, &length) == JC_END && length == 0, "end of event stream");
        const std::string response = R"({"schema_version":1,"generation":"1","request_id":"1","action":"cancel"})";
        check(api.jc_session_respond(handle, reinterpret_cast<const uint8_t *>(response.data()),
              static_cast<uint32_t>(response.size())) == JC_STALE_REQUEST, "no invented authentication request");
        check(api.jc_session_stop(handle, 1000) == JC_OK && api.jc_session_stop(handle, 1000) == JC_OK, "idempotent stop");
        check(api.jc_session_destroy(handle, 1000) == JC_OK && api.jc_session_destroy(handle, 1000) == JC_OK, "idempotent destroy");
        check(api.jc_session_read(handle, 0, nullptr, 0, &length) == JC_INVALID_HANDLE, "stale handle");
        while (reserve.hasPendingConnections() || reserve.waitForNewConnection(0)) delete reserve.nextPendingConnection();
    }
    reserve.close();
    uint64_t failedHandle = 0, failedGeneration = 0;
    check(api.jc_session_create(JC_ABI_VERSION, &failedHandle) == JC_OK, "create network failure session");
    check(api.jc_session_start(failedHandle, configInput, uint32_t(config.size()), &failedGeneration) == JC_OK, "start connection failure");
    auto failure = read(api, failedHandle);
    check(failure["type"] == "state" && failure["state"] == "starting", "network failure starts asynchronously");
    do { failure = read(api, failedHandle); } while (failure["type"] == "diagnostic" || failure["type"] == "observation");
    check(failure["type"] == "terminal" && failure["status"].toInt() == JC_NETWORK_FAILURE
          && failure["generation"].toString() == QString::number(failedGeneration), "connection refusal has its precise network failure status");
    check(api.jc_session_read(failedHandle, 0, nullptr, 0, &length) == JC_END, "network failure releases the event stream");
    check(api.jc_session_destroy(failedHandle, 1000) == JC_OK, "network failure releases the handle");
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
