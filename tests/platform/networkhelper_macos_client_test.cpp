#include "infrastructure/platform/macos/networkhelperclient.h"
#include "infrastructure/platform/macos/networkownership.h"
#include "infrastructure/platform/dnsroutepublisher.h"
#include "infrastructure/platform/macos/helperidentity.h"
#include "infrastructure/platform/macos/helpertransport.h"
#include "infrastructure/platform/macos/tunroutes.h"
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QJsonDocument>
#include <QSocketNotifier>
#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

class PublicationCore final : public CoreEngine
{
public:
    bool start(const ConnectionProfile &, Operation) override { return false; }
    void stop() override {}
    void respond(const QJsonObject &) override {}
    void acknowledgeDNSRoutes(const QString &generation,const QString &request,bool applied) override { acknowledged(generation,request,applied); }
    std::function<void(const QString &,const QString &,bool)> acknowledged;
};
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static void report(const QJsonObject &value) { std::cout << QJsonDocument(value).toJson(QJsonDocument::Compact).constData() << std::endl; }
static const MacHelperConfiguration configuration{"198.18.0.1","198.18.0.2",1400,{"198.18.0.6/32"},{"campus.justconnect-fixture.test"}};
static void checkOriginalView(const MacNetworkHelperClient &client)
{
    const auto configuration = client.ownedConfiguration(); check(configuration.has_value(),"Confirmed configuration for original view");
    const auto device = client.ownedDevice(), view = client.ownedNetwork();
    const auto filter = macOriginalNetworkView(client.owner(),*configuration,device,view); check(bool(filter),"Construct the confirmed native original view");
    const QJsonObject externalRoute{{"destination","192.0.2.99/32"},{"interface_index",device["index"]},{"flags",1},{"external",true}};
    QJsonArray routes{externalRoute};
    for (const auto &value : view["capture"].toObject()["routes"].toArray()) {
        const auto row = value.toObject()["applied"].toObject();
        routes.append(QJsonObject{{"destination",row["prefix"]},{"interface_index",row["index"]},{"flags",row["flags"]}});
    }
    const QJsonObject interface{{"name",device["interface"]},{"index",device["index"]},{"up",true},{"addresses",QJsonArray{configuration->address+"/32","192.0.2.99/32"}}};
    const QJsonObject network{{"interfaces",QJsonArray{interface}},{"routes",routes}};
    QJsonObject entries;
    const auto published = view["dns"].toObject();
    for (auto it=published.begin();it!=published.end();++it) if (it.key().endsWith("/DNS")) entries[it.key()] = it.value();
    const QString externalKey("State:/Network/Service/external/DNS");
    entries[externalKey] = QJsonObject{{"ServerAddresses",QJsonArray{"192.0.2.53"}}};
    const auto original = filter(network,QJsonObject{{"dynamic_store",entries}});
    check(original && original->first["routes"] == QJsonArray{externalRoute}
        && original->first["interfaces"].toArray().first().toObject()["addresses"] == QJsonArray{"192.0.2.99/32"}
        && original->second["dynamic_store"].toObject() == QJsonObject{{externalKey,entries[externalKey]}},
        "Original view removed external fields, addresses or resolver namespaces");
    for (auto it=entries.begin();it!=entries.end();++it) if (it.key()!=externalKey) it.value() = QJsonObject{{"ServerAddresses",QJsonArray{"192.0.2.54"}}};
    const auto changed = filter(network,QJsonObject{{"dynamic_store",entries}});
    check(changed && changed->second["dynamic_store"] == entries,"Original view hid externally changed DNS");
}
static void deliver(int control, int descriptor)
{
    char token = 'D'; iovec payload{&token,1};
    union { cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } ancillary{};
    msghdr message{}; message.msg_iov = &payload; message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes; message.msg_controllen = sizeof(ancillary.bytes);
    auto *item = CMSG_FIRSTHDR(&message); item->cmsg_level = SOL_SOCKET; item->cmsg_type = SCM_RIGHTS; item->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(item),&descriptor,sizeof(descriptor));
    check(::sendmsg(control,&message,0) == 1,"Deliver the ordinary test DNS descriptor");
}
static void packet(int device,const char *target = "198.18.0.6")
{
    check((::fcntl(device,F_GETFL)&O_NONBLOCK) && (::fcntl(device,F_GETFD)&FD_CLOEXEC),"Delivered fd is blocking or inheritable");
    const int socket = ::socket(AF_INET,SOCK_DGRAM,0); check(socket >= 0,"Create ordinary UDP socket");
    sockaddr_in destination{}; destination.sin_len = sizeof(destination); destination.sin_family = AF_INET;
    destination.sin_port = htons(39871); ::inet_pton(AF_INET,target,&destination.sin_addr);
    const QByteArray content("JustConnect signed helper data path");
    const auto sent = ::sendto(socket,content.constData(),size_t(content.size()),0,reinterpret_cast<sockaddr *>(&destination),sizeof(destination));
    ::close(socket); check(sent == content.size(),"Ordinary UDP did not reach the owned device");
    QDeadlineTimer deadline(3000);
    while (!deadline.hasExpired()) {
        pollfd readiness{device,POLLIN,0};
        if (::poll(&readiness,1,int(deadline.remainingTime())) == 0) break;
        char buffer[65536]{}; const auto count = ::read(device,buffer,sizeof(buffer));
        check(count > 0,"Read transferred native utun packet");
        const QByteArray bytes(buffer,qsizetype(count));
        // System DNS may already be probing this newly published interface.
        if (!bytes.endsWith(content)) continue;
        const quint32 family = htonl(AF_INET);
        check(bytes.size() >= 32 && !std::memcmp(bytes.constData(),&family,4),"Received fd is not the configured native utun packet path");
        return;
    }
    check(false,"Transferred utun did not receive the ordinary UDP payload");
}
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv); const auto arguments = app.arguments();
    check(::geteuid() != 0,"Client fixture must run as an ordinary account");
    if (arguments.size() == 2 && arguments[1] == "--unavailable") {
        MacNetworkHelperClient client; bool completed = false;
        QObject::connect(&client,&MacNetworkHelperClient::finished,&app,[&](auto,auto result) {
            check(result.status == PlatformOperationResult::Status::Unsupported && !result.mayHaveChanged,"Unsigned client reached network authorization"); completed = true;
        });
        client.apply(QUuid::createUuid(),configuration); check(completed,"Unsigned application did not report its deployment requirement"); return 0;
    }
    if (arguments.size() >= 2 && arguments[1].startsWith("--wire-")) {
        const bool extension = arguments[1] == "--wire-live-extend";
        const bool recover = arguments[1] == "--wire-foreign" || arguments[1] == "--wire-live" || extension;
        check(arguments.size() == (recover ? 3 : 2),"Invalid wire boundary arguments");
        const auto connection = xpc_connection_create_mach_service(MacHelperIdentifier,nullptr,XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
        check(connection,"Create native XPC connection"); xpc_connection_set_event_handler(connection,^(xpc_object_t) {}); xpc_connection_resume(connection);
        const auto request = extension ? macHelperExtendRequest(QUuid(arguments[2]),QUuid::createUuid(),{"198.18.0.8"})
            : recover ? macHelperRequest("recover",QUuid(arguments[2]),QUuid::createUuid())
            : macHelperApplyRequest(QUuid::createUuid(),QUuid::createUuid(),configuration);
        const AuthorizationExternalForm invalid{};
        const auto message = macHelperMessage(request,-1,arguments[1] == "--wire-invalid-auth" ? &invalid : nullptr);
        const auto reply = xpc_connection_send_message_with_reply_sync(connection,message);
        if (arguments[1] == "--wire-untrusted") check(xpc_get_type(reply) == XPC_TYPE_ERROR,"Untrusted signed identity received a privileged reply");
        else {
            MacHelperIdentity identity(MacHelperAppIdentifier,MacHelperIdentifier); QJsonObject response; int descriptor = -1;
            check(identity.accepts(reply) && xpc_connection_get_euid(connection) == 0 && readMacHelperMessage(reply,response,&descriptor),"No authenticated root denial");
            const auto result = parseMacHelperResponse(response,request);
            const auto expected = arguments[1] == "--wire-foreign" ? PlatformOperationResult::Status::Failed : PlatformOperationResult::Status::PermissionDenied;
            check(result && result->status == expected && result->mayHaveChanged == (arguments[1] == "--wire-foreign") && descriptor < 0,
                "Signed client without administrator right changed the network or received a device");
        }
        xpc_release(reply); xpc_release(message); xpc_connection_cancel(connection); xpc_release(connection);
        report({{"event","wire-denied"}}); return 0;
    }
    check(arguments.size() == 3 || arguments.size() == 4,"Invalid native client fixture arguments");
    const auto mode = arguments[1];
    const auto owner = arguments.size() == 4 && mode != "--dns" ? QUuid(arguments[3]) : QUuid::createUuid();
    const int authorizationDescriptor = arguments[2].toInt();
    auto provider = [authorizationDescriptor](AuthorizationRef *authorization) {
        AuthorizationExternalForm external{};
        if (::read(authorizationDescriptor,&external,sizeof(external)) != sizeof(external)) return OSStatus(errAuthorizationDenied);
        return AuthorizationCreateFromExternalForm(&external,authorization);
    };
    MacNetworkHelperClient client(nullptr,provider); int held = -1; QString interface; qint64 index = 0;
    PublicationCore core; DNSRoutePublisher<MacNetworkHelperClient> publisher(&core,&client);
    int publication = 0;
    core.acknowledged = [&](const QString &generation,const QString &request,bool applied) {
        if (mode == "--cancel-extend") {
            check(!applied,"Cancelled DNS publication was acknowledged as applied"); return;
        }
        check(generation == owner.toString(QUuid::WithoutBraces) && request == QString::number(publication) && applied,
            "Owned helper did not confirm the exact CoreEngine DNS publication");
        const auto configuration = client.ownedConfiguration();
        check(configuration && configuration->capturePrefixes.contains("198.18.0.7/32"),"Confirmed DNS address was not retained in client ownership");
        checkOriginalView(client); packet(held,"198.18.0.7");
        report({{"event","published"},{"owner",generation},{"request_id",request}});
    };
    QObject::connect(&client,&MacNetworkHelperClient::stateChanged,&app,[&](auto state) {
        if ((mode == "--cancel" && state == MacNetworkHelperClient::State::Applying)
            || (mode == "--cancel-extend" && state == MacNetworkHelperClient::State::Extending)) {
            report({{"event",mode == "--cancel" ? "applying" : "extending"},{"owner",owner.toString(QUuid::WithoutBraces)}});
            pollfd control{STDIN_FILENO,POLLIN,0}; char command[32]{};
            check(::poll(&control,1,30000) == 1 && ::read(STDIN_FILENO,command,sizeof(command)) > 0
                && QByteArray(command).trimmed() == "cancel","Parent did not confirm an actual applied cancellation point");
            client.cancel();
        }
    });
    QObject::connect(&client,&MacNetworkHelperClient::finished,&app,[&](auto operation,auto result) {
        if (operation == MacNetworkHelperClient::Operation::Extend && client.state() == MacNetworkHelperClient::State::Active) return;
        if (client.state() == MacNetworkHelperClient::State::Active) {
            check(result.succeeded() && operation == MacNetworkHelperClient::Operation::Apply,"Ordinary signed apply failed");
            interface = client.ownedDevice()["interface"].toString(); index = client.ownedDevice()["index"].toInteger(); held = ::fcntl(client.descriptor(),F_DUPFD_CLOEXEC,0);
            check(held >= 0,"Retain ordinary device reference"); checkOriginalView(client); packet(held);
            emit core.sessionStarted(owner.toString(QUuid::WithoutBraces));
            if (mode == "--dns") deliver(arguments[3].toInt(),held);
            report({{"event","active"},{"owner",owner.toString(QUuid::WithoutBraces)},{"interface",interface},
                {"peer",configuration.peer},{"dns_domains",QJsonArray::fromStringList(configuration.dnsDomains)}}); return;
        }
        if (client.state() == MacNetworkHelperClient::State::RecoveryRequired) return;
        check(client.state() == MacNetworkHelperClient::State::Idle
            && (result.succeeded() || ((mode == "--cancel" || mode == "--cancel-extend") && result.status == PlatformOperationResult::Status::Cancelled)),qPrintable(result.detail));
        if (held >= 0) {
            const auto routes = readMacRoutes(); check(routes.result.succeeded(),"Read routes after restoration");
            for (const auto &value : routes.rows) check((value.toObject()["prefix"] != "198.18.0.6/32" && value.toObject()["prefix"] != "198.18.0.7/32") || value.toObject()["index"].toInteger() != index,
                "Capture persisted while the ordinary device fd remained open");
            ::close(held); held = -1;
        }
        report({{"event","restored"},{"owner",owner.toString(QUuid::WithoutBraces)}}); app.quit();
    });
    QObject::connect(&client,&MacNetworkHelperClient::ownershipLost,&app,[&](auto result) {
        report({{"event","lost"},{"owner",owner.toString(QUuid::WithoutBraces)},{"interface",interface},{"detail",result.detail}});
    });
    QSocketNotifier input(STDIN_FILENO,QSocketNotifier::Read);
    QObject::connect(&input,&QSocketNotifier::activated,&app,[&] {
        char buffer[128]{}; const auto count = ::read(STDIN_FILENO,buffer,sizeof(buffer));
        if (count <= 0) std::_Exit(0);
        const QByteArray command(buffer,qsizetype(count));
        if (command.trimmed() == "publish") {
            ++publication;
            emit core.dnsRoutesRequired(QJsonObject{{"generation",owner.toString(QUuid::WithoutBraces)},{"request_id",QString::number(publication)},
                {"addresses",QJsonArray{"198.18.0.7","198.18.0.7","198.18.0.6"}}});
        }
        else if (command.trimmed() == "restore") client.restore();
        else if (command.trimmed() == "exit") std::_Exit(0);
    });
    QTimer::singleShot(0,&app,[&] {
        if (mode == "--recover") client.recover(owner);
        else if (mode == "--cleanup") client.cleanupRestored(owner);
        else client.apply(owner,configuration);
    });
    QTimer::singleShot(60000,&app,[] { std::_Exit(4); });
    const int status = app.exec();
    if (held >= 0) ::close(held);
    return status;
} catch (const std::exception &error) { std::cerr << error.what() << '\n';return 1; }
