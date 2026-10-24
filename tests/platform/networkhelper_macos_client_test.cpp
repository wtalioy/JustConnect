#include "infrastructure/platform/macos/networkhelperclient.h"
#include "infrastructure/platform/macos/helperidentity.h"
#include "infrastructure/platform/macos/helpertransport.h"
#include "infrastructure/platform/macos/tunroutes.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QSocketNotifier>
#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static void report(const QJsonObject &value) { std::cout << QJsonDocument(value).toJson(QJsonDocument::Compact).constData() << std::endl; }
static const MacHelperConfiguration configuration{"198.18.0.1","198.18.0.2",1400,{"198.18.0.6/32"}};
static void packet(int device)
{
    check((::fcntl(device,F_GETFL)&O_NONBLOCK) && (::fcntl(device,F_GETFD)&FD_CLOEXEC),"Delivered fd is blocking or inheritable");
    const int socket = ::socket(AF_INET,SOCK_DGRAM,0); check(socket >= 0,"Create ordinary UDP socket");
    sockaddr_in destination{}; destination.sin_len = sizeof(destination); destination.sin_family = AF_INET;
    destination.sin_port = htons(39871); ::inet_pton(AF_INET,"198.18.0.6",&destination.sin_addr);
    const QByteArray content("JustConnect signed helper data path");
    const auto sent = ::sendto(socket,content.constData(),size_t(content.size()),0,reinterpret_cast<sockaddr *>(&destination),sizeof(destination));
    ::close(socket); check(sent == content.size(),"Ordinary UDP did not reach the owned device");
    pollfd readiness{device,POLLIN,0}; check(::poll(&readiness,1,3000) == 1,"Transferred utun received no real packet");
    char buffer[65536]{}; const auto count = ::read(device,buffer,sizeof(buffer));
    const auto bytes = count > 0 ? QByteArray(buffer,qsizetype(count)) : QByteArray{};
    const quint32 family = htonl(AF_INET);
    check(bytes.size() >= 32 && !std::memcmp(bytes.constData(),&family,4) && bytes.endsWith(content),"Received fd is not the configured native utun packet path");
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
    if (arguments.size() == 2 && arguments[1].startsWith("--wire-")) {
        const auto connection = xpc_connection_create_mach_service(MacHelperIdentifier,nullptr,XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
        check(connection,"Create native XPC connection"); xpc_connection_set_event_handler(connection,^(xpc_object_t) {}); xpc_connection_resume(connection);
        const auto request = macHelperApplyRequest(QUuid::createUuid(),QUuid::createUuid(),configuration);
        const auto message = macHelperMessage(request); const auto reply = xpc_connection_send_message_with_reply_sync(connection,message);
        if (arguments[1] == "--wire-untrusted") check(xpc_get_type(reply) == XPC_TYPE_ERROR,"Untrusted signed identity received a privileged reply");
        else {
            MacHelperIdentity identity(MacHelperAppIdentifier,MacHelperIdentifier); QJsonObject response; int descriptor = -1;
            check(identity.accepts(reply) && xpc_connection_get_euid(connection) == 0 && readMacHelperMessage(reply,response,&descriptor),"No authenticated root denial");
            const auto result = parseMacHelperResponse(response,request);
            check(result && result->status == PlatformOperationResult::Status::PermissionDenied && !result->mayHaveChanged && descriptor < 0,
                "Signed client without administrator right changed the network or received a device");
        }
        xpc_release(reply); xpc_release(message); xpc_connection_cancel(connection); xpc_release(connection);
        report({{"event","wire-denied"}}); return 0;
    }
    check(arguments.size() == 3 || arguments.size() == 4,"Invalid native client fixture arguments");
    const auto mode = arguments[1]; const auto owner = arguments.size() == 4 ? QUuid(arguments[3]) : QUuid::createUuid();
    const int authorizationDescriptor = arguments[2].toInt();
    auto provider = [authorizationDescriptor](AuthorizationRef *authorization) {
        AuthorizationExternalForm external{};
        if (::read(authorizationDescriptor,&external,sizeof(external)) != sizeof(external)) return OSStatus(errAuthorizationDenied);
        return AuthorizationCreateFromExternalForm(&external,authorization);
    };
    MacNetworkHelperClient client(nullptr,provider); int held = -1; QString interface; qint64 index = 0;
    QObject::connect(&client,&MacNetworkHelperClient::stateChanged,&app,[&](auto state) {
        if (mode == "--cancel" && state == MacNetworkHelperClient::State::Applying) QTimer::singleShot(0,&client,&MacNetworkHelperClient::cancel);
    });
    QObject::connect(&client,&MacNetworkHelperClient::finished,&app,[&](auto operation,auto result) {
        if (client.state() == MacNetworkHelperClient::State::Active) {
            check(result.succeeded() && operation == MacNetworkHelperClient::Operation::Apply,"Ordinary signed apply failed");
            interface = client.ownedDevice()["interface"].toString(); index = client.ownedDevice()["index"].toInteger(); held = ::fcntl(client.descriptor(),F_DUPFD_CLOEXEC,0);
            check(held >= 0,"Retain ordinary device reference"); packet(held);
            report({{"event","active"},{"owner",owner.toString(QUuid::WithoutBraces)},{"interface",interface}}); return;
        }
        if (client.state() == MacNetworkHelperClient::State::RecoveryRequired) return;
        check(client.state() == MacNetworkHelperClient::State::Idle
            && (result.succeeded() || (mode == "--cancel" && result.status == PlatformOperationResult::Status::Cancelled)),qPrintable(result.detail));
        if (held >= 0) {
            const auto routes = readMacRoutes(); check(routes.result.succeeded(),"Read routes after restoration");
            for (const auto &value : routes.rows) check(value.toObject()["prefix"] != "198.18.0.6/32" || value.toObject()["index"].toInteger() != index,
                "Capture persisted while the ordinary device fd remained open");
            ::close(held); held = -1;
        }
        report({{"event","restored"},{"owner",owner.toString(QUuid::WithoutBraces)}}); app.quit();
    });
    QObject::connect(&client,&MacNetworkHelperClient::ownershipLost,&app,[&](auto) {
        report({{"event","lost"},{"owner",owner.toString(QUuid::WithoutBraces)},{"interface",interface}});
    });
    QSocketNotifier input(STDIN_FILENO,QSocketNotifier::Read);
    QObject::connect(&input,&QSocketNotifier::activated,&app,[&] {
        char buffer[128]{}; const auto count = ::read(STDIN_FILENO,buffer,sizeof(buffer));
        if (count <= 0) std::_Exit(0);
        const QByteArray command(buffer,qsizetype(count));
        if (command.trimmed() == "restore") client.restore();
        else if (command.trimmed() == "exit") std::_Exit(0);
    });
    QTimer::singleShot(0,&app,[&] {
        if (mode == "--recover") client.recover(owner);
        else if (mode == "--cleanup") client.cleanupRestored(owner);
        else client.apply(owner,configuration);
    });
    QTimer::singleShot(60000,&app,[] { std::_Exit(4); });
    const int status = app.exec(); if (held >= 0) ::close(held); return status;
} catch (const std::exception &error) { std::cerr << error.what() << '\n';return 1; }
