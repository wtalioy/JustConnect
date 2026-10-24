#include "helperauthorization.h"
#include "helperidentity.h"
#include "helpertransport.h"
#include "networkhelperstate.h"
#include <QCoreApplication>
#include <QDebug>
#include <QJsonDocument>
#include <QMap>
#include <QScopeGuard>
#include <dispatch/dispatch.h>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
constexpr int MaximumOwners = 256;
struct Ownership {
    std::unique_ptr<MacNetworkHelperState> state;
    quint64 peer = 0;
};
QString key(uid_t uid, const QUuid &owner) { return QString::number(uid)+'/'+owner.toString(QUuid::WithoutBraces); }
QStringList children(int directory)
{
    QStringList result;
    const int copied = ::openat(directory,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (copied < 0) return result;
    auto *stream = ::fdopendir(copied);
    if (!stream) { ::close(copied); return result; }
    const auto close = qScopeGuard([&] { ::closedir(stream); });
    while (auto *entry = ::readdir(stream)) {
        if (!std::strcmp(entry->d_name,".") || !std::strcmp(entry->d_name,"..")) continue;
        if (result.size() >= MaximumOwners) break;
        result.append(QString::fromLatin1(entry->d_name));
    }
    return result;
}
class Server {
public:
    int directory = -1;
    MacHelperIdentity identity{MacHelperIdentifier,MacHelperAppIdentifier};
    QMap<QString,std::shared_ptr<Ownership>> owners;
    QMap<quint64,xpc_connection_t> peers;
    quint64 serial = 0;
    dispatch_queue_t queue = dispatch_queue_create(MacHelperIdentifier,DISPATCH_QUEUE_SERIAL);

    void discover()
    {
        for (const auto &account : children(directory)) {
            bool ok = false; const auto uid = account.toUInt(&ok);
            if (!ok || !uid || QString::number(uid) != account) continue;
            const int user = openPrivateNetworkDirectory(directory,account.toLatin1(),false);
            if (user < 0) continue;
            const auto names = children(user); ::close(user);
            for (const auto &name : names) {
                const QUuid owner(name);
                if (owner.isNull() || owner.toString(QUuid::WithoutBraces) != name || owners.contains(key(uid,owner))) continue;
                if (owners.size() >= MaximumOwners) return;
                auto entry = std::make_shared<Ownership>(); entry->state = std::make_unique<MacNetworkHelperState>();
                entry->state->open(directory,uid,owner,false);
                owners.insert(key(uid,owner),entry);
            }
        }
    }
    void recoverOrphans()
    {
        discover();
        for (const auto &entry : owners) if (!entry->peer && entry->state->phase() != "restored") entry->state->restore();
    }
    void disconnected(quint64 peer)
    {
        const auto connection = peers.take(peer);
        if (!connection) return;
        for (const auto &entry : owners) if (entry->peer == peer) { entry->peer = 0; entry->state->restore(); }
        xpc_connection_cancel(connection); xpc_release(connection);
    }
    void request(quint64 peer, xpc_object_t message)
    {
        const auto connection = peers.value(peer,nullptr);
        if (!connection || !identity.accepts(message)) { disconnected(peer); return; }
        const auto uid = xpc_connection_get_euid(connection);
        QJsonObject packet;
        if (!uid || uid == uid_t(-1) || !readMacHelperMessage(message,packet) || !validMacHelperRequest(packet)) { disconnected(peer); return; }
        const QUuid owner(packet["owner"].toString()); const auto operation = packet["operation"].toString();
        auto entry = owners.value(key(uid,owner));
        Result result; QJsonObject device; int descriptor = -1; QJsonArray receipts;
        if (operation == "probe") {
            discover();
            for (const auto &saved : owners) if (saved->state->uid() == uid)
                receipts.append(QJsonObject{{"owner",saved->state->owner().toString(QUuid::WithoutBraces)},{"phase",saved->state->phase()}});
        } else if (entry && entry->peer && entry->peer != peer) {
            result = {Status::PermissionDenied,"Connection ownership belongs to another live client.",false};
        } else if (operation == "apply") {
            const auto configuration = parseMacHelperApply(packet);
            if (!configuration) result = {Status::Failed,"Invalid bounded network configuration.",false};
            else if (!authorizedMacNetworkMessage(message)) result = {Status::PermissionDenied,"Network administrator authorization is required.",false};
            else if (entry || owners.size() >= MaximumOwners) result = {Status::Failed,"Existing or exhausted connection ownership is preserved.",false};
            else {
                entry = std::make_shared<Ownership>(); entry->state = std::make_unique<MacNetworkHelperState>();
                result = entry->state->open(directory,uid,owner,true);
                owners.insert(key(uid,owner),entry);
                if (result.succeeded()) result = entry->state->apply(*configuration);
                if (result.succeeded()) { entry->peer = peer; device = entry->state->deviceInfo(); descriptor = entry->state->descriptor(); }
            }
        } else if (!entry) {
            // Only an explicit receipt acknowledgement is idempotent without ownership evidence.
            result = operation == "cleanup" ? Result{} : Result{Status::Failed,"No authenticated connection ownership was found.",true};
        } else if (operation == "cleanup") {
            result = entry->state->cleanup();
            if (result.succeeded()) owners.remove(key(uid,owner));
        } else {
            result = entry->state->restore();
            if (result.succeeded()) entry->peer = 0;
        }
        auto response = macHelperResponse(packet,result,device);
        if (operation == "probe" && result.succeeded()) response["owners"] = receipts;
        const auto reply = xpc_dictionary_create_reply(message);
        const auto encoded = macHelperMessage(response,descriptor);
        if (!reply || !encoded) { if (reply) xpc_release(reply); if (encoded) xpc_release(encoded); disconnected(peer); return; }
        xpc_dictionary_apply(encoded,^(const char *name, xpc_object_t value) { xpc_dictionary_set_value(reply,name,value); return true; });
        xpc_connection_send_message(connection,reply); xpc_release(encoded); xpc_release(reply);
    }
    void accept(xpc_connection_t connection)
    {
        const auto uid = xpc_connection_get_euid(connection);
        if (!uid || uid == uid_t(-1) || peers.size() >= MacHelperMaxPeers || !identity.constrain(connection)) { xpc_connection_cancel(connection); return; }
        const auto peer = ++serial;
        xpc_retain(connection); peers.insert(peer,connection); xpc_connection_set_target_queue(connection,queue);
        xpc_connection_set_event_handler(connection,^(xpc_object_t message) {
            if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) request(peer,message);
            else if (message == XPC_ERROR_CONNECTION_INVALID || message == XPC_ERROR_CONNECTION_INTERRUPTED) disconnected(peer);
        });
        xpc_connection_resume(connection);
    }
};
}

int main(int argc, char **argv)
{
    QCoreApplication application(argc,argv);
    if (application.arguments() == QStringList{application.arguments().first(),"--version"}) {
        MacHelperIdentity identity(MacHelperIdentifier,MacHelperAppIdentifier);
        const QJsonObject report{{"protocol",MacHelperProtocol},{"storage_version",MacHelperStorageVersion},
            {"revision",JC_HELPER_REVISION},{"source_state",JC_HELPER_SOURCE_STATE},{"identity_ready",identity.ready()}};
        std::puts(QJsonDocument(report).toJson(QJsonDocument::Compact).constData()); return 0;
    }
    if (argc != 1 || ::geteuid() != 0) return 2;
    auto *server = new Server;
    if (!server->identity.ready() || (server->directory = openMacHelperBootDirectory()) < 0) return 3;
    const auto listener = xpc_connection_create_mach_service(MacHelperIdentifier,server->queue,XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!listener) return 4;
    xpc_connection_set_event_handler(listener,^(xpc_object_t connection) {
        if (xpc_get_type(connection) == XPC_TYPE_CONNECTION) server->accept(xpc_connection_t(connection));
    });
    dispatch_async(server->queue,^{ server->recoverOrphans(); });
    const auto timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,server->queue);
    dispatch_source_set_timer(timer,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC),5*NSEC_PER_SEC,NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer,^{ server->recoverOrphans(); }); dispatch_resume(timer);
    ::signal(SIGTERM,SIG_IGN); ::signal(SIGINT,SIG_IGN);
    for (int number : {SIGTERM,SIGINT}) {
        const auto source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,uintptr_t(number),0,server->queue);
        dispatch_source_set_event_handler(source,^{
            for (const auto &entry : server->owners) entry->state->restore();
            std::exit(0);
        });
        dispatch_resume(source);
    }
    xpc_connection_resume(listener); dispatch_main();
}
