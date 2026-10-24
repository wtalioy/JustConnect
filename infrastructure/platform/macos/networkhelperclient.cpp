#include "networkhelperclient.h"
#include "helperauthorization.h"
#include "helperidentity.h"
#include "helperregistration.h"
#include "helpertransport.h"
#include "infrastructure/platform/ipv4.h"
#include <QScopeGuard>
#include <dispatch/dispatch.h>
#include <functional>
#include <net/if.h>
#include <unistd.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
std::shared_ptr<int> ownedFd(int descriptor = -1)
{
    return {new int(descriptor),[](int *value) { if (*value >= 0) ::close(*value); delete value; }};
}
}
struct MacNetworkHelperClient::Native {
    MacNetworkHelperClient *client = nullptr;
    dispatch_queue_t queue = dispatch_queue_create("JustConnect.network.client",DISPATCH_QUEUE_SERIAL);
    xpc_connection_t connection = nullptr;
    bool invalid = false;
    MacHelperIdentity identity{MacHelperAppIdentifier,MacHelperIdentifier};
    AuthorizationRef authorization = nullptr;
    AuthorizationProvider authorize = acquireMacNetworkAuthorization;
    ~Native()
    {
        if (connection) { xpc_connection_cancel(connection); xpc_release(connection); }
        if (authorization) AuthorizationFree(authorization,kAuthorizationFlagDestroyRights);
        dispatch_release(queue);
    }
    void post(std::function<void(MacNetworkHelperClient *)> callback)
    {
        if (client) {
            auto *target = client;
            QMetaObject::invokeMethod(target,[target,callback] { callback(target); },Qt::QueuedConnection);
        }
    }
    // Blocks copy reference parameters as references; retain the weak handle by value.
    void connect(std::weak_ptr<Native> weak)
    {
        if (connection && !invalid) return;
        if (connection) { xpc_connection_cancel(connection); xpc_release(connection); connection = nullptr; }
        invalid = false;
        connection = xpc_connection_create_mach_service(MacHelperIdentifier,queue,XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
        if (!connection) return;
        xpc_connection_set_event_handler(connection,^(xpc_object_t event) {
            if (xpc_get_type(event) == XPC_TYPE_ERROR) {
                const auto detail = QString::fromUtf8(xpc_dictionary_get_string(event,XPC_ERROR_KEY_DESCRIPTION));
                if (auto state = weak.lock()) {
                    state->invalid = true; state->post([detail](auto *target) { target->disconnected(detail); });
                }
            }
        });
        if (!identity.constrain(connection)) {
            xpc_connection_cancel(connection); xpc_connection_resume(connection); xpc_release(connection); connection = nullptr; return;
        }
        xpc_connection_resume(connection);
    }
};

MacNetworkHelperClient::MacNetworkHelperClient(QObject *parent, AuthorizationProvider authorization) : QObject(parent), native(std::make_shared<Native>())
{
    if (authorization) native->authorize = std::move(authorization);
    native->client = this; deadline.setSingleShot(true); deadline.setInterval(MacHelperOperationTimeoutMs);
    connect(&deadline,&QTimer::timeout,this,[this] {
        pendingRequest = {}; closeDevice();
        const bool changed = current == State::Applying || current == State::Extending || current == State::Restoring || current == State::Acknowledging;
        const Result result{Status::TimedOut,"Network helper timed out; pending ownership is retained.",changed};
        finish(result,current == State::Acknowledging ? State::CleanupRequired : changed ? State::RecoveryRequired : State::Idle);
        if (changed) emit ownershipLost(result);
    });
}
MacNetworkHelperClient::~MacNetworkHelperClient()
{
    const auto state = native;
    dispatch_sync(state->queue,^{ state->client = nullptr; });
    closeDevice(); native.reset();
}
void MacNetworkHelperClient::setState(State state) { if (current != state) { current = state; emit stateChanged(state); } }
void MacNetworkHelperClient::finish(const Result &result, State state)
{
    deadline.stop(); pendingRequest = {}; setState(state); emit finished(operation,result);
}
void MacNetworkHelperClient::closeDevice()
{
    if (device >= 0) ::close(device);
    device = -1; deviceInfo = {};
}
void MacNetworkHelperClient::apply(const QUuid &owner, const MacHelperConfiguration &config)
{
    if (current != State::Idle) return;
    operation = Operation::Apply;
    if (!parseMacHelperApply(macHelperApplyRequest(owner,QUuid::createUuid(),config))) {
        finish({Status::Failed,"Invalid bounded network configuration.",false},State::Idle); return;
    }
    if (!native->identity.ready()) {
        finish({Status::Unsupported,"A certificate-signed application with hardened runtime is required for network authorization.",false},State::Idle); return;
    }
    connection = owner; configuration = config; cancelled = false; registered = false; receipts = {}; outcome = {};
    setState(State::Inspecting); send("probe");
}
void MacNetworkHelperClient::extend(const QStringList &addresses)
{
    const auto parsed = parseMacHelperExtend(macHelperExtendRequest(connection,QUuid::createUuid(),addresses));
    if (current != State::Active || device < 0 || !parsed || addresses.contains(configuration.address) || addresses.contains(configuration.peer)) {
        emit finished(Operation::Extend,{Status::Failed,"DNS publication requires active ownership and canonical addresses.",false}); return;
    }
    operation = Operation::Extend; pendingExtension = *parsed; outcome = {};
    send("extend"); setState(State::Extending);
}
void MacNetworkHelperClient::send(const char *name)
{
    pendingRequest = QUuid::createUuid();
    const auto request = QByteArray(name) == "apply" ? macHelperApplyRequest(connection,pendingRequest,configuration)
        : QByteArray(name) == "extend" ? macHelperExtendRequest(connection,pendingRequest,pendingExtension)
        : macHelperRequest(name,connection,pendingRequest);
    deadline.start();
    const std::weak_ptr<Native> weak(native);
    dispatch_async(native->queue,^{
        const auto state = weak.lock(); if (!state || !state->client) return;
        state->connect(weak);
        AuthorizationExternalForm external{};
        const bool apply = request["operation"] == "apply";
        if (!state->connection || !state->identity.ready() || (apply && (!state->authorization
            || AuthorizationMakeExternalForm(state->authorization,&external) != errAuthorizationSuccess))) {
            state->post([request](auto *target) { target->receive(request,{},ownedFd(),false); }); return;
        }
        const auto message = macHelperMessage(request,-1,apply ? &external : nullptr);
        if (!message) { state->post([request](auto *target) { target->receive(request,{},ownedFd(),false); }); return; }
        xpc_connection_send_message_with_reply(state->connection,message,state->queue,^(xpc_object_t reply) {
            const auto accepted = weak.lock(); if (!accepted) return;
            QJsonObject response; int fd = -1;
            const bool trusted = xpc_connection_get_euid(accepted->connection) == 0 && accepted->identity.accepts(reply)
                && readMacHelperMessage(reply,response,&fd);
            const bool unavailable = reply == XPC_ERROR_CONNECTION_INVALID || reply == XPC_ERROR_CONNECTION_INTERRUPTED;
            auto descriptor = ownedFd(fd);
            accepted->post([request,response,descriptor,trusted,unavailable](auto *target) { target->receive(request,response,descriptor,trusted,unavailable); });
        });
        xpc_release(message);
    });
}
void MacNetworkHelperClient::probeFailed()
{
    if (cancelled) { finish({Status::Cancelled,"Network setup cancelled.",false},State::Idle); return; }
    if (registered) { finish({Status::Failed,"The trusted root network helper is unavailable.",false},State::Idle); return; }
    registered = true; deadline.stop(); setState(State::Registering);
    const std::weak_ptr<Native> weak(native);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        const auto result = registerMacNetworkHelper();
        if (auto state = weak.lock()) dispatch_async(state->queue,^{ state->post([result](auto *target) {
            if (target->current != State::Registering) return;
            if (target->cancelled) target->finish({Status::Cancelled,"Network setup cancelled.",false},State::Idle);
            else if (!result.succeeded()) target->finish(result,State::Idle);
            else { target->setState(State::Inspecting); target->send("probe"); }
        }); });
    });
}
void MacNetworkHelperClient::authorize()
{
    deadline.stop(); setState(State::Authorizing);
    const std::weak_ptr<Native> weak(native);
    const auto provider = native->authorize;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        AuthorizationRef authorization = nullptr;
        const auto status = provider(&authorization);
        const auto state = weak.lock();
        if (!state) { if (authorization) AuthorizationFree(authorization,kAuthorizationFlagDestroyRights); return; }
        dispatch_async(state->queue,^{
            if (state->authorization) AuthorizationFree(state->authorization,kAuthorizationFlagDestroyRights);
            state->authorization = authorization;
            state->post([status](auto *target) {
                if (target->current != State::Authorizing) return;
                if (target->cancelled || status == errAuthorizationCanceled) target->finish({Status::Cancelled,"Network authorization cancelled.",false},State::Idle);
                else if (status != errAuthorizationSuccess) target->finish({Status::PermissionDenied,"Network administrator authorization was denied.",false},State::Idle);
                else { target->send("apply"); target->setState(State::Applying); }
            });
        });
    });
}
void MacNetworkHelperClient::receive(const QJsonObject &request, const QJsonObject &response, std::shared_ptr<int> descriptor, bool trusted, bool unavailable)
{
    if (request["request_id"] != pendingRequest.toString(QUuid::WithoutBraces)) return;
    deadline.stop(); pendingRequest = {};
    const auto parsed = trusted ? parseMacHelperResponse(response,request) : std::nullopt;
    const auto name = request["operation"].toString();
    if (!parsed) {
        if (name == "probe") {
            if (unavailable) probeFailed();
            else finish({Status::PermissionDenied,"The network service does not have the expected trusted root identity.",false},State::Idle);
            return;
        }
        closeDevice(); const Result failure{Status::Failed,"The trusted network helper reply is missing or invalid; ownership is retained.",name != "cleanup"};
        finish(failure,name == "cleanup" ? State::CleanupRequired : State::RecoveryRequired); emit ownershipLost(failure); return;
    }
    const auto result = *parsed;
    if (name == "probe") {
        if (!result.succeeded()) { finish(result,State::Idle); return; }
        receipts = response["owners"].toArray();
        if (cancelled) finish({Status::Cancelled,"Network setup cancelled.",false},State::Idle);
        else if (!receipts.isEmpty()) finish({Status::Failed,"Recover or acknowledge previous network ownership before starting a new connection.",false},State::Idle);
        else authorize();
        return;
    }
    if (name == "apply") {
        if (result.succeeded()) {
            const auto info = response["device"].toObject(); const auto link = info["configuration"].toObject()["applied"].toObject();
            const QJsonArray expected{QJsonObject{{"source",configuration.address},{"peer",configuration.peer},{"netmask","255.255.255.255"}}};
            if (*descriptor < 0 || info["owner"] != request["owner"] || !info["interface"].toString().startsWith("utun")
                || info["index"].toInteger() <= 0 || ::if_nametoindex(info["interface"].toString().toLatin1().constData()) != info["index"].toInteger()
                || link["mtu"] != configuration.mtu || link["ipv4"] != expected) {
                outcome = {Status::Failed,"The delivered device does not match the requested connection.",true};
                setState(State::Restoring); send("restore"); return;
            }
            device = *descriptor; *descriptor = -1; deviceInfo = info;
            if (!cancelled) { finish(result,State::Active); return; }
            outcome = {Status::Cancelled,"Network setup cancelled after restoring its changes.",false};
            closeDevice(); setState(State::Restoring); send("restore"); return;
        }
        if (result.mayHaveChanged) { finish(result,State::RecoveryRequired); return; }
        outcome = cancelled ? Result{Status::Cancelled,"Network setup cancelled.",false} : result;
        setState(State::Acknowledging); send("cleanup"); return;
    }
    if (name == "extend") {
        if (!result.succeeded()) {
            closeDevice(); auto failure = result; failure.mayHaveChanged = true;
            finish(failure,State::RecoveryRequired); emit ownershipLost(failure); return;
        }
        for (const auto &address : pendingExtension) {
            bool covered = false;
            for (const auto &prefix : configuration.capturePrefixes) covered |= ipv4PrefixContainsAddress(prefix,address);
            if (!covered) configuration.capturePrefixes.append(address+"/32");
        }
        pendingExtension.clear();
        if (!cancelled) { finish(result,State::Active); return; }
        outcome = {Status::Cancelled,"DNS publication cancelled after restoring its changes.",false};
        closeDevice(); setState(State::Restoring); send("restore"); return;
    }
    if (name == "cleanup") {
        if (!result.succeeded()) finish(result,State::CleanupRequired);
        else finish(outcome,State::Idle);
        return;
    }
    closeDevice();
    if (!result.succeeded()) { finish(result,State::RecoveryRequired); emit ownershipLost(result); return; }
    setState(State::Acknowledging); send("cleanup");
}
void MacNetworkHelperClient::restore()
{
    if (current != State::Active && current != State::RecoveryRequired) return;
    operation = Operation::Restore; outcome = {}; closeDevice(); setState(State::Restoring); send("restore");
}
void MacNetworkHelperClient::recover(const QUuid &owner)
{
    if (current != State::Idle && current != State::RecoveryRequired) return;
    if (owner.isNull()) return;
    operation = Operation::Recover; connection = owner; outcome = {}; closeDevice(); setState(State::Restoring); send("recover");
}
void MacNetworkHelperClient::cleanupRestored(const QUuid &owner)
{
    if (current != State::Idle && current != State::CleanupRequired) return;
    if (owner.isNull()) return;
    operation = Operation::Cleanup; connection = owner; outcome = {}; setState(State::Acknowledging); send("cleanup");
}
void MacNetworkHelperClient::cancel()
{
    cancelled = true;
    if (current == State::Active || current == State::RecoveryRequired) restore();
}
void MacNetworkHelperClient::disconnected(const QString &detail)
{
    if (current != State::Active && current != State::Extending) return;
    closeDevice(); const Result result{Status::Failed,"Network helper ownership was lost; stop the core and recover before reconnecting. "+detail,true};
    finish(result,State::RecoveryRequired); emit ownershipLost(result);
}
