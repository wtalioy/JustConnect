#include "infrastructure/systemproxy/proxyrecovery.h"
#include "infrastructure/systemproxy/proxyvalidation.h"
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QLockFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>
#include <QUuid>
#include <optional>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
constexpr qsizetype MaxFrame = 64*1024;
constexpr int OperationTimeout = 15000;

bool send(QLocalSocket &socket, const QJsonObject &object, const QDeadlineTimer &deadline)
{
    auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    bytes += '\n';
    if (bytes.size()>MaxFrame || socket.write(bytes)!=bytes.size()) return false;
    while (socket.bytesToWrite())
        if (deadline.hasExpired() || !socket.waitForBytesWritten(int(deadline.remainingTime()))) return false;
    return true;
}

std::optional<QJsonObject> receive(QLocalSocket &socket, const QDeadlineTimer &deadline)
{
    while (!socket.canReadLine()) {
        if (socket.bytesAvailable()>=MaxFrame || deadline.hasExpired()
            || !socket.waitForReadyRead(int(deadline.remainingTime()))) return std::nullopt;
    }
    const auto bytes = socket.readLine(MaxFrame+1);
    if (bytes.size()>MaxFrame || !bytes.endsWith('\n') || QString::fromUtf8(bytes).toUtf8()!=bytes) return std::nullopt;
    const auto document = QJsonDocument::fromJson(bytes);
    return document.isObject() ? std::optional(document.object()) : std::nullopt;
}

QJsonObject response(const SystemProxyCheck &check)
{
    return {{"status",int(check.result.status)},{"detail",check.result.detail.left(4096)},
            {"changed",check.result.mayHaveChanged},{"conflict",check.conflict},{"active",check.active},{"managed",check.managed},
            {"endpoints",QJsonArray::fromStringList(check.endpoints)}};
}

std::optional<SystemProxyCheck> decode(const QJsonObject &object)
{
    const auto status = object["status"].toInteger(-1);
    if (object.size()!=7 || status<0 || status>int(Status::TimedOut) || !object["detail"].isString()
        || object["detail"].toString().size()>4096 || !object["changed"].isBool()
        || !object["conflict"].isBool() || !object["active"].isBool() || !object["managed"].isBool() || !object["endpoints"].isArray()) return std::nullopt;
    SystemProxyCheck result{{Status(status),object["detail"].toString(),object["changed"].toBool()},
                            object["conflict"].toBool(),object["active"].toBool(),object["managed"].toBool()};
    for (const auto &entry : object["endpoints"].toArray()) {
        if (!entry.isString() || entry.toString().isEmpty() || ProxyValidation::endpoint(entry.toString())!=entry.toString() || result.endpoints.contains(entry.toString())) return {};
        result.endpoints.append(entry.toString());
    }
    return result;
}
}

struct ProxyRecoveryBackend::Worker {
    QThread thread;
    QObject *context = new QObject;
    QLocalSocket *socket = nullptr;
    QString executable;
    QString owner;
    bool dirty = false;

    explicit Worker(QString program) : executable(std::move(program))
    {
        context->moveToThread(&thread);
        QObject::connect(&thread,&QThread::finished,context,&QObject::deleteLater);
        thread.start();
    }
    ~Worker()
    {
        QMetaObject::invokeMethod(context,[this] { delete socket;socket=nullptr; },Qt::BlockingQueuedConnection);
        thread.quit();thread.wait();
    }
    Result connect(const QDeadlineTimer &operationDeadline, bool recovery)
    {
        if (socket && socket->state()==QLocalSocket::ConnectedState) return {};
        if (dirty && !recovery) return {Status::Failed,"System proxy recovery acknowledgement was lost; ownership remains unresolved.",true};
        const bool previousDirty=dirty;
        if(!previousDirty)owner=QUuid::createUuid().toString(QUuid::WithoutBraces);
        delete socket;socket=nullptr;
        const QFileInfo program(executable);
        if (!program.isAbsolute() || !program.isFile() || !program.isExecutable())
            return {Status::Unsupported,"The packaged system proxy recovery worker is unavailable."};
#ifdef Q_OS_WIN
        const auto endpoint = "jcpr-"+QUuid::createUuid().toString(QUuid::Id128);
#else
        // macOS ignores socket mode bits; the enclosing private directory restricts traversal.
        QTemporaryDir directory(QDir::tempPath()+"/jcpr-XXXXXX");
        if (!directory.isValid()) return {Status::Failed,"Cannot create a private system proxy recovery channel."};
        const auto endpoint = directory.filePath("p");
#endif
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        server.setMaxPendingConnections(1);
        if (!server.listen(endpoint)) return {Status::Failed,"Cannot listen on the private system proxy recovery channel."};
        QProcess process;
        process.setProgram(program.absoluteFilePath());
        QStringList arguments{endpoint,owner};if(previousDirty)arguments.append("--resume");
        process.setArguments(arguments);
        process.setWorkingDirectory(program.absolutePath());
        process.setStandardInputFile(QProcess::nullDevice());
        process.setStandardOutputFile(QProcess::nullDevice());
        process.setStandardErrorFile(QProcess::nullDevice());
        QDeadlineTimer deadline(qMin(qint64(5000),operationDeadline.remainingTime()));
        if (!process.startDetached()) return {Status::Failed,"Cannot start the system proxy recovery worker."};
        // Even an initial query or EOF can resume persistent recovery in the worker.
        dirty = true;
        if (!server.waitForNewConnection(int(deadline.remainingTime())))
            return {Status::TimedOut,"The system proxy recovery worker did not connect.",true};
        socket = server.nextPendingConnection();
        socket->setParent(context);
        socket->setReadBufferSize(MaxFrame+1);
        server.close();
        const auto hello = receive(*socket,deadline);
        if (hello && *hello==QJsonObject{{"protocol",ProxyRecoveryProtocol},{"ready",false}}) {
            delete socket;socket=nullptr;
            dirty = previousDirty;
            return {Status::Failed,"Another system proxy recovery owner is active or its ownership lock is unavailable.",dirty};
        }
        if (!hello || *hello!=QJsonObject{{"protocol",ProxyRecoveryProtocol},{"ready",true}}) {
            delete socket;socket=nullptr;
            return {Status::Failed,"Invalid system proxy recovery worker handshake.",true};
        }
        return {};
    }
    SystemProxyCheck request(const QString &operation, const SystemProxyConfig &config)
    {
        if (operation=="clear" && !dirty) return {};
        if (operation!="clear" && operation!="inspect") {
            const auto valid = ProxyValidation::config(config);
            if (!valid.succeeded()) return {valid};
        }
        QDeadlineTimer deadline(OperationTimeout);
        const bool previousDirty = dirty;
        if(!previousDirty && socket && socket->state()==QLocalSocket::ConnectedState)
            owner=QUuid::createUuid().toString(QUuid::WithoutBraces);
        for (int attempt=0;;++attempt) {
            auto connected = connect(deadline,operation=="clear");
            if (!connected.succeeded()) {connected.mayHaveChanged|=previousDirty;return {connected};}
            QJsonObject command{{"operation",operation}};
            if (operation!="clear" && operation!="inspect") {
                command["owner"]=owner;
                command["config"] = ProxyValidation::json(config);
            }
            if (QJsonDocument(command).toJson(QJsonDocument::Compact).size()+1>MaxFrame)
                return {{Status::Failed,"System proxy request exceeds the recovery channel limit.",dirty}};
            if (operation=="apply" || operation=="check" || operation=="inspect") dirty = true;
            const auto object = send(*socket,command,deadline) ? receive(*socket,deadline) : std::nullopt;
            auto result = object ? decode(*object) : std::nullopt;
            if (!result) {
                delete socket;socket=nullptr;
                if(operation=="clear" && attempt==0 && !deadline.hasExpired())continue;
                return {{deadline.hasExpired() ? Status::TimedOut : Status::Failed,
                         "System proxy recovery channel failed; the independent worker retains pending recovery.",dirty}};
            }
            if (operation=="apply") dirty = result->result.succeeded() || result->result.mayHaveChanged;
            else if ((operation=="check" || operation=="inspect")) dirty = previousDirty || result->result.mayHaveChanged;
            else if (operation=="clear" && result->result.succeeded()) dirty = false;
            if(operation=="clear" && !result->result.succeeded())result->result.mayHaveChanged|=previousDirty;
            return *result;
        }
    }
    SystemProxyCheck call(const QString &operation, const SystemProxyConfig &config = {})
    {
        SystemProxyCheck result;
        QMetaObject::invokeMethod(context,[&] { result=request(operation,config); },Qt::BlockingQueuedConnection);
        return result;
    }
};

ProxyRecoveryBackend::ProxyRecoveryBackend(QString executable)
{
    if (executable.isEmpty()) {
        executable = QCoreApplication::applicationDirPath()+"/JustConnectProxyRecovery";
#ifdef Q_OS_WIN
        executable += ".exe";
#endif
    }
    worker = std::make_unique<Worker>(std::move(executable));
}
ProxyRecoveryBackend::~ProxyRecoveryBackend() = default;
SystemProxyCheck ProxyRecoveryBackend::check(const SystemProxyConfig &config) { return worker->call("check",config); }
SystemProxyCheck ProxyRecoveryBackend::inspect() { return worker->call("inspect"); }
PlatformOperationResult ProxyRecoveryBackend::apply(const SystemProxyConfig &config) { return worker->call("apply",config).result; }
PlatformOperationResult ProxyRecoveryBackend::clear() { return worker->call("clear").result; }

int runProxyRecoveryWorker(SystemProxyBackend &backend, const QString &endpoint, const QString &lockFile,
                           const QString &legacyLockFile, bool userOwnership, const QString &owner, bool resume)
{
    // shortcut: unattended startup/logoff recovery is pending, integrate it with the application lifecycle.
    QLocalSocket channel;
    channel.setReadBufferSize(MaxFrame+1);
    channel.connectToServer(endpoint);
    if (!channel.waitForConnected(5000)) return 1;
    QLockFile ownership(lockFile);
    ownership.setStaleLockTime(0);
    bool locked = userOwnership && ownership.tryLock();
    std::optional<QLockFile> legacy;
    if (locked && !legacyLockFile.isEmpty()) {
        legacy.emplace(legacyLockFile);legacy->setStaleLockTime(0);locked=legacy->tryLock();
    }
    if(locked && !owner.isEmpty())locked=backend.beginRecovery(owner,resume).succeeded();
    if (!send(channel,{{"protocol",ProxyRecoveryProtocol},{"ready",locked}},QDeadlineTimer(5000)) || !locked) return 1;
    while (const auto object = receive(channel,QDeadlineTimer(QDeadlineTimer::Forever))) {
        const auto operation = (*object)["operation"].toString();
        if (operation!="check" && operation!="apply" && operation!="clear" && operation!="inspect") break;
        const bool clear = operation=="clear" || operation=="inspect";
        if (object->size()!=(clear ? 1 : 3)) break;
        SystemProxyConfig config;
        if (!clear) {
            const auto parsed = ProxyValidation::parse((*object)["config"].toObject());
            if (!parsed) break;
            config = *parsed;
            const auto scope=(*object)["owner"].toString();const QUuid id(scope);
            if(id.isNull() || id.toString(QUuid::WithoutBraces)!=scope)break;
            const auto selected=backend.beginRecovery(scope,false);
            if(!selected.succeeded()) {
                if(!send(channel,response({selected}),QDeadlineTimer(OperationTimeout)))break;
                continue;
            }
        }
        const auto result = operation=="check" ? backend.check(config)
            : operation=="inspect" ? backend.inspect()
            : SystemProxyCheck{clear ? backend.clear() : backend.apply(config)};
        if (!send(channel,response(result),QDeadlineTimer(OperationTimeout))) break;
    }
    // The host may already be gone; keep the original backend alive until its recovery succeeds.
    unsigned delay = 1;
    for (;;) {
        const auto result=backend.clear();
        if (result.succeeded()) return 0;
        if (!result.mayHaveChanged) return 1;
        QThread::sleep(delay);
        delay = qMin(delay*2,30u);
    }
}
