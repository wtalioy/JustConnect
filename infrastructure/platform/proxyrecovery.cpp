#include "proxyrecovery.h"
#include "proxyvalidation.h"
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
            {"changed",check.result.mayHaveChanged},{"conflict",check.conflict},{"active",check.active}};
}

std::optional<SystemProxyCheck> decode(const QJsonObject &object)
{
    const auto status = object["status"].toInteger(-1);
    if (object.size()!=5 || status<0 || status>int(Status::TimedOut) || !object["detail"].isString()
        || object["detail"].toString().size()>4096 || !object["changed"].isBool()
        || !object["conflict"].isBool() || !object["active"].isBool()) return std::nullopt;
    return SystemProxyCheck{{Status(status),object["detail"].toString(),object["changed"].toBool()},
                            object["conflict"].toBool(),object["active"].toBool()};
}
}

struct ProxyRecoveryBackend::Worker {
    QThread thread;
    QObject *context = new QObject;
    QLocalSocket *socket = nullptr;
    QString executable;
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
    Result connect(const QDeadlineTimer &operationDeadline)
    {
        if (socket && socket->state()==QLocalSocket::ConnectedState) return {};
        if (dirty) return {Status::Failed,"System proxy recovery acknowledgement was lost; ownership remains unresolved.",true};
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
        process.setArguments({endpoint});
        process.setWorkingDirectory(program.absolutePath());
        process.setStandardInputFile(QProcess::nullDevice());
        process.setStandardOutputFile(QProcess::nullDevice());
        process.setStandardErrorFile(QProcess::nullDevice());
        QDeadlineTimer deadline(qMin(qint64(5000),operationDeadline.remainingTime()));
        if (!process.startDetached()) return {Status::Failed,"Cannot start the system proxy recovery worker."};
        if (!server.waitForNewConnection(int(deadline.remainingTime())))
            return {Status::TimedOut,"The system proxy recovery worker did not connect."};
        socket = server.nextPendingConnection();
        socket->setParent(context);
        socket->setReadBufferSize(MaxFrame+1);
        server.close();
        const auto hello = receive(*socket,deadline);
        if (hello && *hello==QJsonObject{{"protocol",1},{"ready",false}}) {
            delete socket;socket=nullptr;
            return {Status::Failed,"Another system proxy recovery owner is active or its ownership lock is unavailable."};
        }
        if (!hello || *hello!=QJsonObject{{"protocol",1},{"ready",true}}) {
            delete socket;socket=nullptr;
            return {Status::Failed,"Invalid system proxy recovery worker handshake."};
        }
        return {};
    }
    SystemProxyCheck request(const QString &operation, const SystemProxyConfig &config)
    {
        if (operation=="clear" && !dirty) return {};
        if (operation!="clear") {
            const auto valid = ProxyValidation::config(config);
            if (!valid.succeeded()) return {valid};
        }
        QDeadlineTimer deadline(OperationTimeout);
        const auto connected = connect(deadline);
        if (!connected.succeeded()) return {connected};
        QJsonObject command{{"operation",operation}};
        if (operation!="clear") command["config"] = QJsonObject{{"http_port",config.httpPort},{"socks_port",config.socksPort},{"bypass",config.bypass}};
        if (QJsonDocument(command).toJson(QJsonDocument::Compact).size()+1>MaxFrame)
            return {{Status::Failed,"System proxy request exceeds the recovery channel limit.",dirty}};
        if (operation=="apply") dirty = true;
        const auto object = send(*socket,command,deadline) ? receive(*socket,deadline) : std::nullopt;
        const auto result = object ? decode(*object) : std::nullopt;
        if (!result) {
            delete socket;socket=nullptr;
            return {{deadline.hasExpired() ? Status::TimedOut : Status::Failed,
                     "System proxy recovery channel failed; the independent worker retains pending recovery.",dirty}};
        }
        if (operation=="apply") dirty = result->result.succeeded() || result->result.mayHaveChanged;
        else if (operation=="clear" && result->result.succeeded()) dirty = false;
        return *result;
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
PlatformOperationResult ProxyRecoveryBackend::apply(const SystemProxyConfig &config) { return worker->call("apply",config).result; }
PlatformOperationResult ProxyRecoveryBackend::clear() { return worker->call("clear").result; }

int runProxyRecoveryWorker(SystemProxyBackend &backend, const QString &endpoint, const QString &lockFile,
                           const QString &legacyLockFile)
{
    // shortcut: automatic worker restart still needs persistent backends and an ownership-safe reconnect handshake.
    QLocalSocket channel;
    channel.setReadBufferSize(MaxFrame+1);
    channel.connectToServer(endpoint);
    if (!channel.waitForConnected(5000)) return 1;
    QLockFile ownership(lockFile);
    ownership.setStaleLockTime(0);
    bool locked = ownership.tryLock();
    std::optional<QLockFile> legacy;
    if (locked && !legacyLockFile.isEmpty()) {
        legacy.emplace(legacyLockFile);legacy->setStaleLockTime(0);locked=legacy->tryLock();
    }
    if (!send(channel,{{"protocol",1},{"ready",locked}},QDeadlineTimer(5000)) || !locked) return 1;
    while (const auto object = receive(channel,QDeadlineTimer(QDeadlineTimer::Forever))) {
        const auto operation = (*object)["operation"].toString();
        if (operation!="check" && operation!="apply" && operation!="clear") break;
        const bool clear = operation=="clear";
        if (object->size()!=(clear ? 1 : 2)) break;
        SystemProxyConfig config;
        if (!clear) {
            const auto values = (*object)["config"].toObject();
            const auto http = values["http_port"].toInteger(-1), socks = values["socks_port"].toInteger(-1);
            if (values.size()!=3 || http<1 || http>65535 || socks<1 || socks>65535 || !values["bypass"].isString()) break;
            config = {int(http),int(socks),values["bypass"].toString()};
            if (!ProxyValidation::config(config).succeeded()) break;
        }
        const auto result = operation=="check" ? backend.check(config)
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
