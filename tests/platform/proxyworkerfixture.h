#pragma once
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QTemporaryDir>
#include <QUuid>
#include <memory>
#include <stdexcept>

static void nativeWorkerCheck(bool valid,const char *message) {if(!valid)throw std::runtime_error(message);}

class NativeProxyWorker {
#ifndef Q_OS_WIN
    QTemporaryDir directory{"/tmp/jcpr-native-XXXXXX"};
#endif
    QLocalServer server;
    QProcess process;
    std::unique_ptr<QLocalSocket> channel;
    QJsonObject receive() {
        QDeadlineTimer deadline(5000);
        while(!channel->canReadLine())nativeWorkerCheck(!deadline.hasExpired() && channel->bytesAvailable()<65536
            && channel->waitForReadyRead(int(deadline.remainingTime())),"Receive native recovery frame");
        const auto bytes=channel->readLine(65537);const auto document=QJsonDocument::fromJson(bytes);
        nativeWorkerCheck(bytes.size()<=65536 && bytes.endsWith('\n') && QString::fromUtf8(bytes).toUtf8()==bytes && document.isObject(),"Invalid native recovery frame");
        return document.object();
    }
public:
    explicit NativeProxyWorker(bool ready=true) {
        server.setSocketOptions(QLocalServer::UserAccessOption);
#ifdef Q_OS_WIN
        const auto endpoint="jcpr-native-"+QUuid::createUuid().toString(QUuid::Id128);
#else
        nativeWorkerCheck(directory.isValid(),"Create private native recovery channel directory");
        const auto endpoint=directory.filePath("p");
#endif
        nativeWorkerCheck(server.listen(endpoint),"Listen for directly owned native recovery worker");
        auto executable=QCoreApplication::applicationDirPath()+"/JustConnectProxyRecovery";
#ifdef Q_OS_WIN
        executable+=".exe";
#endif
        process.start(executable,{endpoint});
        nativeWorkerCheck(process.waitForStarted(5000) && server.waitForNewConnection(5000),"Start directly owned native recovery worker");
        channel.reset(server.nextPendingConnection());server.close();
        nativeWorkerCheck(receive()==QJsonObject{{"protocol",1},{"ready",ready}},"Native recovery ownership handshake mismatch");
        if(!ready)nativeWorkerCheck((process.state()==QProcess::NotRunning || process.waitForFinished(5000)) && process.exitStatus()==QProcess::NormalExit && process.exitCode()==1,
                        "Refused native owner did not exit without backend operations");
    }
    ~NativeProxyWorker() {
        // Only this fixture's directly owned helper may be terminated during test failure cleanup.
        if(process.state()!=QProcess::NotRunning){process.kill();process.waitForFinished(5000);}
    }
    void call(const char *operation) {
        QJsonObject request{{"operation",operation}};
        if(QString::fromLatin1(operation)!="clear")request["config"]=QJsonObject{{"http_port",config.httpPort},{"socks_port",config.socksPort},{"bypass",config.bypass}};
        const auto bytes=QJsonDocument(request).toJson(QJsonDocument::Compact)+'\n';
        nativeWorkerCheck(channel->write(bytes)==bytes.size(),"Queue native recovery operation");QDeadlineTimer deadline(5000);
        while(channel->bytesToWrite())nativeWorkerCheck(!deadline.hasExpired() && channel->waitForBytesWritten(int(deadline.remainingTime())),"Deliver native recovery operation");
        nativeWorkerCheck(receive()["status"]==int(Status::Success),"Native persistent recovery operation failed");
    }
    void stop() {
        channel->disconnectFromServer();
        nativeWorkerCheck((process.state()==QProcess::NotRunning || process.waitForFinished(5000)) && process.exitStatus()==QProcess::NormalExit && process.exitCode()==0,"Native persistent worker did not finish cleanup");
    }
    void crash() {
        process.kill();nativeWorkerCheck(process.waitForFinished(5000) && process.exitCode()!=0,"Terminate only the directly owned native recovery worker");channel->abort();
    }
};

