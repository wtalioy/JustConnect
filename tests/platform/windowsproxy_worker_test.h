#pragma once
#include "infrastructure/platform/windows/proxyrecoverylock.h"
#include <QLocalServer>
#include <QLocalSocket>
#include <QLockFile>
#include <QStandardPaths>
#include <QDir>
#include <QDeadlineTimer>
#include <stdexcept>

static void nativeWorkerCheck(bool valid,const char *message) {if(!valid)throw std::runtime_error(message);}

class NativeProxyWorker {
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
        const auto endpoint="jcpr-native-"+QUuid::createUuid().toString(QUuid::Id128);
        nativeWorkerCheck(server.listen(endpoint),"Listen for directly owned native recovery worker");
        process.start(QCoreApplication::applicationDirPath()+"/JustConnectProxyRecovery.exe",{endpoint});
        nativeWorkerCheck(process.waitForStarted(5000) && server.waitForNewConnection(5000),"Start directly owned native recovery worker");
        channel.reset(server.nextPendingConnection());server.close();
        nativeWorkerCheck(receive()==QJsonObject{{"protocol",1},{"ready",ready}},"Native recovery ownership handshake mismatch");
        if(!ready)nativeWorkerCheck(process.waitForFinished(5000) && process.exitStatus()==QProcess::NormalExit && process.exitCode()==1,
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
        nativeWorkerCheck(process.waitForFinished(5000) && process.exitStatus()==QProcess::NormalExit && process.exitCode()==0,"Native persistent worker did not finish cleanup");
    }
    void crash() {
        process.kill();nativeWorkerCheck(process.waitForFinished(5000) && process.exitCode()!=0,"Terminate only the directly owned native recovery worker");channel->abort();
    }
};

static void nativePersistentRecovery() {
    nativeWorkerCheck(qEnvironmentVariable("GITHUB_ACTIONS")=="true","Native persistent recovery requires a disposable runner");
    auto credentials=createSystemCredentialStore();const auto key=PersistentProxyBackend::credentialKey();
    nativeWorkerCheck(credentials->read(key).status==CredentialStatus::NotFound,"Native product recovery record already exists");
    nativeWorkerCheck(nativeRead(nativeOriginal),"Read native persistent baseline");nativeSaved=true;std::atexit(nativeRestore);
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=prior.invalid:3128","old.invalid","https://pac.invalid/original.pac"};
    nativeWorkerCheck(nativeWrite(original),"Seed native persistent recovery baseline");
    const auto restored=[&] {
        WinState current;
        nativeWorkerCheck(nativeRead(current) && current.flags==original.flags && current.proxy==original.proxy && current.bypass==original.bypass
              && current.pac==original.pac && credentials->read(key).status==CredentialStatus::NotFound,
              "Native product recovery lost original settings or its confirmed record removal");
    };
    {
        NativeProxyWorker owner;owner.call("apply");const auto stored=credentials->read(key);
        nativeWorkerCheck(stored.succeeded(),"Product worker changed WinINet without a protected record");
        {NativeProxyWorker concurrent(false);nativeWorkerCheck(credentials->read(key).value==stored.value,"Refused user owner changed the protected record");}
        owner.stop();restored();
    }
    const auto applicationName=QCoreApplication::applicationName();QCoreApplication::setApplicationName("JustConnect");
    const auto directory=QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);QCoreApplication::setApplicationName(applicationName);
    {
        QLockFile legacy(directory+"/proxy-recovery.lock");legacy.setStaleLockTime(0);nativeWorkerCheck(legacy.tryLock(),"Acquire legacy native directory lock");
        NativeProxyWorker refused(false);restored();
    }
    {
        NativeProxyWorker owner;owner.call("apply");nativeWorkerCheck(credentials->read(key).succeeded(),"Missing protected worker crash record");owner.crash();
    }
    {
        NativeProxyWorker fresh;fresh.call("check");restored();fresh.stop();
    }
    std::cout<<"PASS: product Windows persistent worker, user/legacy ownership refusal, EOF recovery and fresh process after worker termination\n";
}
