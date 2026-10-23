#include "infrastructure/platform/persistentproxy.h"
#include "infrastructure/platform/proxyrecovery.h"
#include "infrastructure/platform/systemcredentialstore.h"
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QLockFile>
#include <QProcess>
#include <QTemporaryDir>
#include <iostream>
#include <memory>
#include <stdexcept>

using Status = PlatformOperationResult::Status;
static QDir root;
static bool kde = false;
static const SystemProxyConfig config{11081,11080,"localhost;*.example.test"};
static void require(bool valid,const char *message) {if(!valid)throw std::runtime_error(message);}
static PlatformCommandResult command(const QString &program,const QStringList &arguments) {
    const auto result=runPlatformCommand(program,arguments);require(result.result.succeeded(),"Private native proxy command failed");return result;
}
static void set(const QString &schema,const QString &key,const QString &value) {command("gsettings",{"set",schema,key,value});}
static QStringList kdeArguments(const QString &key) {return {"--file",root.filePath("config/kioslaverc"),"--group","Proxy Settings","--key",key};}
static QString kdeGet(const QString &key) {return command("kreadconfig6",kdeArguments(key)).output;}
static void kdeSet(const QString &key,const QString &value) {auto args=kdeArguments(key);args<<"--"<<value;command("kwriteconfig6",args);}
static QByteArray settings() {
    if(!kde)return command("gsettings",{"list-recursively","org.gnome.system.proxy"}).output.toUtf8();
    QJsonObject values;
    for(const auto &key:QStringList{"httpProxy","httpsProxy","ftpProxy","socksProxy","NoProxyFor","ReversedException","ProxyType","Proxy Config Script","FixtureUnmanaged"})values[key]=kdeGet(key);
    return QJsonDocument(values).toJson(QJsonDocument::Compact);
}
static QJsonObject receive(QLocalSocket &socket) {
    QDeadlineTimer deadline(5000);
    while(!socket.canReadLine())require(!deadline.hasExpired() && socket.bytesAvailable()<65536
        && socket.waitForReadyRead(int(deadline.remainingTime())),"Receive complete fixture response");
    const auto bytes=socket.readLine(65537);const auto document=QJsonDocument::fromJson(bytes);
    require(bytes.size()<=65536 && bytes.endsWith('\n') && QString::fromUtf8(bytes).toUtf8()==bytes && document.isObject(),"Invalid fixture response");
    return document.object();
}
static void send(QLocalSocket &socket,const QJsonObject &object) {
    const auto bytes=QJsonDocument(object).toJson(QJsonDocument::Compact)+'\n';
    require(socket.write(bytes)==bytes.size(),"Queue complete fixture request");QDeadlineTimer deadline(5000);
    while(socket.bytesToWrite())require(!deadline.hasExpired() && socket.waitForBytesWritten(int(deadline.remainingTime())),"Deliver fixture request");
}
static void pauseAt(const char *stage) {
    std::cout<<stage<<std::endl;std::cin.get();throw std::runtime_error("Crash fixture resumed without SIGKILL");
}
static int worker(const QString &endpoint,const QString &stage,const QString &key) {
    auto credentials=createSystemCredentialStore();int writes=0;
    PersistentProxyBackend backend(*credentials,key,[&](const QString &program,const QStringList &arguments) {
        if(arguments.value(0)!="set" && program!="kwriteconfig6")return runPlatformCommand(program,arguments);
        if(stage=="prepared" && writes==0)pauseAt("prepared");
        if(stage=="confirmed" && writes==1)pauseAt("confirmed");
        const auto result=runPlatformCommand(program,arguments);++writes;
        if(result.result.succeeded()) {
            if(stage=="unconfirmed" && writes==1)pauseAt("unconfirmed");
            const bool restored=kde ? arguments.value(5)=="httpProxy" && arguments.last()=="http://prior.invalid 3128"
                : arguments.value(1)=="org.gnome.system.proxy.http" && arguments.value(2)=="host" && arguments.last()=="\"prior.invalid\"";
            if((stage=="restore" || stage=="recreated") && restored)pauseAt("restored");
        }
        return result;
    });
    const auto result=runProxyRecoveryWorker(backend,endpoint,root.filePath("crash-owner.lock"));
    std::cout<<"WRITES "<<writes<<std::endl;return result;
}
class Fixture {
    QTemporaryDir directory;
    QLocalServer server;
    QProcess process;
    std::unique_ptr<QLocalSocket> channel;
    bool reportsWrites = true;
public:
    Fixture(const QString &stage,const QString &key) {
        require(directory.isValid(),"Create private crash channel");
        const auto endpoint=directory.filePath("p");server.setSocketOptions(QLocalServer::UserAccessOption);
        require(server.listen(endpoint),"Listen for owned crash fixture");
        reportsWrites=stage!="steady" && stage!="packaged";
        if(reportsWrites)process.start(QCoreApplication::applicationFilePath(),{"--worker",endpoint,stage,key});
        else process.start(QCoreApplication::applicationDirPath()+"/JustConnectProxyRecovery",{endpoint});
        require(process.waitForStarted(5000) && server.waitForNewConnection(5000),"Start owned crash fixture");
        channel.reset(server.nextPendingConnection());server.close();
        require(receive(*channel)==QJsonObject{{"protocol",1},{"ready",true}},"Crash fixture failed to acquire ownership");
    }
    ~Fixture() {
        // Emergency cleanup applies only to this directly owned test process, never a detached product worker.
        if(process.state()!=QProcess::NotRunning){process.kill();process.waitForFinished(5000);}
    }
    void start(const QString &operation) {
        QJsonObject object{{"operation",operation}};
        if(operation=="apply")object["config"]=QJsonObject{{"http_port",config.httpPort},{"socks_port",config.socksPort},{"bypass",config.bypass}};
        send(*channel,object);
    }
    QJsonObject result() {return receive(*channel);}
    bool clear() {start("clear");return result()["status"]==int(Status::Success);}
    void pause(const QByteArray &stage) {
        QDeadlineTimer deadline(5000);
        while(!process.canReadLine())require(!deadline.hasExpired() && process.waitForReadyRead(int(deadline.remainingTime())),"Owned worker did not reach its native crash boundary");
        require(process.readLine()==stage+'\n',"Unexpected native crash boundary");
    }
    void crash() {
        process.kill();require(process.waitForFinished(5000) && process.exitStatus()==QProcess::CrashExit
            && process.exitCode()==9,"SIGKILL did not terminate the owned test worker");channel->abort();
    }
    int stop() {
        channel->disconnectFromServer();require(process.waitForFinished(5000)
            && process.exitStatus()==QProcess::NormalExit && process.exitCode()==0,"Recovered fixture did not exit cleanly");
        if(!reportsWrites)return -1;
        const auto output=process.readAllStandardOutput().trimmed();bool valid=false;
        const auto writes=output.mid(7).toInt(&valid);require(output.startsWith("WRITES ") && valid,"Missing native write count");return writes;
    }
};
static QJsonObject record(CredentialStore &credentials,const QString &key) {
    const auto value=credentials.read(key);const auto document=QJsonDocument::fromJson(value.value);
    require(value.succeeded() && document.isObject(),"Read real protected crash checkpoint");return document.object();
}
static void phase(const QString &name,const QString &key) {
    auto credentials=createSystemCredentialStore();
    if(name=="unavailable" || name=="locked") {
        int calls=0;const auto before=settings();QLockFile ownership(root.filePath("crash-owner.lock"));ownership.setStaleLockTime(0);
        require(ownership.tryLock(),"Acquire read-failure fixture ownership");
        PersistentProxyBackend backend(*credentials,PersistentProxyBackend::credentialKey(),[&](const QString &,const QStringList &){++calls;return PlatformCommandResult{};});
        const auto result=backend.clear();
        require(!result.succeeded() && result.mayHaveChanged && calls==0 && settings()==before,"Unreadable crash record reached native operations or claimed recovery");
    } else if(name=="prepare" || name=="denied") {
        if(kde) {
            kdeSet("httpProxy","http://prior.invalid 3128");
            for(const auto &key:QStringList{"httpsProxy","ftpProxy","socksProxy"})kdeSet(key,"");
            kdeSet("NoProxyFor","old.example.invalid");kdeSet("ReversedException","true");kdeSet("ProxyType","2");
            kdeSet("Proxy Config Script","https://sensitive-proxy-fixture.invalid/token");kdeSet("FixtureUnmanaged","untouched fixture value");
        } else {
            set("org.gnome.system.proxy.http","host","'prior.invalid'");set("org.gnome.system.proxy.http","port","3128");
            set("org.gnome.system.proxy.http","use-authentication","true");
            set("org.gnome.system.proxy.http","authentication-user","'fixture user'");
            set("org.gnome.system.proxy.http","authentication-password","'fixture password'");
            set("org.gnome.system.proxy","autoconfig-url","'https://sensitive-proxy-fixture.invalid/token'");
            set("org.gnome.system.proxy","mode","'auto'");
        }
        const auto before=settings();
        if(name=="denied") {
            Fixture owner("denied",key);owner.start("apply");require(owner.result()["status"]!=int(Status::Success)
                && settings()==before && owner.clear(),"Denied crash checkpoint changed native settings");
            require(owner.stop()==0 && credentials->read(key).status==CredentialStatus::NotFound,"Denied crash checkpoint wrote native settings or retained a record");
        } else {
            for(const auto &stage:QStringList{"prepared","unconfirmed","confirmed","restore","recreated","steady"}) {
                const auto effectiveKey=stage=="steady"?PersistentProxyBackend::credentialKey():key;
                Fixture owner(stage,effectiveKey);owner.start("apply");
                if(stage=="restore" || stage=="recreated" || stage=="steady") {
                    require(owner.result()["status"]==int(Status::Success),"Apply real private proxy before crash");
                    if(stage!="steady")owner.start("clear");
                }
                if(stage!="steady")owner.pause(stage=="restore" || stage=="recreated"?QByteArray("restored"):stage.toUtf8());
                const auto saved=record(*credentials,effectiveKey);
                const auto first=kde?QString("httpProxy"):QString("http/use-authentication");
                if(stage=="prepared" || stage=="unconfirmed")require(saved["intent"].toArray().contains(first)
                    && !saved["written"].toArray().contains(first),"Crash missed the unconfirmed application boundary");
                if(stage=="confirmed")require(saved["written"].toArray().contains(first),"Crash missed the confirmed checkpoint");
                if(stage=="restore" || stage=="recreated")require(saved["pending_restore"].toArray().contains(kde?"httpProxy":"http/host"),"Crash missed the restoration checkpoint");
                owner.crash();
                if(stage=="steady") {
                    QFile baseline(root.filePath("crash-before.txt"));require(baseline.open(QIODevice::WriteOnly)
                        && baseline.write(before)==before.size(),"Save independent native baseline");break;
                }
                if(stage=="recreated") {
                    if(kde)kdeSet("httpProxy","http://127.0.0.1 11081");else set("org.gnome.system.proxy.http","host","'127.0.0.1'");
                }
                Fixture fresh("recover",key);const bool recovered=fresh.clear();
                if(stage=="unconfirmed" || stage=="recreated" || (!kde && stage=="restore")) {
                    const auto uncertain=kde?QString("httpProxy"):stage=="unconfirmed"?QString("http/use-authentication")
                        :stage=="restore"?QString("http/port"):QString("http/host");
                    require(!recovered && record(*credentials,key)["uncertain"].toArray().contains(uncertain)
                        && (kde ? kdeGet("httpProxy")=="http://127.0.0.1 11081" && kdeGet("ProxyType")== (stage=="unconfirmed"?"2":"1")
                            : command("gsettings",{"get","org.gnome.system.proxy.http","use-authentication"}).output=="false"),
                        "Fresh process guessed an unconfirmed native write or enabled old credentials");
                    if(!kde && (stage=="restore" || stage=="recreated")) {
                        const auto pending=record(*credentials,key)["uncertain"].toArray();
                        require(pending.contains("http/port") && pending.contains("http/use-authentication")
                            && command("gsettings",{"get","org.gnome.system.proxy.http","port"}).output=="11081",
                            "Interrupted endpoint observation lost a sibling field's uncertainty");
                    }
                    if(kde)kdeSet("httpProxy","http://prior.invalid 3128");
                    else {
                        set("org.gnome.system.proxy.http","host","'prior.invalid'");
                        set("org.gnome.system.proxy.http","port","3128");
                        set("org.gnome.system.proxy.http","use-authentication","true");
                    }
                    require(fresh.clear(),"Resolved native uncertainty did not finish recovery");
                } else require(recovered,"Fresh process failed to restore its confirmed native writes");
                const auto writes=fresh.stop();require(settings()==before && credentials->read(key).status==CredentialStatus::NotFound,
                    "Crash recovery changed original values or retained a completed record");
                if(stage=="prepared")require(writes==0,"Unexecuted native intent was claimed by fresh recovery");
                std::cout<<"PASS: native proxy SIGKILL recovery at "<<stage.toStdString()<<'\n';
            }
        }
    } else if(name=="finish") {
        QFile baseline(root.filePath("crash-before.txt"));require(baseline.open(QIODevice::ReadOnly),"Read independent native baseline");
        Fixture fresh("packaged",PersistentProxyBackend::credentialKey());require(fresh.clear(),"Fresh process failed after applied worker SIGKILL and provider restart");fresh.stop();
        require(settings()==baseline.readAll() && credentials->read(PersistentProxyBackend::credentialKey()).status==CredentialStatus::NotFound,"Steady crash recovery lost original values");
        std::cout<<"PASS: native proxy SIGKILL recovery at steady after provider restart\n";
    } else require(false,"Unknown crash fixture phase");
}
int main(int argc,char **argv) try {
    QCoreApplication application(argc,argv);const auto args=application.arguments();
    root=QFileInfo(qEnvironmentVariable("XDG_CONFIG_HOME")).dir();
    kde=qEnvironmentVariable("XDG_CURRENT_DESKTOP")=="KDE";
    require(qEnvironmentVariable("GSETTINGS_BACKEND")=="keyfile" && root.dirName().startsWith("JustConnect-secret-test-")
        && root.absolutePath().startsWith(QDir::tempPath()+'/') && (!kde || qEnvironmentVariable("KDE_SESSION_VERSION")=="6"),"Refuse daily proxy and credential settings");
    if(args.size()==5 && args[1]=="--worker" && CredentialStore::validKey(args[4]))return worker(args[2],args[3],args[4]);
    require(args.size()==3 && CredentialStore::validKey(args[2]),"Invalid private crash fixture arguments");phase(args[1],args[2]);return 0;
} catch(const std::exception &error) {std::cerr<<error.what()<<'\n';return 1;}
