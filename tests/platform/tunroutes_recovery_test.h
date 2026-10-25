#pragma once
#include "infrastructure/networkjournal/networkjournal.h"
#include <QDir>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>
#include <optional>
#include <utility>

static const QString captureSource("198.19.0.1"),capturePeer("198.19.0.2");
static const QStringList capturePrefixes{"198.18.2.0/24","198.18.3.0/24","198.18.4.7/32"};
static void isolatedCapture()
{
    struct stat current{},initial{};
    check(::geteuid()==0 && ::stat("/proc/thread-self/ns/net",&current)==0 && ::stat("/proc/1/ns/net",&initial)==0
          && (current.st_dev!=initial.st_dev || current.st_ino!=initial.st_ino),"Refusing capture recovery in the host namespace");
}
static void openCaptureJournal(UnixNetworkJournal &journal,const QString &path,const QUuid &owner)
{
    check(path.startsWith(QDir::tempPath()+"/JustConnect-capture-test-"),"Refusing an unrelated fixture directory");
    const int fd=::open(QFile::encodeName(path).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    check(fd>=0,"Open the private capture journal directory");
    const auto result=journal.open(fd,owner);::close(fd);check(result.succeeded(),qPrintable(result.detail));
}
static PlatformOperationResult captureCheckpoint(UnixNetworkJournal &journal,const QJsonObject &record)
{
    return record.isEmpty()?journal.remove():journal.store(record);
}
static void pauseCapture()
{
    std::cout<<"READY"<<std::endl;std::cin.get();throw std::runtime_error("Owned capture crash fixture resumed without termination");
}
static void transferCaptureFd(int channel,int fd)
{
    char tag='F';iovec data{&tag,1};alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};message.msg_iov=&data;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);
    auto *header=CMSG_FIRSTHDR(&message);header->cmsg_level=SOL_SOCKET;header->cmsg_type=SCM_RIGHTS;header->cmsg_len=CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header),&fd,sizeof(fd));check(::sendmsg(channel,&message,0)==1,"Transfer only the private owner's TUN fd");
}
static int receiveCaptureFd(int channel)
{
    pollfd ready{channel,POLLIN,0};check(::poll(&ready,1,5000)==1,"Receive the owned capture fixture fd");
    char tag=0;iovec data{&tag,1};alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};message.msg_iov=&data;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);
    check(::recvmsg(channel,&message,MSG_CMSG_CLOEXEC)==1 && tag=='F' && !(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC)),"Receive complete private fd transfer");
    auto *header=CMSG_FIRSTHDR(&message);int fd=-1;
    check(header && header->cmsg_level==SOL_SOCKET && header->cmsg_type==SCM_RIGHTS
          && header->cmsg_len==CMSG_LEN(sizeof(int)) && !CMSG_NXTHDR(&message,header),"Receive exactly one owned device reference");
    std::memcpy(&fd,CMSG_DATA(header),sizeof(fd));check(fd>=0 && (::fcntl(fd,F_GETFD)&FD_CLOEXEC),"Transferred fixture fd leaks across exec");return fd;
}
static void waitCapturePause(QProcess &process)
{
    QDeadlineTimer deadline(5000);
    while(!process.canReadLine())check(!deadline.hasExpired() && process.waitForReadyRead(int(deadline.remainingTime())),
                                      qPrintable("Missing native capture crash boundary: "+QString::fromUtf8(process.readAllStandardError())));
    check(process.readLine()=="READY\n","Unexpected capture crash boundary");
}
static void killCaptureFixture(QProcess &process)
{
    process.kill();check(process.waitForFinished(5000) && process.exitStatus()==QProcess::CrashExit && process.exitCode()==9,
                         "SIGKILL only the directly owned capture fixture");
}
static void stopCaptureFixture(QProcess &process)
{
    if(process.state()!=QProcess::NotRunning){process.kill();process.waitForFinished(5000);}
}
static std::optional<int> captureRecoveryCommand(const QStringList &args)
{
    if(args.value(1)!="--apply-capture-owner" && args.value(1)!="--restore-capture-owner" && args.value(1)!="--recover-capture")return {};
    isolatedCapture();const auto mode=args[1];
    const bool applying=mode=="--apply-capture-owner",recovering=mode=="--recover-capture";
    check(args.size()==(applying?6:recovering?4:5),"Invalid private capture fixture arguments");
    const auto stage=recovering?QString{}:args[2];const auto path=args[recovering?2:3];const auto text=args[recovering?3:4];const QUuid owner(text);
    check(!owner.isNull() && owner.toString(QUuid::WithoutBraces)==text,"Invalid capture fixture owner");
    routeOwner = owner;
    UnixNetworkJournal journal;openCaptureJournal(journal,path,owner);int reads=0,writes=0;
    LinuxTunRoutes routes([&](const QString &program,const QStringList &arguments) {
        ++reads;
        if((applying && reads==5 && (stage=="applied" || stage=="partial")) || (!applying && stage=="deleted" && reads==9))pauseCapture();
        const auto result=runPlatformCommand(program,arguments);
        if(applying && stage=="partial" && reads==4)
            ip({"route","add",capturePrefixes[1],"dev","foreign0","proto","4","scope","link","metric",QString::number(linuxRouteMetric(owner))});
        return result;
    });
    const auto checkpoint=[&](const QJsonObject &record) {
        const auto result=captureCheckpoint(journal,record);if(!result.succeeded())return result;
        if(!record.isEmpty()) {
            ++writes;
            if((applying && ((stage=="prepared" && writes==1) || (stage=="confirmed" && writes==2))) || (!applying && stage=="deleting" && !record["routes"].toArray().isEmpty() && record["routes"].toArray().first().toObject()["delete_started"]==true))pauseCapture();
        }
        return result;
    };
    if(applying) {
        check(stage=="prepared" || stage=="applied" || stage=="partial" || stage=="confirmed","Unknown capture apply boundary");
        bool valid=false;const int channel=args[5].toInt(&valid);check(valid && channel>=3,"Missing owned fd transfer channel");
        UnixTunDevice device;check(device.createIpv4(owner,captureSource,capturePeer,1400).succeeded(),"Create only the isolated capture owner device");
        transferCaptureFd(channel,device.descriptor());::close(channel);
        const auto result=routes.apply(device,captureSource,capturePeer,capturePrefixes,checkpoint);
        check(false,qPrintable("Capture apply missed its private crash boundary: "+result.detail));
    } else {
        check(recovering || stage=="deleting" || stage=="deleted","Unknown capture restore boundary");
        QJsonObject record;check(journal.load(record).succeeded(),"Load the actual protected capture record");
        const auto result=routes.recover(owner,record,checkpoint);
        if(!recovering)check(false,qPrintable("Capture restore missed its private crash boundary: "+result.detail));
        std::cout<<(result.succeeded()?"RECOVERED":"PENDING")<<std::endl;return result.succeeded()?0:2;
    }
    return 1;
}
static bool freshCapture(const QString &path,const QUuid &owner,bool foreignNamespace=false)
{
    QProcess process;QStringList args{"--recover-capture",path,owner.toString(QUuid::WithoutBraces)};
    if(foreignNamespace)process.start("/usr/bin/unshare",QStringList{"--net","--",QCoreApplication::applicationFilePath()}+args);
    else process.start(QCoreApplication::applicationFilePath(),args);
    check(process.waitForStarted(5000) && process.waitForFinished(5000) && process.exitStatus()==QProcess::NormalExit,
          qPrintable("Fresh capture process failed: "+QString::fromUtf8(process.readAllStandardError())));
    const auto output=process.readAllStandardOutput().trimmed();
    check((process.exitCode()==0 && output=="RECOVERED") || (process.exitCode()==2 && output=="PENDING"),"Unexpected fresh capture verdict");
    return process.exitCode()==0;
}
static void captureRecoveryTests(const UnixTunDevice &device,const QStringList &baseline)
{
    using Result=PlatformOperationResult;using Status=Result::Status;
    const auto makeDirectory=[] {return QDir::tempPath()+"/JustConnect-capture-test-XXXXXX";};
    {
        QTemporaryDir directory(makeDirectory());check(directory.isValid(),"Create private capture checkpoint fixture");
        UnixNetworkJournal journal;openCaptureJournal(journal,directory.path(),device.owner());
        const auto checkpoint=[&](const QJsonObject &record){return captureCheckpoint(journal,record);};
        QJsonObject snapshot;
        {
            LinuxTunRoutes routes;check(routes.apply(device,captureSource,capturePeer,capturePrefixes,checkpoint).succeeded(),"Apply with real protected capture checkpoints");snapshot=routes.snapshot();
        }
        const auto active=inventory();int calls=0;
        LinuxTunRoutes rejected([&](const QString &,const QStringList &){++calls;return PlatformCommandResult{};});
        QList<QJsonObject> invalidRecords;auto bad=snapshot;bad["owner"]=QUuid::createUuid().toString(QUuid::WithoutBraces);invalidRecords.append(bad);
        for(const auto &field:QStringList{"version","index","metric"}){bad=snapshot;bad[field]=-1;invalidRecords.append(bad);}
        for(const auto &field:QStringList{"namespace","interface","source","gateway"}){bad=snapshot;bad[field]="foreign";invalidRecords.append(bad);}
        bad=snapshot;bad["index"]=qint64(device.index())+1;invalidRecords.append(bad);
        bad=snapshot;bad["extra"]=true;invalidRecords.append(bad);
        auto entries=snapshot["routes"].toArray();entries.append(entries[0]);bad=snapshot;bad["routes"]=entries;invalidRecords.append(bad);
        entries=snapshot["routes"].toArray();auto entry=entries[0].toObject();entry["before"]=QJsonArray{QJsonObject{}};entries[0]=entry;bad=snapshot;bad["routes"]=entries;invalidRecords.append(bad);
        for(const auto &record:invalidRecords)check(!rejected.recover(device.owner(),record).succeeded() && calls==0 && rejected.snapshot().isEmpty() && inventory()==active,
                                                   "Invalid capture record reached a command or replaced active ownership");
        ip({"route","add",capturePrefixes[0],"dev",device.name(),"proto","4","scope","link","metric",QString::number(linuxRouteMetric(device.owner())),"src",captureSource,"tos","0x04"});
        const auto duplicate=inventory();LinuxTunRoutes ambiguous;int duplicateCheckpoints=0;
        check(!ambiguous.recover(device.owner(),snapshot,[&](const QJsonObject &){++duplicateCheckpoints;return Result{};}).succeeded()
              && duplicateCheckpoints==0 && inventory()==duplicate,"Ambiguous native capture identity reached a write or checkpoint");
        ip({"route","del",capturePrefixes[0],"metric",QString::number(linuxRouteMetric(device.owner())),"tos","0x04"});
        check(inventory()==active,"Remove only the actual duplicate-identity fixture");
        LinuxTunRoutes denied;int checkpoints=0;
        const auto unchanged=denied.recover(device.owner(),snapshot,[&](const QJsonObject &){++checkpoints;return Result{Status::PermissionDenied,"Denied capture deletion checkpoint"};});
        check(unchanged.status==Status::PermissionDenied && unchanged.mayHaveChanged && checkpoints==1 && inventory()==active,"Storage denial changed native capture routes");
        journal.close();
        check(!freshCapture(directory.path(),device.owner(),true) && inventory()==active && QFile::exists(directory.filePath("source.json")),"Another actual namespace adopted protected capture ownership");
        check(freshCapture(directory.path(),device.owner()) && inventory()==baseline && !QFile::exists(directory.filePath("source.json")),
                              "Fresh process did not restore and remove only its authenticated capture record");
    }
    for(const bool published:{false,true}) {
        int checkpoints=0;QJsonObject stored;LinuxTunRoutes routes;
        const auto denied=routes.apply(device,captureSource,capturePeer,capturePrefixes,[&](const QJsonObject &record) {
            ++checkpoints;check(!record.isEmpty() && record["routes"].toArray()[0].toObject()["applied"].toObject().isEmpty(),"First capture checkpoint followed a native write");
            if(published)stored=record;return Result{Status::PermissionDenied,"Denied write-ahead capture",published};
        });
        check(!denied.succeeded() && checkpoints==1 && inventory()==baseline && (published?!routes.snapshot().isEmpty():routes.snapshot().isEmpty()),
              "Write-ahead failure mutated the kernel or discarded possibly published responsibility");
        check(routes.restore(device,[&](const QJsonObject &record){stored=record;return Result{};}).succeeded() && stored.isEmpty() && inventory()==baseline,"Unattempted capture cleanup changed a native route");
    }
    {
        LinuxTunRoutes routes;bool denied=false;
        const auto checkpoint=[&](const QJsonObject &record){if(denied && record.isEmpty())return Result{Status::PermissionDenied,"Denied final capture removal"};return Result{};};
        check(routes.apply(device,captureSource,capturePeer,capturePrefixes,checkpoint).succeeded(),"Apply before final checkpoint denial");denied=true;
        check(!routes.restore(device,checkpoint).succeeded() && !routes.snapshot().isEmpty() && inventory()==baseline,"Final removal denial lost a completed capture record");
        denied=false;ip({"route","add",capturePrefixes[0],"dev",device.name(),"proto","4","scope","link","metric",QString::number(linuxRouteMetric(device.owner())),"src",captureSource});
        const auto recreated=inventory();
        check(routes.restore(device,checkpoint).succeeded() && routes.snapshot().isEmpty() && inventory()==recreated,"Final checkpoint retry deleted a later same-value capture route");
        ip({"route","del",capturePrefixes[0],"metric",QString::number(linuxRouteMetric(device.owner()))});check(inventory()==baseline,"Remove only the recreated private fixture");
    }
    {
        LinuxTunRoutes routes;QJsonObject stored;int checkpoints=0;
        const auto checkpoint=[&](const QJsonObject &record) {
            if(++checkpoints==2)return Result{Status::PermissionDenied,"Denied confirmed capture publication"};
            stored=record;return Result{};
        };
        const auto result=routes.apply(device,captureSource,capturePeer,capturePrefixes,checkpoint);
        check(result.status==Status::PermissionDenied && result.mayHaveChanged && checkpoints==2 && !stored.isEmpty()
              && hasRoute(capturePrefixes[0],device.name()) && hasRoute(capturePrefixes[1],device.name()) && hasRoute(capturePrefixes[2],device.name()),
              "Post-write storage failure continued kernel rollback or discarded responsibility");
        check(routes.restore(device,checkpoint).succeeded() && stored.isEmpty() && inventory()==baseline,"Live capture owner failed to retry after storage recovery");
    }
    {
        LinuxTunRoutes routes;bool inserted=false;QJsonObject stored;
        const auto checkpoint=[&](const QJsonObject &record) {
            stored=record;
            if(!inserted && !record.isEmpty()) {
                inserted=true;ip({"route","add",capturePrefixes[0],"dev",device.name(),"proto","4","scope","link","metric",QString::number(linuxRouteMetric(device.owner())),"src",captureSource});
            }
            return Result{};
        };
        const auto result=routes.apply(device,captureSource,capturePeer,capturePrefixes,checkpoint);const auto external=inventory();
        check(!result.succeeded() && result.mayHaveChanged && hasRoute(capturePrefixes[0],device.name()) && !hasRoute(capturePrefixes[1],device.name())
              && routes.restore(device,checkpoint).succeeded() && stored.isEmpty() && inventory()==external,
              "Unexecuted capture intent adopted an externally created matching route during storage");
        ip({"route","del",capturePrefixes[0],"metric",QString::number(linuxRouteMetric(device.owner()))});check(inventory()==baseline,"Clean only the external application-wait fixture");
    }
    {
        LinuxTunRoutes routes;bool changed=false;QJsonObject stored;QStringList external;
        const auto checkpoint=[&](const QJsonObject &record) {
            stored=record;
            if(!changed && !record.isEmpty() && record["routes"].toArray().first().toObject()["delete_started"]==true) {
                changed=true;ip({"route","replace",capturePrefixes[0],"dev","foreign0","proto","4","scope","0","metric",QString::number(linuxRouteMetric(device.owner())),"src","192.0.2.1","via","192.0.2.2"});external=inventory();
            }
            return Result{};
        };
        check(routes.apply(device,captureSource,capturePeer,capturePrefixes,checkpoint).succeeded(),"Apply before external capture storage-wait change");
        check(!routes.restore(device,checkpoint).succeeded() && changed && inventory()==external,"Deletion checkpoint did not revalidate its storage wait before a native write");
        check(routes.restore(device,checkpoint).succeeded() && stored.isEmpty() && hasRoute(capturePrefixes[0],"foreign0")
              && !hasRoute(capturePrefixes[1],device.name()) && !hasRoute(capturePrefixes[2],device.name()),"Capture retry deleted an external replacement or abandoned independent owned routes");
        ip({"route","del",capturePrefixes[0],"metric",QString::number(linuxRouteMetric(device.owner()))});check(inventory()==baseline,"Clean only the external restoration-wait fixture");
    }
    {
        int reads=0;QJsonObject stored;QStringList external;
        LinuxTunRoutes routes([&](const QString &program,const QStringList &args) {
            const auto snapshot=runPlatformCommand(program,args);
            if(++reads==4) {
                QThread::msleep(LinuxRouteOperationTimeoutMs+100);
                ip({"route","add",capturePrefixes[0],"dev",device.name(),"proto","4","scope","link","metric",QString::number(linuxRouteMetric(device.owner())),"src",captureSource});external=inventory();
            }
            return snapshot;
        });
        const auto checkpoint=[&](const QJsonObject &record){stored=record;return Result{};};
        const auto result=routes.apply(device,captureSource,capturePeer,capturePrefixes,checkpoint);
        check(result.status==Status::TimedOut && inventory()==external && stored.isEmpty() && routes.snapshot().isEmpty(),
              "Expired capture batch claimed an unexecuted matching external route");
        ip({"route","del",capturePrefixes[0],"metric",QString::number(linuxRouteMetric(device.owner()))});check(inventory()==baseline,"Clean only the expired application fixture");
    }
    {
        int reads=0;QJsonObject stored;
        LinuxTunRoutes routes([&](const QString &program,const QStringList &args) {
            const auto snapshot=runPlatformCommand(program,args);
            if(++reads==11)QThread::msleep(LinuxRouteOperationTimeoutMs+100);
            return snapshot;
        });
        const auto checkpoint=[&](const QJsonObject &record){stored=record;return Result{};};
        check(routes.apply(device,captureSource,capturePeer,capturePrefixes,checkpoint).succeeded(),"Apply before unattempted deletion timeout");
        const auto active=rows();
        check(routes.restore(device,checkpoint).status==Status::TimedOut && rows()==active,"Expired deletion changed native capture routes");
        check(routes.restore(device,checkpoint).succeeded() && stored.isEmpty() && inventory()==baseline,
              "A deletion never sent to the kernel became permanently uncertain in its live owner");
    }
    for(const auto &stage:QStringList{"prepared","applied","partial","confirmed"}) {
        QTemporaryDir directory(makeDirectory());check(directory.isValid(),"Create actual capture owner crash journal");const auto owner=QUuid::createUuid();
        int channel[2];check(::socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,channel)==0,"Open private capture fd witness");
        int held=-1;QProcess holder;
        const auto cleanup=qScopeGuard([&]{stopCaptureFixture(holder);if(held>=0)::close(held);for(int fd:channel)if(fd>=0)::close(fd);});
        const int child=channel[1];holder.setChildProcessModifier([child]{if(::fcntl(child,F_SETFD,0)!=0)::_exit(71);});
        holder.start(QCoreApplication::applicationFilePath(),{"--apply-capture-owner",stage,directory.path(),owner.toString(QUuid::WithoutBraces),QString::number(child)});
        check(holder.waitForStarted(5000),"Start only the isolated capture owner");::close(std::exchange(channel[1],-1));held=receiveCaptureFd(channel[0]);waitCapturePause(holder);killCaptureFixture(holder);
        const auto active=inventory();const bool confirmed=stage=="confirmed" || stage=="prepared";
        check(freshCapture(directory.path(),owner)==confirmed,"Fresh capture recovery guessed an unconfirmed native application");
        if(!confirmed)check(inventory()==active && QFile::exists(directory.filePath("source.json")),"Unconfirmed capture recovery changed matching state or erased the record");
        ::close(std::exchange(held,-1));
        if(!confirmed)check(freshCapture(directory.path(),owner),"Absent capture routes did not release their retained recovery record");
        if(stage=="partial")ip({"route","del",capturePrefixes[1],"metric",QString::number(linuxRouteMetric(owner)),"table",QString::number(linuxCaptureTable(owner))});
        check(inventory()==baseline && !QFile::exists(directory.filePath("source.json")),"Capture owner SIGKILL changed unrelated routes or retained completed data");
        std::cout<<"PASS: protected capture owner SIGKILL at "<<stage.toStdString()<<", retained fd and fresh-process recovery\n";
    }
    for(const bool recreate:{false,true}) {
        for(const auto &stage:QStringList{"deleting","deleted"}) {
            if(recreate && stage=="deleting")continue;
            QTemporaryDir directory(makeDirectory());check(directory.isValid(),"Create capture restoration crash journal");
            {
                UnixNetworkJournal journal;openCaptureJournal(journal,directory.path(),device.owner());LinuxTunRoutes routes;
                check(routes.apply(device,captureSource,capturePeer,capturePrefixes,[&](const QJsonObject &record){return captureCheckpoint(journal,record);}).succeeded(),"Apply actual capture before restore interruption");
            }
            QProcess holder;const auto cleanup=qScopeGuard([&]{stopCaptureFixture(holder);});
            holder.start(QCoreApplication::applicationFilePath(),{"--restore-capture-owner",stage,directory.path(),device.owner().toString(QUuid::WithoutBraces)});
            check(holder.waitForStarted(5000),"Start directly owned restoration fixture");waitCapturePause(holder);killCaptureFixture(holder);
            if(recreate)for(const auto &prefix:capturePrefixes)ip({"route","add",prefix,"dev",device.name(),"proto","4","scope","link","metric",QString::number(linuxRouteMetric(device.owner())),"src",captureSource});
            const auto interrupted=inventory();const bool unresolved=stage=="deleting" || recreate;
            check(freshCapture(directory.path(),device.owner())!=unresolved && inventory()==interrupted,"Interrupted restoration adopted matching or recreated capture routes");
            if(unresolved) {
                for(const auto &prefix:capturePrefixes)ip({"route","del",prefix,"metric",QString::number(linuxRouteMetric(device.owner()))});
                check(freshCapture(directory.path(),device.owner()),"Removed ambiguous capture routes did not complete their protected record");
            }
            check(inventory()==baseline && !QFile::exists(directory.filePath("source.json")),"Restoration crash lost native or protected cleanup");
            std::cout<<"PASS: protected capture restore SIGKILL at "<<stage.toStdString()<<(recreate?", same-value recreation retained":"")<<'\n';
        }
    }
    std::cout<<"PASS: capture write-ahead ordering, strict scoped records, storage denial and final-removal retry\n";
}

// Existing installations can leave v1 main-table records after a crash.
static void legacyCaptureRecoveryTests(const UnixTunDevice &device,const QStringList &baseline)
{
    const QString prefix = "198.18.9.7/32", metric = QString::number(linuxRouteMetric(device.owner()));
    const auto install = [&] {
        ip({"route","add",prefix,"dev",device.name(),"proto","4","scope","0","metric",metric,
            "src",captureSource,"via",capturePeer,"table","main"});
    };
    install();
    QJsonObject applied;
    const auto native = runPlatformCommand(trustedIpRouteUtility(), {"-N","-j","-4","route","show","table","main"});
    check(native.result.succeeded(),"Read the independent legacy route fixture");
    for (const auto &value : QJsonDocument::fromJson(native.output.toUtf8()).array())
        if (ipv4RoutePrefix(value.toObject()) == prefix && value.toObject()["dev"] == device.name()) applied = value.toObject();
    // iproute2's table-all query includes a main-table tag; v1 recorded a main-only query.
    applied.remove("table");
    QJsonObject saved{{"version",1},{"owner",device.owner().toString(QUuid::WithoutBraces)},
        {"namespace",linuxNetworkNamespace()},{"interface",device.name()},{"index",qint64(device.index())},
        {"source",captureSource},{"peer",capturePeer},{"metric",qint64(linuxRouteMetric(device.owner()))},
        {"routes",QJsonArray{QJsonObject{{"prefix",prefix},{"before",QJsonArray{}},{"applied",applied},{"delete_started",false}}}}};
    LinuxTunRoutes legacy;
    check(legacy.recover(device.owner(),saved).succeeded() && inventory() == baseline,
          "Upgrade failed to recover an authenticated v1 main-table record");
    install();auto interrupted = saved;auto entries = saved["routes"].toArray();auto entry = entries[0].toObject();
    entry["delete_started"] = true;entries[0] = entry;interrupted["routes"] = entries;
    const auto held = inventory();LinuxTunRoutes ambiguous;
    check(!ambiguous.recover(device.owner(),interrupted).succeeded() && inventory() == held,
          "Upgrade adopted an interrupted or same-value v1 route");
    ip({"route","del",prefix,"metric",metric,"table","main"});
    LinuxTunRoutes absent;
    check(absent.recover(device.owner(),interrupted).succeeded() && inventory() == baseline,
          "Absent legacy routes retained an obsolete recovery obligation");
    std::cout << "PASS: v1 recovery migration, interrupted same-value preservation and absent-route completion\n";
}
