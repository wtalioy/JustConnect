#include "infrastructure/routing/linux/ownedroutetable.h"
#include "infrastructure/networkjournal/networkjournal.h"
#include "infrastructure/routing/linux/tunroutes.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QTemporaryDir>
#include <fcntl.h>
#include <grp.h>
#include <iostream>
#include <linux/capability.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static void ip(const QStringList &args)
{
    const auto result = runPlatformCommand(trustedIpRouteUtility(),args);
    check(result.result.succeeded(),qPrintable(result.result.detail+" "+args.join(' ')+" "+result.standardError));
}
static QJsonArray read(const QStringList &args)
{
    const auto result = runPlatformCommand(trustedIpRouteUtility(),QStringList{"-N","-j","-4"}+args);
    const auto document = QJsonDocument::fromJson(result.output.toUtf8());
    check(result.result.succeeded() && document.isArray(),"Read independent kernel inventory");
    return document.array();
}
static QStringList inventory()
{
    QStringList result;
    for (const auto &row : read({"route","show","table","all"})) result.append("route:"+QString::fromUtf8(QJsonDocument(row.toObject()).toJson(QJsonDocument::Compact)));
    result.sort();
    result.append(QString::fromUtf8(QJsonDocument(read({"rule","show"})).toJson(QJsonDocument::Compact)));
    return result;
}
static QJsonObject lookup(const QString &source = {})
{
    QStringList args{"route","get","198.18.0.6"};
    if (!source.isEmpty()) args += QStringList{"from",source};
    const auto rows = read(args);
    check(rows.size()==1,"Read actual route selection");
    return rows.first().toObject();
}
static void pauseAt(const QJsonObject &record)
{
    std::cout << QJsonDocument(record).toJson(QJsonDocument::Compact).constData() << std::endl;
    std::cin.get();
    throw std::runtime_error("Crash-boundary fixture resumed without owner termination");
}
static bool deletingRoutes(const QJsonObject &record)
{
    for (const auto &value : record["routes"].toArray()) if (value.toObject()["delete_started"].toBool()) return true;
    return false;
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc,argv);
    using Status = PlatformOperationResult::Status;
    const QString source("192.0.2.1"), gateway("192.0.2.2"), target("198.18.0.6/32");
    const auto owner = QUuid::createUuid();
    int reads = 0;
    LinuxOwnedRouteTable missing([&](const QString &, const QStringList &) {
        ++reads;return PlatformCommandResult{{Status::Failed,"Unexpected read"},{}};
    });
    if (argc == 1) {
        check(::geteuid()!=0,"Run ordinary source route checks without root");
        int checkpoints = 0;
        check(!missing.apply({},"original0",source,gateway,{target},[&](const QJsonObject &) {
            ++checkpoints;return PlatformOperationResult{Status::Failed,"Unexpected checkpoint"};
        }).succeeded() && reads==0 && checkpoints==0 && missing.snapshot().isEmpty(),
              "Missing ownership reached network operations");
        check(!missing.recover(owner,{}).succeeded() && reads==0 && missing.snapshot().isEmpty(),
              "An invalid saved owner reached network operations");
        std::cout << "PASS: source routes require a connection owner before OS operations\n";
        return 0;
    }
    struct stat current{}, initial{};
    check(::geteuid()==0 && ::stat("/proc/self/ns/net",&current)==0 && ::stat("/proc/1/ns/net",&initial)==0
          && (current.st_dev!=initial.st_dev || current.st_ino!=initial.st_ino),"Refusing the host network namespace");
    if (argc==4 && app.arguments()[1]=="--journal-owner") {
        const auto stage = app.arguments()[2];
        check(stage=="prepared" || stage=="partial" || stage=="applied" || stage=="confirmed","Unknown source apply crash boundary");
        const int directory = ::open(QFile::encodeName(app.arguments()[3]).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        check(directory>=0,"Open the source owner checkpoint directory");
        UnixNetworkJournal journal;
        const auto opened = journal.open(directory,owner);::close(directory);
        check(opened.succeeded(),qPrintable(opened.detail));
        QJsonObject intent;
        int routeReads = 0, ruleReads = 0;
        LinuxOwnedRouteTable routes([&](const QString &program,const QStringList &args) {
            if (args.contains("route") && ++routeReads==3 && (stage=="applied" || stage=="partial")) pauseAt(intent);
            const auto result = runPlatformCommand(program,args);
            if (args.contains("rule") && ++ruleReads==2 && stage=="partial")
                ip({"route","add",target,"dev","original0","src",source,"proto","99",
                    "metric",QString::number(intent["metric"].toInteger()),"table",QString::number(intent["table"].toInteger())});
            return result;
        });
        const auto result = routes.apply(owner,"original0",source,gateway,{target},[&](const QJsonObject &record) {
            if (record.isEmpty()) return journal.remove();
            intent = record;
            const auto saved = journal.store(record);
            if (saved.succeeded() && stage=="prepared") pauseAt(record);
            return saved;
        });
        check(result.succeeded(),qPrintable(result.detail));
        pauseAt(routes.snapshot());
    }
    if ((argc==4 || argc==5) && app.arguments()[1]=="--recover-journal") {
        const auto id = QUuid(app.arguments()[2]);
        const auto stage = argc==5 ? app.arguments()[4] : QString{};
        check(stage.isEmpty() || stage=="rule-pre" || stage=="rule-post" || stage=="routes-pre" || stage=="routes-post",
              "Unknown source recovery crash boundary");
        const int directory = ::open(QFile::encodeName(app.arguments()[3]).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        check(directory>=0,"Open the trusted source checkpoint directory");
        UnixNetworkJournal journal;
        const auto opened = journal.open(directory,id);::close(directory);
        check(opened.succeeded(),qPrintable(opened.detail));
        QJsonObject saved;
        auto result = journal.load(saved);
        LinuxOwnedRouteTable routes([&](const QString &program,const QStringList &args) {
            const auto result = runPlatformCommand(program,args);
            if (stage=="routes-post" && deletingRoutes(saved) && args.contains("route") && result.result.succeeded()) {
                bool present = false;
                for (const auto &value : QJsonDocument::fromJson(result.output.toUtf8()).array())
                    present |= value.toObject()["table"]==QString::number(saved["table"].toInteger());
                if (!present) pauseAt(saved);
            }
            return result;
        });
        if (result.succeeded()) result = routes.recover(id,saved,[&](const QJsonObject &record) {
            if (stage=="rule-post" && saved["rule_delete_started"]==true && record["rule_pending"]==false) pauseAt(saved);
            const auto result = record.isEmpty() ? journal.remove() : journal.store(record);
            if (result.succeeded()) {
                saved = record;
                if ((stage=="rule-pre" && record["rule_delete_started"]==true)
                    || (stage=="routes-pre" && deletingRoutes(record))) pauseAt(record);
            }
            return result;
        });
        check(result.succeeded() && routes.snapshot().isEmpty(),qPrintable(result.detail));
        std::cout << "PASS: fresh process loaded protected source ownership and synchronized its removal after recovery\n";
        return 0;
    }
    if (argc==6 && app.arguments()[1]=="--hold") {
        LinuxOwnedRouteTable routes;
        const auto result = routes.apply(owner,app.arguments()[2],app.arguments()[3],app.arguments()[4],{app.arguments()[5]});
        check(result.succeeded(),qPrintable(result.detail));
        std::cout << QJsonDocument(routes.snapshot()).toJson(QJsonDocument::Compact).constData() << std::endl;
        char stop = 0;
        std::cin.get(stop);
        const auto restored = routes.restore(owner);
        check(restored.succeeded() && routes.snapshot().isEmpty(),qPrintable(restored.detail));
        check(!std::cin || stop=='R',"Unexpected route holder confirmation");
        std::cout << "PASS: original-source holder restored its routes/rule on parent EOF\n";
        return 0;
    }
    check(argc==2 && app.arguments()[1]=="--isolated","Use the guarded source route modes");
    ip({"link","add","original0","type","dummy"});
    ip({"link","set","original0","up"});
    ip({"address","add",source+"/24","dev","original0"});
    UnixTunDevice tun;
    check(tun.createIpv4(QUuid::createUuid(),"198.19.0.1","198.19.0.2",1400).succeeded(),"Create owned capture fixture");
    LinuxTunRoutes capture;
    check(capture.apply(tun,"198.19.0.1","198.19.0.2",{target}).succeeded(),"Apply formal capture route fixture");
    auto baseline = inventory();
    const auto baselineRuleCount = read({"rule","show"}).size();
    for (const auto &bad : {QString("default"),QString("0.0.0.0/0"),QString("198.18.0.7/24"),QString("198.018.0.6/32"),
                           QString("198.18.0.6")+QChar(0)+"\nrule del priority 0/32"})
        check(!missing.apply(owner,"original0",source,gateway,{bad}).succeeded() && reads==0,"Invalid prefix reached commands");
    check(!missing.apply(owner,"original0",source,gateway,{gateway+"/32"}).succeeded()
          && !missing.apply(owner,QString("original0")+QChar(0)+"\nrule del priority 0",source,gateway,{target}).succeeded()
          && !missing.apply(owner,"original0","192.0.2.99",gateway,{target}).succeeded()
          && reads==0 && inventory()==baseline,"Invalid interface/source changed network state");
    {
        LinuxOwnedRouteTable growing;
        check(growing.apply(owner,"original0",source,gateway,{target}).succeeded(),"Prepare source extension");
        const auto original = growing.snapshot();
        check(growing.extend(owner,{"198.18.1.7","198.18.1.7"}).succeeded()
              && growing.snapshot()["routes"].toArray().size() == original["routes"].toArray().size()+1,
              "DNS source extension lost ownership or duplicated its address");
        check(read({"route","get","198.18.1.7","from",source}).first().toObject()["dev"] == "original0",
              "Published DNS target did not retain its original bound-source route");
        const auto extended = growing.snapshot();
        const auto held = inventory();
        check(growing.extend(owner,{"198.18.1.7"}).succeeded() && growing.snapshot() == extended && inventory() == held,
              "Repeated DNS source publication changed the original rule");
        for (const auto &bad : {QString("127.0.0.1"),source,gateway,QString("198.18.2.0/24")})
            check(!growing.extend(owner,{bad}).succeeded() && growing.snapshot() == extended && inventory() == held,
                  "Invalid DNS source address changed active ownership");
        check(!growing.extend(QUuid::createUuid(),{"198.18.1.8"}).succeeded() && inventory() == held,
              "Another owner extended the source lookup");
        check(!growing.extend(owner,{"198.18.1.8"},[&](const QJsonObject &record) {
            check(inventory() == held,"DNS source wrote before its checkpoint");
            return record == extended ? PlatformOperationResult{} : PlatformOperationResult{Status::Failed,"Refused DNS checkpoint"};
        }).succeeded() && growing.snapshot() == extended && inventory() == held,
              "Failed DNS checkpoint damaged existing source ownership");
        check(growing.ensurePrefixes(owner,{"198.18.9.0/24","198.18.9.0/24"}).succeeded()
              && read({"route","get","198.18.9.7","from",source}).first().toObject()["dev"] == "original0"
              && growing.snapshot()["rule_applied"] == extended["rule_applied"],"Live capture additions lost original egress or replaced its rule");
        LinuxOwnedRouteTable recovered;
        check(recovered.recover(owner,growing.snapshot()).succeeded() && inventory() == baseline,
              "A fresh source backend could not restore appended DNS routes");
        check(growing.restore(owner).succeeded(),"Release already restored source metadata");
    }
    LinuxOwnedRouteTable routes;
    {
        QTemporaryDir checkpoint;
        const int directory = ::open(QFile::encodeName(checkpoint.path()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        UnixNetworkJournal journal;
        check(checkpoint.isValid() && directory>=0 && journal.open(directory,owner).succeeded(),"Open protected write-ahead fixture");
        ::close(directory);
        bool checkpointed = false;
        const auto refused = routes.apply(owner,"original0",source,gateway,{target},[&](const QJsonObject &intent) {
            checkpointed = true;
            check(inventory()==baseline && intent["rule_pending"]==true,"Checkpoint was invoked after source kernel changes");
            return PlatformOperationResult{Status::Failed,"Injected checkpoint refusal"};
        });
        check(!refused.succeeded() && checkpointed && routes.snapshot().isEmpty() && inventory()==baseline,
              "Checkpoint refusal reached source writes or retained uncommitted authority");
        const auto uncertain = routes.apply(owner,"original0",source,gateway,{target},[&](const QJsonObject &intent) {
            const auto stored = journal.store(intent);
            check(stored.succeeded(),"Publish the uncertain checkpoint fixture");
            return PlatformOperationResult{Status::Failed,"Injected failure after checkpoint publication",true};
        });
        check(!uncertain.succeeded() && uncertain.mayHaveChanged && !routes.snapshot().isEmpty() && inventory()==baseline,
              "Unconfirmed checkpoint publication either changed the kernel or discarded recovery intent");
        check(routes.restore(owner).succeeded() && journal.remove().succeeded() && inventory()==baseline,
              "Unapplied intent could not be recovered and removed");

        QFile foreign(checkpoint.filePath("source.json"));
        const auto foreignBytes = QJsonDocument(QJsonObject{{"owner",QUuid::createUuid().toString(QUuid::WithoutBraces)}}).toJson(QJsonDocument::Compact);
        check(foreign.open(QIODevice::WriteOnly) && foreign.write(foreignBytes)==foreignBytes.size(),"Create a previous connection's checkpoint fixture");
        foreign.close();
        check(QFile::setPermissions(foreign.fileName(),QFile::ReadOwner|QFile::WriteOwner),"Keep the foreign checkpoint private");
        const auto existing = routes.apply(owner,"original0",source,gateway,{target},[&](const QJsonObject &intent) { return journal.store(intent); });
        check(!existing.succeeded() && routes.snapshot().isEmpty() && inventory()==baseline
              && foreign.open(QIODevice::ReadOnly) && foreign.readAll()==foreignBytes,
              "An existing journal was replaced or allowed new source kernel writes");
        foreign.close();check(foreign.remove(),"Remove the owned foreign-checkpoint fixture");

        QString privateTable;
        bool sawOwnedRoute = false;
        LinuxOwnedRouteTable changedRules([&](const QString &program,const QStringList &args) {
            const auto result = runPlatformCommand(program,args);
            if (!privateTable.isEmpty() && args.contains("route"))
                for (const auto &value : QJsonDocument::fromJson(result.output.toUtf8()).array())
                    sawOwnedRoute |= value.toObject()["table"]==privateTable;
            return result;
        });
        QStringList changed;
        const auto conflict = changedRules.apply(owner,"original0",source,gateway,{target},[&](const QJsonObject &intent) {
            privateTable = QString::number(intent["table"].toInteger());
            const auto stored = journal.store(intent);
            check(stored.succeeded(),"Persist intent before rule conflict");
            ip({"rule","add","priority","1","table","254","protocol","99"});changed = inventory();
            return stored;
        });
        check(!conflict.succeeded() && conflict.mayHaveChanged && !sawOwnedRoute && inventory()==changed,
              "A rule created during checkpoint publication allowed source kernel changes");
        check(changedRules.restore(owner).succeeded() && inventory()==changed,"Unapplied intent removed the concurrent foreign rule");
        ip({"rule","del","priority","1","table","254","protocol","99"});
        check(journal.remove().succeeded() && inventory()==baseline,"Rule-conflict fixture did not restore its original inventory");

        const auto replaced = routes.apply(owner,"original0",source,gateway,{target},[&](const QJsonObject &intent) {
            const auto stored = journal.store(intent);check(stored.succeeded(),"Persist intent before interface replacement");
            ip({"link","set","original0","down"});ip({"link","set","original0","name","previous0"});
            ip({"link","add","original0","type","dummy"});ip({"address","add",source+"/24","dev","original0"});
            ip({"link","set","original0","up"});changed = inventory();return stored;
        });
        check(!replaced.succeeded() && replaced.mayHaveChanged && inventory()==changed,
              "A same-name replacement interface received source writes after checkpoint publication");
        ip({"link","del","original0"});ip({"link","set","previous0","name","original0"});ip({"link","set","original0","up"});
        check(routes.restore(owner).succeeded() && journal.remove().succeeded() && inventory()==baseline,
              "Interface replacement fixture lost original state or intent cleanup");
    }
    for (const auto &boundary : {QString("applied"),QString("rule"),QString("routes"),QString("remove")}) {
        QTemporaryDir checkpoint;
        const int directory = ::open(QFile::encodeName(checkpoint.path()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        UnixNetworkJournal journal;
        check(checkpoint.isValid() && directory>=0 && journal.open(directory,owner).succeeded(),"Open recovery checkpoint refusal fixture");
        ::close(directory);
        bool rejected = false;
        const auto persist = [&](const QJsonObject &record) {
            const bool reject = boundary=="applied" ? !record["rule_applied"].toObject().isEmpty() && record["rule_delete_started"]==false
                : boundary=="rule" ? record["rule_delete_started"]==true
                : boundary=="routes" ? deletingRoutes(record) : record.isEmpty();
            if (!rejected && reject) {
                rejected = true;
                return PlatformOperationResult{Status::Failed,"Injected recovery checkpoint refusal"};
            }
            return record.isEmpty() ? journal.remove() : journal.store(record);
        };
        const auto applied = routes.apply(owner,"original0",source,gateway,{target},persist);
        if (boundary=="applied") {
            check(!applied.succeeded() && rejected && routes.snapshot().isEmpty() && inventory()==baseline
                  && !QFile::exists(checkpoint.filePath("source.json")),"Applied-value checkpoint failure did not durably roll back its kernel writes");
            continue;
        }
        check(applied.succeeded(),"Apply recovery checkpoint refusal fixture");
        const auto active = inventory();
        const auto stopped = routes.restore(owner,persist);
        check(!stopped.succeeded() && stopped.mayHaveChanged && rejected && !routes.snapshot().isEmpty()
              && QFile::exists(checkpoint.filePath("source.json")),"Failed recovery checkpoint discarded pending duties or its protected record");
        if (boundary=="rule") check(inventory()==active,"Rule deletion preceded its durable checkpoint");
        else if (boundary=="routes") {
            check(read({"rule","show"}).size()==baselineRuleCount && routes.snapshot()["routes"].toArray().size()==2
                  && !deletingRoutes(routes.snapshot()),"Route deletion preceded its checkpoint or retained an unattempted marker");
        } else {
            check(inventory()==baseline && routes.snapshot()["routes"].toArray().isEmpty(),"Journal removal failed before kernel recovery completed");
            ip({"rule","add","priority","100","table",QString::number(routes.snapshot()["table"].toInteger()),"protocol","99"});
        }
        const auto beforeRetry = inventory();
        const auto savedTable = QString::number(routes.snapshot()["table"].toInteger());
        check(routes.restore(owner,persist).succeeded() && routes.snapshot().isEmpty()
              && !QFile::exists(checkpoint.filePath("source.json")),"Recovery checkpoint failure could not be retried");
        if (boundary=="remove") {
            check(inventory()==beforeRetry,"Journal-removal retry adopted a new external table reference");
            ip({"rule","del","priority","100","table",savedTable,"protocol","99"});
        }
        check(inventory()==baseline,"Checkpoint refusal recovery changed original network state");
    }
    for (const bool changeRule : {true,false}) {
        QTemporaryDir checkpoint;
        const int directory = ::open(QFile::encodeName(checkpoint.path()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        UnixNetworkJournal journal;
        check(checkpoint.isValid() && directory>=0 && journal.open(directory,owner).succeeded(),"Open checkpoint interference fixture");
        ::close(directory);
        bool interfere = false;
        QStringList changed;
        QString privateTable, privateMetric;
        const auto persist = [&](const QJsonObject &record) {
            const auto result = record.isEmpty() ? journal.remove() : journal.store(record);
            if (interfere && result.succeeded() && (changeRule ? record["rule_delete_started"]==true : deletingRoutes(record))) {
                interfere = false;
                if (changeRule) ip({"rule","add","priority","100","table",privateTable,"protocol","99"});
                else ip({"route","replace",target,"dev","original0","via","192.0.2.3","src",source,
                         "proto","4","metric",privateMetric,"table",privateTable});
                changed = inventory();
            }
            return result;
        };
        check(routes.apply(owner,"original0",source,gateway,{target},persist).succeeded(),"Apply checkpoint interference fixture");
        privateTable = QString::number(routes.snapshot()["table"].toInteger());
        privateMetric = QString::number(routes.snapshot()["metric"].toInteger());
        interfere = true;
        check(!routes.restore(owner,persist).succeeded() && !interfere && inventory()==changed,
              "A concurrent checkpoint change reached subsequent kernel deletions");
        if (changeRule) ip({"rule","del","priority","100","table",privateTable,"protocol","99"});
        check(routes.restore(owner,persist).succeeded(),"Retry after checkpoint interference failed");
        if (!changeRule) {
            check(read({"route","show","table",privateTable}).size()==1,"Recovery removed the foreign next-hop route");
            ip({"route","del",target,"dev","original0","via","192.0.2.3","src",source,
                "proto","4","metric",privateMetric,"table",privateTable});
        }
        check(inventory()==baseline && !QFile::exists(checkpoint.filePath("source.json")),"Checkpoint interference lost state or durable cleanup");
    }
    check(routes.apply(owner,"original0",source,gateway,{target,target}).succeeded(),"Apply real source route table and rule");
    const auto snapshot = routes.snapshot();
    const auto table = QString::number(snapshot["table"].toInteger());
    const auto metric = QString::number(snapshot["metric"].toInteger());
    check(snapshot["routes"].toArray().size()==2 && lookup()["dev"]==tun.name()
          && lookup(source)["dev"]=="original0" && lookup(source)["table"]==table,
          "Actual bound source did not bypass the more specific TUN capture route");
    const auto active = inventory();
    check(!routes.recover(owner,snapshot).succeeded() && routes.snapshot()==snapshot && inventory()==active,
          "A saved record replaced active source ownership");
    QList<QJsonObject> invalidRecords;
    auto invalid = snapshot;invalid["owner"] = QUuid::createUuid().toString(QUuid::WithoutBraces);invalidRecords.append(invalid);
    invalid = snapshot;invalid["table"] = snapshot["table"].toInteger()+1;invalidRecords.append(invalid);
    invalid = snapshot;invalid["index"] = 0;invalidRecords.append(invalid);
    invalid = snapshot;invalid["namespace"] = "another boot or network namespace";invalidRecords.append(invalid);
    invalid = snapshot;invalid["rule_pending"] = "false";invalidRecords.append(invalid);
    invalid = snapshot;invalid["rule_delete_started"] = "false";invalidRecords.append(invalid);
    invalid = snapshot;invalid["rule_pending"] = false;invalid["rule_delete_started"] = true;invalidRecords.append(invalid);
    invalid = snapshot;invalid["extra"] = true;invalidRecords.append(invalid);
    auto savedRoutes = snapshot["routes"].toArray();
    invalid = snapshot;savedRoutes.append(savedRoutes.first());invalid["routes"] = savedRoutes;invalidRecords.append(invalid);
    savedRoutes = snapshot["routes"].toArray();
    auto changedEntry = savedRoutes.last().toObject();
    for (const QJsonValue marker : {QJsonValue("false"),QJsonValue(true)}) {
        changedEntry["delete_started"] = marker;savedRoutes[savedRoutes.size()-1] = changedEntry;
        invalid = snapshot;invalid["routes"] = savedRoutes;invalidRecords.append(invalid);
    }
    savedRoutes = snapshot["routes"].toArray();changedEntry = savedRoutes.last().toObject();
    auto changedRow = changedEntry["applied"].toObject();
    changedRow["gateway"] = "192.0.2.99";changedEntry["applied"] = changedRow;savedRoutes[savedRoutes.size()-1] = changedEntry;
    invalid = snapshot;invalid["routes"] = savedRoutes;invalidRecords.append(invalid);
    for (const auto &saved : invalidRecords)
        check(!missing.recover(owner,saved).succeeded() && reads==0 && missing.snapshot().isEmpty() && inventory()==active,
              "An invalid saved source record reached OS operations or retained partial authority");
    check(!routes.restore(QUuid::createUuid()).succeeded() && inventory()==active && routes.snapshot()==snapshot,
          "Another owner restored or discarded this connection's state");
    LinuxOwnedRouteTable collision;
    check(!collision.apply(QUuid::createUuid(),"original0",source,gateway,{target}).succeeded()
          && collision.snapshot().isEmpty() && inventory()==active,"Early rule conflict was adopted or changed");
    check(routes.restore(owner).succeeded() && routes.snapshot().isEmpty() && inventory()==baseline,"Normal source recovery changed original state");
    check(routes.restore(owner).succeeded() && inventory()==baseline,"Repeated source recovery changed original state");
    check(routes.apply(owner,"original0",source,{}, {target}).succeeded() && lookup(source)["dev"]=="original0"
          && !lookup(source).contains("gateway") && read({"route","show","table",table}).size()==1,
          "Direct original routes gained a fictitious gateway or lost source selection");
    LinuxOwnedRouteTable directRecovery;
    check(directRecovery.recover(owner,routes.snapshot()).succeeded() && directRecovery.snapshot().isEmpty()
          && routes.restore(owner).succeeded() && inventory()==baseline,"Direct saved source recovery changed original state");

    // Root-owned checkpoint fixtures must be destroyed before the later permanent uid drop.
    for (const auto &stage : {QString("prepared"),QString("partial"),QString("applied"),QString("confirmed")}) {
        QTemporaryDir checkpoint;
        check(checkpoint.isValid(),"Create private checkpoint fixture");
        QProcess holder;
        holder.start(QCoreApplication::applicationFilePath(),{"--journal-owner",stage,checkpoint.path()});
        check(holder.waitForStarted(5000) && holder.waitForReadyRead(5000),"Start independent journaled source owner");
        const auto savedOwner = holder.readLine();
        const auto deadOwner = QJsonDocument::fromJson(savedOwner).object();
        QFile savedFile(checkpoint.filePath("source.json"));
        check(savedFile.open(QIODevice::ReadOnly) && QJsonDocument::fromJson(savedFile.readAll()).object()==deadOwner,
              "Crash-boundary readiness preceded the complete durable source record");
        savedFile.close();
        const auto savedTable = QString::number(deadOwner["table"].toInteger());
        check(!deadOwner.isEmpty() && (stage=="prepared" ? inventory()==baseline
              : stage=="partial" ? read({"route","show","table",savedTable}).size()==2
              : lookup(source)["table"]==savedTable),
              "Source owner applied kernel state before its checkpoint or failed to apply the recorded state");
        for (const auto &entry : deadOwner["routes"].toArray())
            check(entry.toObject()["applied"].toObject().isEmpty()==(stage!="confirmed"),
                  "Crash boundary did not preserve the expected unconfirmed or confirmed route values");
        UnixNetworkJournal competing;
        const int directory = ::open(QFile::encodeName(checkpoint.path()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        check(directory>=0 && !competing.open(directory,QUuid(deadOwner["owner"].toString())).succeeded(),
              "Another guardian acquired the live source owner's protected journal");
        ::close(directory);
        holder.kill();
        check(holder.waitForFinished(5000) && holder.exitStatus()==QProcess::CrashExit,
              "Source owner was not killed at its actual checkpoint boundary");
        QProcess differentNamespace;
        differentNamespace.start("/usr/bin/unshare",{"--net","--",QCoreApplication::applicationFilePath(),"--recover-journal",deadOwner["owner"].toString(),checkpoint.path()});
        check(differentNamespace.waitForStarted(5000) && differentNamespace.waitForFinished(12000)
              && differentNamespace.exitCode()==1 && savedFile.open(QIODevice::ReadOnly)
              && QJsonDocument::fromJson(savedFile.readAll()).object()==deadOwner,
              "A different network namespace adopted or altered protected source ownership");
        savedFile.close();
        QProcess recovery;
        recovery.start(QCoreApplication::applicationFilePath(),{"--recover-journal",deadOwner["owner"].toString(),checkpoint.path()});
        check(recovery.waitForStarted(5000) && recovery.waitForFinished(12000),"Fresh protected source recovery exceeded its budget");
        check(recovery.exitStatus()==QProcess::NormalExit && recovery.exitCode()==0
              && !QFile::exists(checkpoint.filePath("source.json")),
              qPrintable("Fresh process failed source recovery: "+QString::fromUtf8(recovery.readAllStandardError())));
        if (stage=="partial") {
            const auto preserved = read({"route","show","table",savedTable});
            check(preserved.size()==1 && preserved.first().toObject()["protocol"]=="99"
                  && ipv4RoutePrefix(preserved.first().toObject())==target,"Partial-write recovery removed the foreign row or retained an owned row");
            ip({"route","del",target,"dev","original0","src",source,"proto","99",
                "metric",QString::number(deadOwner["metric"].toInteger()),"table",savedTable});
        }
        check(inventory()==baseline,"Crash-boundary recovery changed the original kernel inventory");
        std::cout << "PASS: source owner SIGKILL at " << stage.toStdString()
                  << ", fresh protected-journal recovery restored the exact kernel inventory\n";
    }

    for (const auto &stage : {QString("rule-pre"),QString("rule-post"),QString("routes-pre"),QString("routes-post")}) {
        for (const bool recreate : {false,true}) {
            if (recreate && !stage.endsWith("-pre")) continue;
            QTemporaryDir checkpoint;
            UnixNetworkJournal journal;
            const int directory = ::open(QFile::encodeName(checkpoint.path()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
            check(checkpoint.isValid() && directory>=0 && journal.open(directory,owner).succeeded(),"Open recovery crash fixture");
            ::close(directory);
            check(routes.apply(owner,"original0",source,gateway,{target},[&](const QJsonObject &record) {
                return record.isEmpty() ? journal.remove() : journal.store(record);
            }).succeeded(),"Apply durable recovery crash fixture");
            journal.close();
            QProcess recovery;
            recovery.start(QCoreApplication::applicationFilePath(),{"--recover-journal",owner.toString(QUuid::WithoutBraces),checkpoint.path(),stage});
            check(recovery.waitForStarted(5000) && recovery.waitForReadyRead(5000),"Reach independent source recovery crash boundary");
            const auto interrupted = QJsonDocument::fromJson(recovery.readLine()).object();
            QFile savedFile(checkpoint.filePath("source.json"));
            check(!interrupted.isEmpty() && savedFile.open(QIODevice::ReadOnly)
                  && QJsonDocument::fromJson(savedFile.readAll()).object()==interrupted,"Recovery readiness preceded its durable checkpoint");
            savedFile.close();
            recovery.kill();
            check(recovery.waitForFinished(5000) && recovery.exitStatus()==QProcess::CrashExit,"Terminate the isolated recovery fixture");
            const auto rule = QStringList{"priority","1","from",source+"/32","table",table,"protocol","4"};
            const auto route = QStringList{target,"dev","original0","via",gateway,"src",source,"proto","4","metric",metric,"table",table};
            if (recreate) {
                const auto row = stage=="rule-pre" ? rule : route;
                const auto kind = stage=="rule-pre" ? QString("rule") : QString("route");
                const auto original = inventory();
                ip(QStringList{kind,"del"}+row);ip(QStringList{kind,"add"}+row);
                check(inventory()==original,"Same-value recreation changed the crash fixture");
            }
            const auto beforeRestart = inventory();
            QProcess restarted;
            const auto retry = [&] {
                restarted.start(QCoreApplication::applicationFilePath(),{"--recover-journal",owner.toString(QUuid::WithoutBraces),checkpoint.path()});
                check(restarted.waitForStarted(5000) && restarted.waitForFinished(12000),"Restarted recovery exceeded its budget");
            };
            retry();
            if (stage.endsWith("-pre")) {
                check(restarted.exitCode()==1 && inventory()==beforeRestart
                      && QString::fromUtf8(restarted.readAllStandardError()).contains("unresolved")
                      && savedFile.open(QIODevice::ReadOnly) && QJsonDocument::fromJson(savedFile.readAll()).object()==interrupted,
                      "Cold recovery guessed ownership after an interrupted deletion or lost the recovery record");
                savedFile.close();
                if (recreate) ip(QStringList{stage=="rule-pre" ? "rule" : "route","del"}+(stage=="rule-pre" ? rule : route));
                // The original creating instance still knows it never attempted these deletions.
                check(routes.restore(owner).succeeded(),"The authoritative fixture owner failed to clean its original state");
                retry();
            }
            check(restarted.exitStatus()==QProcess::NormalExit && restarted.exitCode()==0
                  && !QFile::exists(checkpoint.filePath("source.json")) && routes.restore(owner).succeeded() && inventory()==baseline,
                  "Restarted recovery failed to finish after interrupted objects were confirmed absent");
            std::cout << "PASS: recovery SIGKILL at " << stage.toStdString() << (recreate ? " with same-value foreign recreation" : "")
                      << ", protected duties preserved or durably completed\n";
        }
    }
    std::cout << "PASS: recovery checkpoints reject storage failures and concurrent kernel changes; durable removal retries preserve new foreign references\n";

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply saved ownership external-reference fixture");
    const auto savedReference = routes.snapshot();
    ip({"rule","add","priority","100","table",table,"protocol","99"});
    const auto referencedRecovery = inventory();
    LinuxOwnedRouteTable restarted;
    check(!restarted.recover(owner,savedReference).succeeded() && restarted.snapshot()==savedReference
          && inventory()==referencedRecovery,"Fresh recovery deleted an external reference or discarded saved responsibilities");
    ip({"rule","del","priority","100","table",table,"protocol","99"});
    check(restarted.restore(owner).succeeded() && routes.restore(owner).succeeded() && inventory()==baseline,
          "Fresh recovery could not retry after an external reference disappeared");

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply unconfirmed saved-write fixture");
    auto unconfirmed = routes.snapshot();
    auto intended = unconfirmed["routes"].toArray();
    for (int i=0; i<intended.size(); ++i) { auto entry = intended[i].toObject();entry["applied"] = QJsonObject{};intended[i] = entry; }
    unconfirmed["routes"] = intended;unconfirmed["rule_applied"] = QJsonObject{};
    check(restarted.recover(owner,unconfirmed).succeeded() && routes.restore(owner).succeeded() && inventory()==baseline,
          "Fresh recovery could not confirm and undo its recorded unconfirmed writes");
    ip({"route","add","198.18.9.0/24","dev","original0","table",table,"proto","99"});
    const auto foreignTable = inventory();
    check(!routes.apply(owner,"original0",source,gateway,{target}).succeeded() && routes.snapshot().isEmpty()
          && inventory()==foreignTable,"An existing private table was adopted");
    ip({"route","del","198.18.9.0/24","dev","original0","table",table,"proto","99"});
    ip({"rule","add","priority","100","table",table,"protocol","99"});
    const auto foreignReference = inventory();
    check(!routes.apply(owner,"original0",source,gateway,{target}).succeeded() && inventory()==foreignReference,
          "An existing table reference was adopted");
    ip({"rule","del","priority","100","table",table,"protocol","99"});

    int routeReads = 0;
    bool sawApplied = false;
    LinuxOwnedRouteTable failedRead([&](const QString &program,const QStringList &args) {
        if (args.contains("route") && ++routeReads==2) {
            sawApplied = inventory()!=baseline;
            return PlatformCommandResult{{Status::Failed,"Injected post-apply read failure"},{}};
        }
        return runPlatformCommand(program,args);
    });
    check(!failedRead.apply(QUuid::createUuid(),"original0",source,gateway,{target}).succeeded() && sawApplied
          && failedRead.snapshot().isEmpty() && inventory()==baseline,"Failed readback did not roll back real source operations");

    bool block = false;
    LinuxOwnedRouteTable retry([&](const QString &program,const QStringList &args) {
        if (block) return PlatformCommandResult{{Status::Failed,"Injected recovery read failure"},{}};
        return runPlatformCommand(program,args);
    });
    check(retry.apply(QUuid::createUuid(),"original0",source,gateway,{target}).succeeded(),"Apply recovery retry fixture");
    const auto retryOwner = QUuid(retry.snapshot()["owner"].toString());
    const auto retryState = inventory();block = true;
    check(!retry.restore(retryOwner).succeeded() && !retry.snapshot().isEmpty() && inventory()==retryState,
          "Failed recovery discarded ownership or changed state");
    block = false;
    check(retry.restore(retryOwner).succeeded() && retry.snapshot().isEmpty() && inventory()==baseline,"Recovery retry did not clean the original state");

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply external reference fixture");
    ip({"rule","add","priority","100","table",table,"protocol","99"});
    const auto referenced = inventory();
    check(!routes.restore(owner).succeeded() && !routes.snapshot().isEmpty() && inventory()==referenced,
          "An external table reference lost its routing data or ownership responsibility");
    ip({"rule","del","priority","100","table",table,"protocol","99"});
    check(routes.restore(owner).succeeded() && inventory()==baseline,"Recovery after removing an external reference failed");
    bool duplicateRead = false;
    LinuxOwnedRouteTable ambiguous([&](const QString &program,const QStringList &args) {
        auto result = runPlatformCommand(program,args);
        if (duplicateRead && args.contains("rule")) {
            auto rows = QJsonDocument::fromJson(result.output.toUtf8()).array();
            // Kernels can reject duplicate inserts; exercise uncertain readback against real unchanged state.
            for (const auto &value : rows) if (value.toObject()["table"]==table) { rows.append(value);break; }
            result.output = QString::fromUtf8(QJsonDocument(rows).toJson(QJsonDocument::Compact));
        }
        return result;
    });
    check(ambiguous.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply ambiguous reference fixture");
    duplicateRead = true;
    const auto duplicate = inventory();
    check(!ambiguous.restore(owner).succeeded() && inventory()==duplicate && !ambiguous.snapshot().isEmpty(),
          "Duplicate rule identities were guessed during recovery");
    duplicateRead = false;
    check(ambiguous.restore(owner).succeeded() && inventory()==baseline,"Recovery after duplicate reference resolution failed");

    int malformed = 0;
    LinuxOwnedRouteTable invalidRead([&](const QString &program,const QStringList &args) {
        auto result = runPlatformCommand(program,args);
        if ((malformed==1 && args.contains("route")) || (malformed==2 && args.contains("rule"))) {
            auto rows = QJsonDocument::fromJson(result.output.toUtf8()).array();
            for (int i=0; i<rows.size(); ++i) {
                auto row = rows[i].toObject();
                if (row["table"]==table) { row.remove("table");rows[i]=row;break; }
            }
            result.output = QString::fromUtf8(QJsonDocument(rows).toJson(QJsonDocument::Compact));
        }
        return result;
    });
    check(invalidRead.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply malformed recovery snapshot fixture");
    const auto complete = inventory();
    for (const int mode : {1,2}) {
        malformed = mode;
        check(!invalidRead.restore(owner).succeeded() && !invalidRead.snapshot().isEmpty() && inventory()==complete,
              "Missing table data was mistaken for absent owned state during recovery");
    }
    malformed = 0;
    check(invalidRead.restore(owner).succeeded() && inventory()==baseline,"Recovery after complete table facts returned failed");

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply non-lookup foreign rule fixture");
    ip({"rule","add","priority","100","blackhole"});ip({"rule","add","priority","101","goto","200"});
    check(routes.restore(owner).succeeded(),"Valid terminal or goto rules were treated as malformed lookup data");
    check(read({"rule","show"}).size()==baselineRuleCount+2,"Foreign terminal/goto rules were removed");
    ip({"rule","del","priority","100"});ip({"rule","del","priority","101"});
    check(inventory()==baseline,"Non-lookup foreign rule recovery changed unrelated state");

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply external route change fixture");
    ip({"route","replace",target,"dev","original0","via","192.0.2.3","src",source,"proto","4","metric",metric,"table",table});
    check(routes.restore(owner).succeeded() && routes.snapshot().isEmpty(),"Known external next-hop change was not preserved");
    check(read({"route","show","table",table}).size()==1,"Unchanged owned source routes were left or external route was removed");
    ip({"route","del",target,"dev","original0","via","192.0.2.3","src",source,"proto","4","metric",metric,"table",table});
    check(inventory()==baseline,"External route fixture cleanup changed unrelated state");

    bool interfere = false;
    LinuxOwnedRouteTable race([&](const QString &program,const QStringList &args) {
        const auto readback = runPlatformCommand(program,args);
        if (interfere && args.contains("rule")) {
            interfere = false;
            ip({"rule","del","priority","1","from",source+"/32","table",table,"protocol","4"});
            ip({"rule","add","priority","1","from","192.0.2.99/32","table",table,"protocol","4"});
        }
        return readback;
    });
    check(race.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply rule deletion race fixture");
    interfere = true;
    check(!race.restore(owner).succeeded() && !race.snapshot().isEmpty() && read({"route","show","table",table}).size()==2,
          "Changed source rule was deleted or its route table was cleared after a failed guarded delete");
    ip({"rule","del","priority","1","from","192.0.2.99/32","table",table,"protocol","4"});
    check(race.restore(owner).succeeded() && inventory()==baseline,"Recovery after a rule change did not finish");

    bool reinsert = false;
    LinuxOwnedRouteTable recreated([&](const QString &program,const QStringList &args) {
        if (reinsert && args.contains("route")) {
            bool present = false;
            for (const auto &value : read({"rule","show"})) present |= value.toObject()["table"]==table;
            if (!present) {
                reinsert = false;
                ip({"rule","add","priority","1","from",source+"/32","table",table,"protocol","4"});
            }
        }
        return runPlatformCommand(program,args);
    });
    check(recreated.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply recreated rule fixture");
    reinsert = true;
    check(!recreated.restore(owner).succeeded() && recreated.snapshot()["rule_pending"]==false,
          "A newly recreated rule was adopted after confirmed deletion");
    const auto recreatedState = inventory();
    check(!recreated.restore(owner).succeeded() && inventory()==recreatedState,
          "Retry deleted a recreated external rule or its route table");
    LinuxOwnedRouteTable recreatedRestart;
    check(!recreatedRestart.recover(owner,recreated.snapshot()).succeeded()
          && recreatedRestart.snapshot()["rule_pending"]==false && inventory()==recreatedState,
          "Restart adopted the same-value rule recreated after confirmed deletion");
    ip({"rule","del","priority","1","from",source+"/32","table",table,"protocol","4"});
    check(recreatedRestart.restore(owner).succeeded() && recreated.restore(owner).succeeded() && inventory()==baseline,
          "Recovery after recreated external rule removal failed");

    bool reference = true;
    LinuxOwnedRouteTable concurrentReference([&](const QString &program,const QStringList &args) {
        const auto readback = runPlatformCommand(program,args);
        if (reference && args.contains("rule")) {
            reference = false;
            ip({"rule","add","priority","100","table",table,"protocol","99"});
        }
        return readback;
    });
    check(!concurrentReference.apply(owner,"original0",source,gateway,{target}).succeeded()
          && !concurrentReference.snapshot().isEmpty(),"Concurrent external reference published success or discarded cleanup records");
    ip({"rule","del","priority","100","table",table,"protocol","99"});
    check(concurrentReference.restore(owner).succeeded() && inventory()==baseline,"Recovery after concurrent external table reference failed");

    bool insert = true;
    LinuxOwnedRouteTable partial([&](const QString &program,const QStringList &args) {
        const auto readback = runPlatformCommand(program,args);
        if (insert && args.contains("rule")) {
            insert = false;
            ip({"route","add",target,"dev","original0","src",source,"proto","99","metric",metric,"table",table});
        }
        return readback;
    });
    check(!partial.apply(owner,"original0",source,gateway,{target}).succeeded() && partial.snapshot().isEmpty()
          && read({"route","show","table",table}).size()==1,"Real partial batch failure did not preserve foreign route and roll back the owned gateway");
    ip({"route","del",target,"dev","original0","src",source,"proto","99","metric",metric,"table",table});
    check(inventory()==baseline,"Partial apply recovery changed unrelated state");

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply link-down recovery fixture");
    ip({"link","set","original0","down"});
    check(routes.restore(owner).succeeded() && routes.snapshot().isEmpty(),"A derived linkdown flag prevented owned route recovery");
    ip({"link","set","original0","up"});
    check(inventory()==baseline,"Link-down recovery changed unrelated state");

    ip({"address","add","192.0.2.9/24","dev","original0","label","original0:alt"});
    check(routes.apply(owner,"original0","192.0.2.9",gateway,{target}).succeeded()
          && lookup("192.0.2.9")["table"]==table,"An address alias was not recognized on its actual interface");
    check(routes.restore(owner).succeeded(),"Restore source routing for the aliased address");
    ip({"address","del","192.0.2.9/24","dev","original0"});
    check(inventory()==baseline,"Alias recovery changed unrelated state");

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply interface rename fixture");
    ip({"link","set","original0","down"});ip({"link","set","original0","name","renamed0"});
    const auto renamed = inventory();
    check(!routes.restore(owner).succeeded() && !routes.snapshot().isEmpty() && inventory()==renamed,
          "Renamed original interface lost recovery ownership or reached writes");
    ip({"link","set","renamed0","name","original0"});ip({"link","set","original0","up"});
    check(routes.restore(owner).succeeded() && inventory()==baseline,"Recovery after restoring original interface identity failed");

    const int count = LinuxRouteSnapshotRows-read({"route","show","table","all"}).size()-1;
    QStringList bulk;
    for (int i=0; i<count; ++i) bulk.append(QString("198.20.%1.%2/32").arg(i/256).arg(i%256));
    check(!routes.apply(owner,"original0",source,gateway,bulk+QStringList{"198.21.0.1/32"}).succeeded()
          && routes.snapshot().isEmpty() && inventory()==baseline,"Route capacity was checked after writing instead of before");
    check(routes.apply(owner,"original0",source,gateway,bulk).succeeded()
          && read({"route","show","table","all"}).size()==LinuxRouteSnapshotRows,"Largest complete source route snapshot was rejected or truncated");
    const auto bulkRecord = QJsonDocument(routes.snapshot()).toJson(QJsonDocument::Compact);
    check(restarted.recover(owner,QJsonDocument::fromJson(bulkRecord).object()).succeeded()
          && routes.restore(owner).succeeded() && inventory()==baseline,"Full-capacity saved source recovery failed");
    {
        const auto beforeLoss = inventory();
        ip({"link","add","vanished0","type","dummy"});ip({"link","set","vanished0","up"});
        ip({"address","add","192.0.3.1/24","dev","vanished0"});
        LinuxOwnedRouteTable disappearing;
        check(disappearing.apply(owner,"vanished0","192.0.3.1",{},{target}).succeeded(),"Own source lookup before interface loss");
        const auto saved = disappearing.snapshot();ip({"link","del","vanished0"});
        LinuxOwnedRouteTable recovered;
        check(recovered.recover(owner,saved).succeeded() && recovered.snapshot().isEmpty() && inventory() == beforeLoss,
              "A genuinely removed original device retained its owned lookup or changed unrelated state");
    }
    check(capture.restore(tun).succeeded(),"Restore the formal capture fixture");tun.close();baseline=inventory();
    check(::setgroups(0,nullptr)==0 && ::setresgid(65534,65534,65534)==0 && ::setresuid(65534,65534,65534)==0,"Permanently drop device privileges");
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3,0};__user_cap_data_struct caps[2]{};
    check(::syscall(SYS_capget,&header,caps)==0 && (caps[0].effective|caps[1].effective|caps[0].permitted|caps[1].permitted)==0,"Retained route capabilities");
    const auto denied = routes.apply(owner,"original0",source,gateway,{target});
    check(denied.status==Status::PermissionDenied && routes.snapshot().isEmpty() && inventory()==baseline,
          "Actual unprivileged source operation changed state or hid permission denial");
    std::cout << "PASS: owned source tables/rules, partial rollback, external references/changes, guarded rule deletion, retry, linkdown and permission denial\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';return 1;
}
