#include "infrastructure/platform/linux/sourceroutes.h"
#include "infrastructure/platform/linux/sourcejournal.h"
#include "infrastructure/platform/linux/tunroutes.h"
#include "infrastructure/platform/linux/iprouteutility.h"
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

int main(int argc, char **argv) try
{
    QCoreApplication app(argc,argv);
    using Status = PlatformOperationResult::Status;
    const QString source("192.0.2.1"), gateway("192.0.2.2"), target("198.18.0.6/32");
    const auto owner = QUuid::createUuid();
    int reads = 0;
    LinuxSourceRoutes missing([&](const QString &, const QStringList &) {
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
        LinuxSourceJournal journal;
        const auto opened = journal.open(directory,owner);::close(directory);
        check(opened.succeeded(),qPrintable(opened.detail));
        const auto pause = [](const QJsonObject &record) {
            std::cout << QJsonDocument(record).toJson(QJsonDocument::Compact).constData() << std::endl;
            std::cin.get();
            throw std::runtime_error("Crash-boundary fixture resumed without owner termination");
        };
        QJsonObject intent;
        int routeReads = 0, ruleReads = 0;
        LinuxSourceRoutes routes([&](const QString &program,const QStringList &args) {
            if (args.contains("route") && ++routeReads==3 && (stage=="applied" || stage=="partial")) pause(intent);
            const auto result = runPlatformCommand(program,args);
            if (args.contains("rule") && ++ruleReads==2 && stage=="partial")
                ip({"route","add",target,"dev","original0","src",source,"proto","99",
                    "metric",QString::number(intent["metric"].toInteger()),"table",QString::number(intent["table"].toInteger())});
            return result;
        });
        const auto result = routes.apply(owner,"original0",source,gateway,{target},[&](const QJsonObject &record) {
            intent = record;
            const auto saved = journal.store(record);
            if (saved.succeeded() && stage=="prepared") pause(record);
            return saved;
        });
        check(result.succeeded(),qPrintable(result.detail));
        const auto confirmed = journal.store(routes.snapshot());
        check(confirmed.succeeded(),qPrintable(confirmed.detail));
        pause(routes.snapshot());
    }
    if (argc==4 && app.arguments()[1]=="--recover-journal") {
        const auto id = QUuid(app.arguments()[2]);
        const int directory = ::open(QFile::encodeName(app.arguments()[3]).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        check(directory>=0,"Open the trusted source checkpoint directory");
        LinuxSourceJournal journal;
        const auto opened = journal.open(directory,id);::close(directory);
        check(opened.succeeded(),qPrintable(opened.detail));
        QJsonObject saved;
        auto result = journal.load(saved);
        LinuxSourceRoutes routes;
        if (result.succeeded()) result = routes.recover(id,saved);
        if (result.succeeded()) result = journal.remove();
        else if (!routes.snapshot().isEmpty()) {
            const auto checkpointed = journal.store(routes.snapshot());
            if (!checkpointed.succeeded()) result.detail += " Updated recovery record could not be persisted.";
        }
        check(result.succeeded() && routes.snapshot().isEmpty(),qPrintable(result.detail));
        std::cout << "PASS: fresh process loaded protected source ownership and synchronized its removal after recovery\n";
        return 0;
    }
    if (argc==6 && app.arguments()[1]=="--hold") {
        LinuxSourceRoutes routes;
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
    for (const auto &bad : {QString("default"),QString("0.0.0.0/0"),QString("198.18.0.7/24"),QString("198.018.0.6/32"),
                           QString("198.18.0.6")+QChar(0)+"\nrule del priority 0/32"})
        check(!missing.apply(owner,"original0",source,gateway,{bad}).succeeded() && reads==0,"Invalid prefix reached commands");
    check(!missing.apply(owner,"original0",source,gateway,{gateway+"/32"}).succeeded()
          && !missing.apply(owner,QString("original0")+QChar(0)+"\nrule del priority 0",source,gateway,{target}).succeeded()
          && !missing.apply(owner,"original0","192.0.2.99",gateway,{target}).succeeded()
          && reads==0 && inventory()==baseline,"Invalid interface/source changed network state");
    LinuxSourceRoutes routes;
    {
        QTemporaryDir checkpoint;
        const int directory = ::open(QFile::encodeName(checkpoint.path()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        LinuxSourceJournal journal;
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
        LinuxSourceRoutes changedRules([&](const QString &program,const QStringList &args) {
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
    invalid = snapshot;invalid["extra"] = true;invalidRecords.append(invalid);
    auto savedRoutes = snapshot["routes"].toArray();
    invalid = snapshot;savedRoutes.append(savedRoutes.first());invalid["routes"] = savedRoutes;invalidRecords.append(invalid);
    savedRoutes = snapshot["routes"].toArray();
    auto changedEntry = savedRoutes.last().toObject();auto changedRow = changedEntry["applied"].toObject();
    changedRow["gateway"] = "192.0.2.99";changedEntry["applied"] = changedRow;savedRoutes[savedRoutes.size()-1] = changedEntry;
    invalid = snapshot;invalid["routes"] = savedRoutes;invalidRecords.append(invalid);
    for (const auto &saved : invalidRecords)
        check(!missing.recover(owner,saved).succeeded() && reads==0 && missing.snapshot().isEmpty() && inventory()==active,
              "An invalid saved source record reached OS operations or retained partial authority");
    check(!routes.restore(QUuid::createUuid()).succeeded() && inventory()==active && routes.snapshot()==snapshot,
          "Another owner restored or discarded this connection's state");
    LinuxSourceRoutes collision;
    check(!collision.apply(QUuid::createUuid(),"original0",source,gateway,{target}).succeeded()
          && collision.snapshot().isEmpty() && inventory()==active,"Early rule conflict was adopted or changed");
    check(routes.restore(owner).succeeded() && routes.snapshot().isEmpty() && inventory()==baseline,"Normal source recovery changed original state");
    check(routes.restore(owner).succeeded() && inventory()==baseline,"Repeated source recovery changed original state");
    check(routes.apply(owner,"original0",source,{}, {target}).succeeded() && lookup(source)["dev"]=="original0"
          && !lookup(source).contains("gateway") && read({"route","show","table",table}).size()==1,
          "Direct original routes gained a fictitious gateway or lost source selection");
    LinuxSourceRoutes directRecovery;
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
        LinuxSourceJournal competing;
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

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply saved ownership external-reference fixture");
    const auto savedReference = routes.snapshot();
    ip({"rule","add","priority","100","table",table,"protocol","99"});
    const auto referencedRecovery = inventory();
    LinuxSourceRoutes restarted;
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
    LinuxSourceRoutes failedRead([&](const QString &program,const QStringList &args) {
        if (args.contains("route") && ++routeReads==2) {
            sawApplied = inventory()!=baseline;
            return PlatformCommandResult{{Status::Failed,"Injected post-apply read failure"},{}};
        }
        return runPlatformCommand(program,args);
    });
    check(!failedRead.apply(QUuid::createUuid(),"original0",source,gateway,{target}).succeeded() && sawApplied
          && failedRead.snapshot().isEmpty() && inventory()==baseline,"Failed readback did not roll back real source operations");

    bool block = false;
    LinuxSourceRoutes retry([&](const QString &program,const QStringList &args) {
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
    LinuxSourceRoutes ambiguous([&](const QString &program,const QStringList &args) {
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
    LinuxSourceRoutes invalidRead([&](const QString &program,const QStringList &args) {
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
    check(read({"rule","show"}).size()==5,"Foreign terminal/goto rules were removed");
    ip({"rule","del","priority","100"});ip({"rule","del","priority","101"});
    check(inventory()==baseline,"Non-lookup foreign rule recovery changed unrelated state");

    check(routes.apply(owner,"original0",source,gateway,{target}).succeeded(),"Apply external route change fixture");
    ip({"route","replace",target,"dev","original0","via","192.0.2.3","src",source,"proto","4","metric",metric,"table",table});
    check(routes.restore(owner).succeeded() && routes.snapshot().isEmpty(),"Known external next-hop change was not preserved");
    check(read({"route","show","table",table}).size()==1,"Unchanged owned source routes were left or external route was removed");
    ip({"route","del",target,"dev","original0","via","192.0.2.3","src",source,"proto","4","metric",metric,"table",table});
    check(inventory()==baseline,"External route fixture cleanup changed unrelated state");

    bool interfere = false;
    LinuxSourceRoutes race([&](const QString &program,const QStringList &args) {
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
    LinuxSourceRoutes recreated([&](const QString &program,const QStringList &args) {
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
    LinuxSourceRoutes recreatedRestart;
    check(!recreatedRestart.recover(owner,recreated.snapshot()).succeeded()
          && recreatedRestart.snapshot()["rule_pending"]==false && inventory()==recreatedState,
          "Restart adopted the same-value rule recreated after confirmed deletion");
    ip({"rule","del","priority","1","from",source+"/32","table",table,"protocol","4"});
    check(recreatedRestart.restore(owner).succeeded() && recreated.restore(owner).succeeded() && inventory()==baseline,
          "Recovery after recreated external rule removal failed");

    bool reference = true;
    LinuxSourceRoutes concurrentReference([&](const QString &program,const QStringList &args) {
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
    LinuxSourceRoutes partial([&](const QString &program,const QStringList &args) {
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

    const int count = 4096-read({"route","show","table","all"}).size()-1;
    QStringList bulk;
    for (int i=0; i<count; ++i) bulk.append(QString("198.20.%1.%2/32").arg(i/256).arg(i%256));
    check(!routes.apply(owner,"original0",source,gateway,bulk+QStringList{"198.21.0.1/32"}).succeeded()
          && routes.snapshot().isEmpty() && inventory()==baseline,"Route capacity was checked after writing instead of before");
    check(routes.apply(owner,"original0",source,gateway,bulk).succeeded()
          && read({"route","show","table","all"}).size()==4096,"Largest complete source route snapshot was rejected or truncated");
    const auto bulkRecord = QJsonDocument(routes.snapshot()).toJson(QJsonDocument::Compact);
    check(restarted.recover(owner,QJsonDocument::fromJson(bulkRecord).object()).succeeded()
          && routes.restore(owner).succeeded() && inventory()==baseline,"Full-capacity saved source recovery failed");
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
