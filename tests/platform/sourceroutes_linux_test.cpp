#include "infrastructure/platform/linux/sourceroutes.h"
#include "infrastructure/platform/linux/tunroutes.h"
#include "infrastructure/platform/linux/iprouteutility.h"
#include <QCoreApplication>
#include <QJsonDocument>
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
        check(!missing.apply({},"original0",source,gateway,{target}).succeeded() && reads==0 && missing.snapshot().isEmpty(),
              "Missing ownership reached network operations");
        std::cout << "PASS: source routes require a connection owner before OS operations\n";
        return 0;
    }
    struct stat current{}, initial{};
    check(::geteuid()==0 && ::stat("/proc/self/ns/net",&current)==0 && ::stat("/proc/1/ns/net",&initial)==0
          && (current.st_dev!=initial.st_dev || current.st_ino!=initial.st_ino),"Refusing the host network namespace");
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
    check(routes.apply(owner,"original0",source,gateway,{target,target}).succeeded(),"Apply real source route table and rule");
    const auto snapshot = routes.snapshot();
    const auto table = QString::number(snapshot["table"].toInteger());
    const auto metric = QString::number(snapshot["metric"].toInteger());
    check(snapshot["routes"].toArray().size()==2 && lookup()["dev"]==tun.name()
          && lookup(source)["dev"]=="original0" && lookup(source)["table"]==table,
          "Actual bound source did not bypass the more specific TUN capture route");
    const auto active = inventory();
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
    check(routes.restore(owner).succeeded() && inventory()==baseline,"Direct source recovery changed original state");
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
    ip({"rule","del","priority","1","from",source+"/32","table",table,"protocol","4"});
    check(recreated.restore(owner).succeeded() && inventory()==baseline,"Recovery after recreated external rule removal failed");

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
    check(routes.restore(owner).succeeded() && inventory()==baseline,"Full-capacity source recovery failed");
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
