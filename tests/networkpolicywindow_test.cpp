#include "presentation/dialogs/networkpolicywindow.h"
#include "application/networkpolicysession.h"
#include <QApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QPushButton>
#include <QInputDialog>
#include <QPointer>
#include <QPixmap>
#include <QThread>
#include <QTreeWidget>
#include <QTabWidget>
#include <atomic>
#include <iostream>
#include <memory>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class Predicate> static void until(Predicate ready)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (!ready()) {
        check(elapsed.elapsed() < 5000, "Network inspection UI timed out");
        QCoreApplication::processEvents();
        QThread::msleep(1);
    }
}
class Engine : public CoreEngine
{
public:
    int policies = 0;
    QJsonObject lastPolicy;
    bool start(const ConnectionProfile &, Operation) override { return true; }
    void stop() override { emit finished(ConnectionError::NONE); }
    void respond(const QJsonObject &) override {}
    void updatePolicy(const QJsonObject &policy) override { ++policies; lastPolicy = policy; }
    void readSnapshot(Snapshot kind, const QString &id) override {
        QJsonObject data;
        if (kind == Snapshot::Network) data = {{"schema_version", 1},
            {"network", QJsonObject{
                {"interfaces", QJsonArray{QJsonObject{{"index", qint64(2147483648LL)}, {"name", "OTHER"}, {"addresses", QJsonArray{}}},
                    QJsonObject{{"index", qint64(2147483649LL)}, {"name", "LAN <bridge>&"}, {"up", true},
                    {"addresses", QJsonArray{"192.168.24.19/24"}}}}},
                {"routes", QJsonArray{QJsonObject{{"destination", "192.168.24.0/24"}, {"interface_index", qint64(2147483649LL)}, {"table", qint64(4000000000LL)}}}}}}};
        else data = {{"resources", QJsonObject{
            {"ip_resources", QJsonArray{QJsonObject{{"ip_min", "192.168.24.10"}, {"ip_max", "192.168.24.20"},
                {"protocol", "tcp"}, {"port_min", 22}, {"port_max", 22}}}},
            {"dns_records", QJsonObject{{"ssh.campus.test", QJsonArray{"192.168.24.12"}}}},
            {"campus_dns", "192.168.24.53"}, {"campus_dns_enabled", false}}}};
        emit snapshotReady(kind, id, data, RequestStatus::Success);
    }
};

int main(int argc, char **argv) try
{
    QApplication app(argc, argv);
    Engine engine;
    std::atomic_bool fail = false;
    const auto readDns = [&] {
        return fail ? DnsSnapshot{{PlatformOperationResult::Status::TimedOut, {}}, {}}
                    : DnsSnapshot{{}, {
                        {"resolved", QJsonObject{{"status", "available"}, {"Domains", QJsonArray{
                            QJsonObject{{"domain", "."}, {"interface_index", 0}, {"route_only", true}},
                            QJsonObject{{"domain", "mesh.test"}, {"interface_index", qint64(2147483649LL)}, {"route_only", false}}}}}},
                        {"nrpt", QJsonArray{QJsonObject{{"Namespace", QJsonArray{"host", ".mesh.test"}}}}},
                        {"dynamic_store", QJsonObject{
                            {"State:/Network/Service/a/DNS", QJsonObject{{"SupplementalMatchDomains", QJsonArray{""}}}},
                            {"Setup:/Network/Service/a/DNS", QJsonObject{{"SearchDomains", QJsonArray{"saved.test"}}}}}}}};
    };
    NetworkPolicySession session(&engine, readDns);
    NetworkPolicyWindow window(&session);
    window.show();
    auto *tree = window.findChild<QTreeWidget *>("networkPolicyTargets");
    auto *refresh = window.findChild<QPushButton *>("refreshNetworkPolicy");
    auto *status = window.findChild<QLabel *>("networkPolicyStatus");
    auto *dns = window.findChild<QTreeWidget *>("networkPolicyDnsNamespaces");
    auto *tabs = window.findChild<QTabWidget *>();
    check(tree && refresh && status && tree->topLevelItemCount() == 0 && !refresh->isEnabled(), "Inactive model became actionable");
    emit engine.sessionStarted("1");
    check(tree->topLevelItemCount() == 0, "Pending model retained rows");
    emit engine.connectionEstablished();
    until([&] { return session.status() == CoreEngine::RequestStatus::Success; });
    check(tree->topLevelItemCount() == 3 && refresh->isEnabled(), "Complete original ranges not shown");
    QTreeWidgetItem *lan = nullptr;
    for (int i = 0; i < tree->topLevelItemCount(); ++i) {
        auto *item = tree->topLevelItem(i);
        if (item->text(0) == "192.168.24.0/24") lan = item;
    }
    check(lan && lan->text(1).contains("LAN <bridge>&") && lan->text(1).contains("4000000000") && !lan->text(1).contains("OTHER")
          && lan->text(2).contains("TCP") && lan->text(2).contains("22")
          && lan->text(2).contains("ssh.campus.test") && lan->text(2).contains("192.168.24.53"),
          "Native source, protocol/port or DNS role lost in explanation");
    check(lan->toolTip(2)==lan->text(2), "Long overlap details became inaccessible in a narrow column");
    check(dns && tabs && dns->topLevelItemCount() == 7, "Native and reserved DNS namespace sources are reachable in a separate tab");
    tabs->setCurrentWidget(dns);
    check(dns->isVisible() && dns->topLevelItem(0)->text(0).contains("根域")
          && dns->topLevelItem(1)->text(1).contains("搜索后缀及路由域")
          && dns->topLevelItem(1)->text(2).contains("LAN <bridge>&")
          && dns->topLevelItem(2)->text(0) == "host" && dns->topLevelItem(2)->text(1).contains("原生表达式"),
          "DNS root, native NRPT expression or original interface source misrepresented");
    check(dns->topLevelItem(0)->text(3).isEmpty() && dns->topLevelItem(2)->text(3).contains("host*")
          && dns->topLevelItem(6)->text(0)=="localhost", "Root became blanket protection, prefix became exact or reserved loopback name was lost");
    bool saved=false, current=false;
    for(int i=0;i<dns->topLevelItemCount();++i) {
        auto *item=dns->topLevelItem(i);
        if(item->text(0)=="saved.test") saved=item->text(2).startsWith("已保存 DNS 配置") && item->text(3).isEmpty();
        if(item->text(0).contains("根域") && item->text(2).contains("State:")) current=item->text(2).startsWith("当前 DNS 配置");
    }
    check(saved && current,"Stored and current macOS resolver inputs collapsed into one active claim");
    auto *choose = window.findChild<QPushButton *>("chooseCampusAddress");
    auto *restore = window.findChild<QPushButton *>("restoreOriginalAddress");
    auto *preferenceStatus = window.findChild<QLabel *>("networkPolicyPreferenceStatus");
    auto lanRow = [&]() -> QTreeWidgetItem * {
        for (int i=0; i<tree->topLevelItemCount(); ++i)
            if (tree->topLevelItem(i)->text(0)=="192.168.24.0/24") return tree->topLevelItem(i);
        return nullptr;
    };
    auto activeInput = [&]() -> QInputDialog * {
        for (auto *input : window.findChildren<QInputDialog *>()) if (input->isVisible()) return input;
        check(false, "Address action did not open its input");
        return nullptr;
    };
    auto acknowledge = [&](CoreEngine::RequestStatus result) {
        const auto policy = engine.lastPolicy;
        emit engine.policyUpdated(policy["generation"].toString(), policy["revision"].toString(), result);
    };
    check(choose && restore && preferenceStatus && !choose->isEnabled() && !restore->isEnabled() && engine.policies==0,
          "Inspection wrote a policy without an explicit address selection");
    tabs->setCurrentIndex(0);
    tree->setCurrentItem(lanRow());
    check(choose->isEnabled(), "Actual IPv4 scope did not enable explicit selection");
    choose->click();
    auto *input = activeInput(); input->setTextValue("127.0.0.1"); input->accept();
    check(engine.policies==0 && preferenceStatus->text().contains("192.168.24.0/24"),
          "Input escaped its selected original scope");
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    choose->click(); input=activeInput(); input->setTextValue("192.168.24.12"); input->accept();
    check(engine.policies==1 && session.isPolicyUpdating() && session.campusAddresses().isEmpty()
          && !choose->isEnabled() && !restore->isEnabled() && lanRow()->text(3).isEmpty(),
          "UI published or allowed another unconfirmed preference");
    acknowledge(CoreEngine::RequestStatus::Success);
    check(session.campusAddresses()==QJsonArray{"192.168.24.12"} && lanRow()->text(3)=="192.168.24.12/32" && restore->isEnabled(),
          "Confirmed exact preference was not displayed or reversible");
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    tabs->setCurrentWidget(dns);
    if (app.arguments().size() == 2) {
        QCoreApplication::processEvents();
        check(window.grab().save(app.arguments()[1]+".dns.png"), "Save controlled DNS UI preview");
    }
    tabs->setCurrentIndex(0);
    if (app.arguments().size() == 2) {
        QCoreApplication::processEvents();
        check(window.grab().save(app.arguments()[1]), "Save controlled UI preview");
    }
    choose->click(); input=activeInput(); input->setTextValue("192.168.24.13"); input->accept();
    check(engine.policies==2, "Second explicit selection did not reach the core");
    acknowledge(CoreEngine::RequestStatus::Failed);
    check(session.campusAddresses()==QJsonArray{"192.168.24.12"} && !lanRow()->text(3).contains("192.168.24.13")
          && preferenceStatus->text().contains("未能应用"), "Failed preference replaced the confirmed UI state");
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    fail = true;
    refresh->click();
    until([&] { return session.status() == CoreEngine::RequestStatus::Failed; });
    check(tree->topLevelItemCount() == 0 && dns->topLevelItemCount() == 0 && refresh->isEnabled(), "Failed refresh retained stale network details");
    check(!choose->isEnabled() && restore->isEnabled(), "Failed DNS inspection disabled owned recovery or enabled a new choice");
    restore->click(); input=activeInput();
    check(input->textValue()=="192.168.24.12", "Recovery offered something other than confirmed exceptions");
    input->accept();
    check(engine.policies==3 && session.isPolicyUpdating(), "Owned recovery did not run after failed inspection");
    acknowledge(CoreEngine::RequestStatus::Success);
    check(session.campusAddresses().isEmpty() && !restore->isEnabled() && tree->topLevelItemCount()==0
          && session.status()==CoreEngine::RequestStatus::Failed, "Recovery invented successful inspection or retained the exception");
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    fail = false;
    refresh->click();
    until([&] { return session.status() == CoreEngine::RequestStatus::Success; });
    check(tree->topLevelItemCount() == 3, "Retry did not restore complete inspection");
    tree->setCurrentItem(lanRow()); choose->click();
    QPointer<QInputDialog> oldInput=activeInput(); oldInput->setTextValue("192.168.24.14");
    emit engine.sessionStarted("2");
    if (oldInput) oldInput->accept();
    check(engine.policies==3 && session.campusAddresses().isEmpty(), "Old generation input changed the new session");
    emit engine.connectionEstablished();
    until([&] { return session.status()==CoreEngine::RequestStatus::Success; });
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    check(!session.policyStatus(), "New session retained a previous policy result");
    tree->setCurrentItem(lanRow()); choose->click();
    input=activeInput(); input->setTextValue("192.168.24.15"); input->accept();
    acknowledge(CoreEngine::RequestStatus::Unavailable);
    check(engine.policies==4 && session.campusAddresses().isEmpty() && !restore->isEnabled()
          && preferenceStatus->text().contains("无法更新"), "Unavailable first update was hidden as an untouched policy");
    engine.stop();
    check(tree->topLevelItemCount() == 0 && dns->topLevelItemCount() == 0 && !refresh->isEnabled() && engine.policies == 4,
          "Stop changed routing preference or retained disconnected facts");
    Engine detachedEngine;
    auto owned = std::make_unique<NetworkPolicySession>(&detachedEngine, readDns);
    NetworkPolicyWindow detached(owned.get());
    detached.show();
    emit detachedEngine.sessionStarted("1");
    emit detachedEngine.connectionEstablished();
    until([&] { return owned->status() == CoreEngine::RequestStatus::Success; });
    auto *detachedTree=detached.findChild<QTreeWidget *>("networkPolicyTargets");
    for (int i=0; i<detachedTree->topLevelItemCount(); ++i)
        if (detachedTree->topLevelItem(i)->text(0)=="192.168.24.0/24") detachedTree->setCurrentItem(detachedTree->topLevelItem(i));
    detached.findChild<QPushButton *>("chooseCampusAddress")->click();
    QPointer<QInputDialog> detachedInput=detached.findChild<QInputDialog *>();
    check(detachedInput && detachedInput->isVisible(), "Detached window input was not opened");
    owned.reset();
    if (detachedInput) { detachedInput->setTextValue("192.168.24.12"); detachedInput->accept(); }
    check(!detached.isVisible() && detached.findChild<QTreeWidget *>("networkPolicyTargets")->topLevelItemCount() == 0
          && detached.findChild<QTreeWidget *>("networkPolicyDnsNamespaces")->topLevelItemCount() == 0
          && !detached.findChild<QPushButton *>("refreshNetworkPolicy")->isEnabled() && detachedEngine.policies==0,
          "Destroyed model retained stale network details in its window");
    std::cout << "PASS: network sources, exact confirmed choices, failure recovery, stale input and owned window lifecycle\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
