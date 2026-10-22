#include "presentation/dialogs/networkpolicywindow.h"
#include "application/networkpolicysession.h"
#include <QApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QPushButton>
#include <QPixmap>
#include <QThread>
#include <QTreeWidget>
#include <atomic>
#include <iostream>
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
    bool start(const ConnectionProfile &, Operation) override { return true; }
    void stop() override { emit finished(ConnectionError::NONE); }
    void respond(const QJsonObject &) override {}
    void updatePolicy(const QJsonObject &) override { ++policies; }
    void readSnapshot(Snapshot kind, const QString &id) override {
        QJsonObject data;
        if (kind == Snapshot::Network) data = {
            {"network", QJsonObject{
                {"interfaces", QJsonArray{QJsonObject{{"index", 7}, {"name", "LAN <bridge>&"}, {"up", true},
                    {"addresses", QJsonArray{"192.168.24.19/24"}}}}},
                {"routes", QJsonArray{QJsonObject{{"destination", "192.168.24.0/24"}, {"interface_index", 7}, {"table", 52}}}}}}};
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
    NetworkPolicySession session(&engine, [&] {
        return fail ? DnsSnapshot{{PlatformOperationResult::Status::TimedOut, {}}, {}}
                    : DnsSnapshot{{}, {{"resolver", "fixture"}}};
    });
    NetworkPolicyWindow window(&session);
    window.show();
    auto *tree = window.findChild<QTreeWidget *>("networkPolicyTargets");
    auto *refresh = window.findChild<QPushButton *>("refreshNetworkPolicy");
    auto *status = window.findChild<QLabel *>("networkPolicyStatus");
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
    check(lan && lan->text(1).contains("LAN <bridge>&") && lan->text(1).contains("52")
          && lan->text(2).contains("TCP") && lan->text(2).contains("22")
          && lan->text(2).contains("ssh.campus.test") && lan->text(2).contains("192.168.24.53"),
          "Native source, protocol/port or DNS role lost in explanation");
    if (app.arguments().size() == 2) {
        QCoreApplication::processEvents();
        check(window.grab().save(app.arguments()[1]), "Save controlled UI preview");
    }
    fail = true;
    refresh->click();
    until([&] { return session.status() == CoreEngine::RequestStatus::Failed; });
    check(tree->topLevelItemCount() == 0 && refresh->isEnabled(), "Failed refresh retained stale network details");
    fail = false;
    refresh->click();
    until([&] { return session.status() == CoreEngine::RequestStatus::Success; });
    check(tree->topLevelItemCount() == 3, "Retry did not restore complete inspection");
    engine.stop();
    check(tree->topLevelItemCount() == 0 && !refresh->isEnabled() && engine.policies == 0,
          "Inspection changed routing preference or retained disconnected facts");
    std::cout << "PASS: network inspection sources, resource roles, refresh recovery, stale clearing and no policy writes\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
