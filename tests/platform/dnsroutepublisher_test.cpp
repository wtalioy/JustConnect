#include "infrastructure/dns/dnsroutepublisher.h"
#include <QCoreApplication>
#include <iostream>
#include <stdexcept>

class Core final : public CoreEngine
{
public:
    using CoreEngine::CoreEngine;
    bool start(const ConnectionProfile &, Operation) override { return false; }
    void stop() override {}
    void respond(const QJsonObject &) override {}
    void acknowledgeDNSRoutes(const QString &generation, const QString &id, bool applied) override {
        replies.append(QJsonObject{{"generation",generation},{"id",id},{"applied",applied}});
    }
    QJsonArray replies;
};
class Helper final : public QObject
{
    Q_OBJECT
public:
    enum class State { Active, Extending, Idle };
    enum class Operation { Extend, Restore };
    State state() const { return current; }
    void extend(const QStringList &addresses) { sent.append(addresses); current = State::Extending; }
    void cancel() { ++cancelled; current = State::Idle; }
    State current = State::Active;
    QList<QStringList> sent;
    int cancelled = 0;
signals:
    void finished(Helper::Operation operation, PlatformOperationResult result);
    void ownershipLost(PlatformOperationResult result);
};
static void check(bool ok,const char *message) { if (!ok) throw std::runtime_error(message); }
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv); Core core; Helper helper; bool available = true;
    DNSRoutePublisher<Helper> publisher(&core,&helper,nullptr,[&] { return available; });
    const auto request = [](const QString &generation,const QString &id) {
        return QJsonObject{{"generation",generation},{"request_id",id},{"addresses",QJsonArray{"198.18.0.7"}}};
    };
    emit core.dnsRoutesRequired(request("","before-start"));
    emit core.sessionStarted("one");
    emit core.dnsRoutesRequired(request("old","stale"));
    auto malformed = request("one","malformed"); malformed["addresses"] = QJsonArray{1};
    emit core.dnsRoutesRequired(malformed);
    available = false; emit core.dnsRoutesRequired(request("one","busy")); available = true;
    check(helper.sent.isEmpty() && core.replies.size() == 4,"Rejected publication reached the helper");
    for (const auto &reply : core.replies) check(!reply.toObject()["applied"].toBool(),"Rejected publication was acknowledged");
    emit core.dnsRoutesRequired(request("one","first"));
    emit core.dnsRoutesRequired(request("one","parallel"));
    emit helper.finished(Helper::Operation::Restore,{});
    check(helper.sent.size() == 1 && core.replies.size() == 5,"Parallel request or unrelated completion changed pending publication");
    helper.current = Helper::State::Active; emit helper.finished(Helper::Operation::Extend,{});
    check(core.replies.last().toObject() == QJsonObject{{"generation","one"},{"id","first"},{"applied",true}},"Confirmed helper result did not acknowledge its exact request");
    emit core.dnsRoutesRequired(request("one","lost")); emit helper.ownershipLost({});
    check(core.replies.last().toObject()["id"] == "lost" && !core.replies.last().toObject()["applied"].toBool(),"Lost ownership acknowledged a publication");
    helper.current = Helper::State::Active;
    emit core.dnsRoutesRequired(request("one","stopped")); emit core.finished(ConnectionError::NONE);
    const auto replies = core.replies.size(); emit helper.finished(Helper::Operation::Extend,{});
    check(helper.cancelled == 1 && core.replies.size() == replies,"Core stop retained a native extension or acknowledged its stale result");
    helper.current = Helper::State::Active; emit core.sessionStarted("two");
    emit core.dnsRoutesRequired(request("two","new"));
    emit helper.finished(Helper::Operation::Extend,{PlatformOperationResult::Status::Failed,"denied",true});
    check(core.replies.last().toObject() == QJsonObject{{"generation","two"},{"id","new"},{"applied",false}},"New generation inherited a previous publication or ignored failure");
    std::cout << "PASS: DNS publication correlation, serialization, helper failure/loss and generation cancellation\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
#include "dnsroutepublisher_test.moc"
