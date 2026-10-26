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
    enum class Operation { Extend, Routes, Restore };
    State state() const { return current; }
    void extend(const QStringList &addresses) { sent.append(addresses); current = State::Extending; }
    void reconcile(const QStringList &prefixes) { routed.append(prefixes); current = State::Extending; }
    void cancel() { ++cancelled; current = State::Idle; }
    State current = State::Active;
    QList<QStringList> sent, routed;
    int cancelled = 0;
signals:
    void finished(Helper::Operation operation, PlatformOperationResult result);
    void ownershipLost(PlatformOperationResult result);
};
static void check(bool ok,const char *message) { if (!ok) throw std::runtime_error(message); }
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv); Core core; Helper helper; bool available = true;
    bool validExclusion = true;
    DNSRoutePublisher<Helper> publisher(&core,&helper,nullptr,[&] { return available; },
        [&](const QStringList &addresses) -> std::optional<QStringList> {
            check(addresses == QStringList{"198.18.0.7"},"Exclusion lost the requested addresses");
            if (!validExclusion) return {};
            return QStringList{"198.18.0.8/32"};
        });
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
    helper.current = Helper::State::Active;
    auto exclusion = request("two","original"); exclusion["exclude"] = true;
    const auto before = core.replies.size();
    emit core.dnsRoutesRequired(exclusion);
    check(helper.routed == QList<QStringList>{QStringList{"198.18.0.8/32"}} && core.replies.size() == before,
          "Original answer was acknowledged before capture withdrawal");
    emit helper.finished(Helper::Operation::Extend,{});
    check(core.replies.size() == before,"Unrelated extension acknowledged a withdrawal");
    helper.current = Helper::State::Active; emit helper.finished(Helper::Operation::Routes,{});
    check(core.replies.last().toObject() == QJsonObject{{"generation","two"},{"id","original"},{"applied",true}},
          "Confirmed withdrawal did not acknowledge the original answer");
    validExclusion = false;
    emit core.dnsRoutesRequired(exclusion);
    check(helper.routed.size() == 1 && !core.replies.last().toObject()["applied"].toBool(),
          "Invalid withdrawal reached the helper");
    exclusion["exclude"] = "true";
    emit core.dnsRoutesRequired(exclusion);
    check(helper.routed.size() == 1 && !core.replies.last().toObject()["applied"].toBool(),
          "Malformed exclusion direction reached the helper");
    validExclusion = true; exclusion["exclude"] = true;
    emit core.dnsRoutesRequired(exclusion);
    emit helper.finished(Helper::Operation::Routes,{PlatformOperationResult::Status::Failed,"denied",true});
    check(!core.replies.last().toObject()["applied"].toBool(),"Failed capture withdrawal acknowledged original DNS");
    helper.current = Helper::State::Active;
    emit core.dnsRoutesRequired(exclusion); emit core.finished(ConnectionError::NONE);
    const auto afterStop = core.replies.size(); emit helper.finished(Helper::Operation::Routes,{});
    check(helper.cancelled == 2 && core.replies.size() == afterStop,"Stopped withdrawal retained or acknowledged stale work");
    Core unsupportedCore; Helper unsupportedHelper;
    DNSRoutePublisher<Helper> unsupported(&unsupportedCore,&unsupportedHelper);
    emit unsupportedCore.sessionStarted("two"); emit unsupportedCore.dnsRoutesRequired(exclusion);
    check(unsupportedHelper.sent.isEmpty() && unsupportedHelper.routed.isEmpty()
          && !unsupportedCore.replies.last().toObject()["applied"].toBool(),"Missing exclusion support fell back to capture");
    std::cout << "PASS: DNS publication correlation, serialization, helper failure/loss and generation cancellation\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
#include "dnsroutepublisher_test.moc"
