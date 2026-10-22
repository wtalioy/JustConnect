#include "infrastructure/platform/proxyjournal.h"
#include <QMap>
#include <iostream>
#include <stdexcept>

namespace {
using Status=CredentialStatus;
void check(bool okay,const char *message) { if (!okay) throw std::runtime_error(message); }
const QString key(64,'a'),other(64,'b');
const QByteArray first("original\0proxy record",21),second="updated proxy record";
class Store final : public CredentialStore {
public:
    QMap<QString,QByteArray> values;
    int writes=0,removes=0,unavailableReads=0;
    Status writeStatus=Status::Success,removeStatus=Status::Success;
    bool publishBeforeFailure=false,unavailableAfterWrite=false,unavailableAfterRemove=false,ignoreWrite=false;
    std::optional<QByteArray> recreate;
    CredentialResult read(const QString &key) override {
        if (unavailableReads) {--unavailableReads;return {Status::Unavailable,{}};}
        return values.contains(key)?CredentialResult{Status::Success,values[key]}:CredentialResult{Status::NotFound,{}};
    }
    CredentialResult write(const QString &key,const QByteArray &value) override {
        ++writes;
        if (!ignoreWrite && (writeStatus==Status::Success || publishBeforeFailure)) values[key]=value;
        if (unavailableAfterWrite) unavailableReads=1;
        return {writeStatus,{}};
    }
    CredentialResult remove(const QString &key) override {
        ++removes;
        if (removeStatus==Status::Success || publishBeforeFailure) values.remove(key);
        if (recreate) values[key]=*recreate;
        if (unavailableAfterRemove) unavailableReads=1;
        return {removeStatus,{}};
    }
};
}
int main() try {
    Store store;store.values[other]="unrelated secret";
    ProxyRecoveryJournal journal(store,key),invalid(store,"invalid/key");
    check(invalid.load().status==Status::InvalidArgument && invalid.checkpoint(first).status==Status::InvalidArgument,"Invalid journal key reached protected storage");
    check(journal.checkpoint(first).status==Status::Conflict && store.writes==0,"Journal mutation did not require an initial observation");
    check(journal.load().status==Status::NotFound && journal.checkpoint({}).succeeded() && store.removes==0,"Missing owned journal required an unsafe deletion");
    check(journal.checkpoint(first).succeeded() && store.values[key]==first,"Protected binary checkpoint was not confirmed");
    ProxyRecoveryJournal fresh(store,key);
    const auto reloaded=fresh.load();check(reloaded.succeeded() && reloaded.value==first,"Fresh journal lost original binary bytes");
    store.writeStatus=Status::PermissionDenied;
    check(journal.checkpoint(second).status==Status::PermissionDenied && store.values[key]==first,"Denied checkpoint changed protected data");
    store.writeStatus=Status::Success;check(journal.checkpoint(second).succeeded(),"Denied checkpoint could not be retried");
    store.writeStatus=Status::Unavailable;store.publishBeforeFailure=true;
    check(journal.checkpoint(first).status==Status::Unavailable && store.values[key]==first,"Lost publication acknowledgement became confirmed success");
    store.writeStatus=Status::Success;store.publishBeforeFailure=false;
    check(journal.checkpoint(first).succeeded(),"Owned unacknowledged publication could not be reconciled");
    store.unavailableAfterWrite=true;
    check(journal.checkpoint(second).status==Status::Unavailable,"Unread checkpoint was acknowledged without readback");
    store.unavailableAfterWrite=false;check(journal.checkpoint(second).succeeded(),"Readback failure could not be retried");
    const auto beforeLimit=store.writes;
    check(journal.checkpoint(QByteArray(CredentialStore::MaxBytes+1,'x')).status==Status::Limit && store.writes==beforeLimit,"Oversized checkpoint reached protected storage");
    store.writeStatus=Status::Limit;
    check(journal.checkpoint(first).status==Status::Limit && store.values[key]==second,"Native protected-store limit damaged the existing record");store.writeStatus=Status::Success;
    store.removeStatus=Status::PermissionDenied;
    check(journal.checkpoint({}).status==Status::PermissionDenied && store.values[key]==second,"Denied removal dropped its recovery record");
    store.removeStatus=Status::Success;check(journal.checkpoint({}).succeeded() && !store.values.contains(key),"Removal could not be retried");
    check(journal.checkpoint(first).succeeded(),"Recreate owned journal after confirmed removal");
    store.removeStatus=Status::Unavailable;store.publishBeforeFailure=true;
    check(journal.checkpoint({}).status==Status::Unavailable && !store.values.contains(key),"Lost removal acknowledgement became confirmed success");
    const auto removed=store.removes;store.removeStatus=Status::Success;store.publishBeforeFailure=false;
    check(journal.checkpoint({}).succeeded() && store.removes==removed,"Removal acknowledgement retry deleted another record");
    check(journal.checkpoint(first).succeeded(),"Seed unknown removal outcome");store.removeStatus=Status::Unavailable;
    check(journal.checkpoint({}).status==Status::Unavailable && store.values[key]==first,"Unknown removal changed the test baseline");
    const auto uncertainRemoves=store.removes;store.removeStatus=Status::Success;
    check(journal.checkpoint({}).status==Status::Conflict && store.removes==uncertainRemoves && store.values[key]==first,
          "Unknown removal outcome guessed ownership from matching bytes");
    check(journal.load().succeeded() && journal.checkpoint({}).succeeded(),"Explicitly reconcile the test-owned uncertain record");
    check(journal.checkpoint(first).succeeded(),"Seed deletion with unavailable readback");store.unavailableAfterRemove=true;store.recreate=first;
    check(journal.checkpoint({}).status==Status::Unavailable,"Unavailable deletion readback was acknowledged");
    store.unavailableAfterRemove=false;store.recreate.reset();const auto recreatedRemoves=store.removes;
    check(journal.checkpoint({}).status==Status::Conflict && store.removes==recreatedRemoves && store.values[key]==first,
          "Lost deletion readback reacquired an external same-value recreation");
    check(journal.load().succeeded() && journal.checkpoint({}).succeeded(),"Explicitly reconcile the test-owned recreated record");
    for (const auto &foreign:QList<QByteArray>{first,"external record"}) {
        check(journal.checkpoint(first).succeeded(),"Seed owned journal before external recreation");store.recreate=foreign;
        check(journal.checkpoint({}).status==Status::Conflict && store.values[key]==foreign,"Deletion did not detect external recreation");
        const auto count=store.removes;
        check(journal.checkpoint({}).status==Status::Conflict && store.removes==count && store.values[key]==foreign,"Retry deleted an externally recreated record");
        store.recreate.reset();check(journal.load().succeeded() && journal.checkpoint({}).succeeded(),"Explicitly reconcile only the test-owned external record");
    }
    check(journal.checkpoint(first).succeeded(),"Seed changed journal fixture");store.values[key]="external";
    const auto writes=store.writes,removes=store.removes;
    check(journal.checkpoint(second).status==Status::Conflict && journal.checkpoint({}).status==Status::Conflict
          && store.writes==writes && store.removes==removes && store.values[key]=="external","External record was overwritten or removed");
    check(journal.load().succeeded(),"Bind explicitly owned failure fixture");store.ignoreWrite=true;
    check(journal.checkpoint(second).status==Status::Conflict && store.values[key]=="external","Successful provider reply without publication was accepted");store.ignoreWrite=false;
    check(journal.load().succeeded(),"Bind record before external deletion");store.values.remove(key);
    check(journal.checkpoint(first).status==Status::Conflict && !store.values.contains(key),"External deletion was silently reclaimed");
    store.values[key]={};check(journal.load().status==Status::Failed && journal.checkpoint({}).status==Status::Conflict,"Empty unknown record was treated as absent ownership");
    store.values[key]=QByteArray(CredentialStore::MaxBytes+1,'x');check(journal.load().status==Status::Limit,"Oversized stored record was accepted");
    check(store.values[other]=="unrelated secret","Journal operation damaged another credential key");
    std::cout<<"PASS: protected proxy journal, fresh reads, failed/lost acknowledgements, limits, readback and external ownership\n";
} catch (const std::exception &error) {std::cerr<<error.what()<<'\n';return 1;}
