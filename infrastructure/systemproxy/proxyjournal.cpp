#include "infrastructure/systemproxy/proxyjournal.h"

CredentialResult ProxyRecoveryJournal::load()
{
    loaded=false;pending.reset();pendingRemoval=removalUncertain=false;
    if (!CredentialStore::validKey(key)) return {CredentialStatus::InvalidArgument,{}};
    auto result=credentials.read(key);
    if (result.status==CredentialStatus::NotFound) {
        loaded=true;present=false;known.clear();return result;
    }
    if (!result.succeeded()) return result;
    if (result.value.size()>CredentialStore::MaxBytes) return {CredentialStatus::Limit,{}};
    if (result.value.isEmpty()) return {CredentialStatus::Failed,{}};
    loaded=present=true;known=result.value;return result;
}

CredentialResult ProxyRecoveryJournal::checkpoint(const QByteArray &record)
{
    if (!CredentialStore::validKey(key)) return {CredentialStatus::InvalidArgument,{}};
    if (record.size()>CredentialStore::MaxBytes) return {CredentialStatus::Limit,{}};
    if (!loaded) return {CredentialStatus::Conflict,{}};
    const auto current=credentials.read(key);
    const bool absent=current.status==CredentialStatus::NotFound;
    if (!absent && !current.succeeded()) return current;
    const bool expected=absent ? !present || pendingRemoval
        : !removalUncertain && ((present && current.value==known) || (pending && current.value==*pending));
    if (!expected) {
        loaded=false;return {CredentialStatus::Conflict,{}};
    }
    if (record.isEmpty()) {
        if (!absent) {
            pendingRemoval=true;
            const auto removed=credentials.remove(key);
            removalUncertain=removed.succeeded() || removed.status==CredentialStatus::NotFound
                || removed.status==CredentialStatus::Unavailable || removed.status==CredentialStatus::Failed;
            if (!removed.succeeded() && removed.status!=CredentialStatus::NotFound) return removed;
        }
    } else {
        // A provider can publish before its acknowledgement is lost; retain both possible records.
        pending=record;
        const auto written=credentials.write(key,record);
        if (!written.succeeded()) return written;
    }
    const auto actual=credentials.read(key);
    if (record.isEmpty() ? actual.status==CredentialStatus::NotFound
                         : actual.succeeded() && actual.value==record) {
        known=record;present=!record.isEmpty();pending.reset();pendingRemoval=removalUncertain=false;
        return {CredentialStatus::Success,{}};
    }
    if (!actual.succeeded() && actual.status!=CredentialStatus::NotFound) return actual;
    loaded=false;return {CredentialStatus::Conflict,{}};
}
