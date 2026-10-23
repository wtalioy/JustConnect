#pragma once

static void checkpointTests() {
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=prior.invalid:3128","old.invalid","https://pac.invalid/original.pac"};
    const auto reset=[&] {
        states.clear();rasNames.clear();states[""]=original;
        denyQuery=denySet=ignoreSet=denyNotify=denyRas=false;
        writes=failAt=setCalls=queries=0;ignoreOption=0;
    };
    const auto restored=[&] {
        check(states[""].flags==original.flags && states[""].proxy==original.proxy
              && states[""].bypass==original.bypass && states[""].pac==original.pac,
              "Checkpoint recovery lost original WinINet values");
    };
    const auto denied=[] {return PlatformOperationResult{Status::PermissionDenied,"Injected protected storage denial"};};
    for(const bool initial:{true,false}) {
        reset();
        PlatformSystemProxyBackend owner(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
            if(record.isEmpty())return PlatformOperationResult{};
            const auto intent=record["connections"].toArray()[0].toObject()["intent"].toInteger();
            return initial || intent?denied():PlatformOperationResult{};
        });
        const auto result=owner.apply(config);
        check(!result.succeeded() && !result.mayHaveChanged && setCalls==0 && owner.recoverySnapshot().isEmpty(),
              "Denied prewrite storage reached WinINet or retained false ownership");restored();
    }
    reset();bool confirmationDenied=false;QJsonObject confirmed;
    PlatformSystemProxyBackend confirmation(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
        const auto entries=record["connections"].toArray();
        if(!entries.isEmpty() && entries[0].toObject()["written"].toInteger() && !confirmationDenied) {
            confirmationDenied=true;return denied();
        }
        confirmed=record;return PlatformOperationResult{};
    });
    const auto rejectedConfirmation=confirmation.apply(config);
    check(confirmationDenied && !rejectedConfirmation.succeeded() && !rejectedConfirmation.mayHaveChanged && confirmed.isEmpty(),
          "Rejected write confirmation did not roll back and release its native mutation");restored();
    struct Interrupted {};
    for(const auto &stage:QStringList{"prepared","unconfirmed","confirmed","restore","observed","recreated"}) {
        reset();QJsonObject durable;WinState installed;bool interrupted=false;
        {
            PlatformSystemProxyBackend owner(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
                const auto entries=record["connections"].toArray();
                const auto entry=entries.isEmpty()?QJsonObject{}:entries[0].toObject();
                const auto written=entry["written"].toInteger(),pending=entry["pending_restore"].toInteger();
                if(stage=="unconfirmed" && written)throw Interrupted{};
                if(stage=="recreated" && entry["released"].toInteger()==7)throw Interrupted{};
                if(stage=="observed" && entry["released"].toInteger()==4)throw Interrupted{};
                durable=record;
                if((stage=="prepared" && !entry["intent"].toInteger()) || (stage=="confirmed" && written)
                    || (stage=="restore" && pending))throw Interrupted{};
                return PlatformOperationResult{};
            });
            try {
                check(owner.apply(config).succeeded(),"Apply checkpoint boundary fixture");installed=states[""];
                if(stage=="observed")states[""].bypass=original.bypass;
                owner.clear();
            } catch(const Interrupted &) {interrupted=true;}
        }
        check(interrupted && !durable.isEmpty(),"Owned checkpoint boundary was not reached");
        if(stage=="recreated" || stage=="observed")states[""]=installed;
        const auto beforeCalls=setCalls;const auto observed=states[""];
        PlatformSystemProxyBackend fresh(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
            durable=record;return PlatformOperationResult{};
        });
        const auto result=fresh.recover(durable);
        if(stage=="prepared" || stage=="confirmed") {
            check(result.succeeded() && durable.isEmpty(),"Confirmed checkpoint did not recover completely");restored();
            if(stage=="prepared")check(setCalls==beforeCalls,"Prepared checkpoint changed native settings");
        } else {
            check(!result.succeeded() && result.mayHaveChanged && setCalls==beforeCalls && !durable.isEmpty()
                  && states[""].flags==observed.flags && states[""].proxy==observed.proxy && states[""].bypass==observed.bypass,
                  "Fresh checkpoint recovery reclaimed an unconfirmed same-value setting");
            check(!fresh.clear().succeeded() && setCalls==beforeCalls,"Retry guessed ownership of ambiguous native settings");
            states[""]=original;
            check(fresh.clear().succeeded() && durable.isEmpty(),"Externally resolved checkpoint retained ownership");restored();
        }
    }
    reset();bool block=false;QJsonObject durable;
    PlatformSystemProxyBackend owner(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
        const auto entries=record["connections"].toArray();
        if(block && !entries.isEmpty() && entries[0].toObject()["pending_restore"].toInteger())return denied();
        durable=record;return PlatformOperationResult{};
    });
    check(owner.apply(config).succeeded(),"Apply before denied restore checkpoint");const auto installed=states[""];
    block=true;const auto beforeCalls=setCalls;
    check(!owner.clear().succeeded() && setCalls==beforeCalls && states[""].proxy==installed.proxy,
          "Denied restore checkpoint reached WinINet");
    block=false;check(owner.clear().succeeded() && durable.isEmpty(),"Retry denied restore checkpoint");restored();

    reset();bool releaseDenied=false,observeRelease=false;
    PlatformSystemProxyBackend release(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
        const auto entries=record["connections"].toArray();
        if(observeRelease && !releaseDenied && !entries.isEmpty() && (entries[0].toObject()["released"].toInteger()&4)) {
            releaseDenied=true;return denied();
        }
        return PlatformOperationResult{};
    });
    check(release.apply(config).succeeded(),"Apply before release confirmation denial");const auto installedBypass=states[""].bypass;
    states[""].bypass=original.bypass;observeRelease=true;const auto beforeRelease=setCalls;
    check(!release.clear().succeeded() && releaseDenied && setCalls==beforeRelease,"Release confirmation denial reached a sibling setter");
    states[""].bypass=installedBypass;
    check(release.clear().succeeded() && states[""].bypass==installedBypass && states[""].proxy==original.proxy
          && states[""].flags==original.flags,"Live retry reacquired a field after release confirmation denial");

    reset();bool removeDenied=true;
    PlatformSystemProxyBackend removal(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
        if(record.isEmpty() && removeDenied)return denied();
        durable=record;return PlatformOperationResult{};
    });
    check(removal.apply(config).succeeded(),"Apply before final record removal denial");const auto recreated=states[""];
    check(!removal.clear().succeeded(),"Final record removal denial lost responsibility");restored();
    states[""]=recreated;const auto beforeRemoval=setCalls;removeDenied=false;
    PlatformSystemProxyBackend released(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
        durable=record;return PlatformOperationResult{};
    });
    check(released.recover(durable).succeeded() && durable.isEmpty() && setCalls==beforeRemoval && states[""].proxy==recreated.proxy,
          "Fresh record removal retry reacquired a released same-value setting");

    for(const bool restoring:{false,true}) {
        reset();bool changed=false;
        PlatformSystemProxyBackend waiting(WindowsProxyApi{query,set,entries},[&](const QJsonObject &record) {
            const auto entries=record["connections"].toArray();
            if(!entries.isEmpty()) {
                const auto entry=entries[0].toObject();
                const bool boundary=restoring?entry["pending_restore"].toInteger()!=0
                    :entry["intent"].toInteger()!=0 && !entry["written"].toInteger();
                if(boundary && !changed){changed=true;states[""].proxy="http=external-during-storage.invalid:8899";}
            }
            return PlatformOperationResult{};
        });
        if(restoring) {
            check(waiting.apply(config).succeeded(),"Apply before restore storage wait");
            check(waiting.clear().succeeded() && states[""].flags==(PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY)
                  && states[""].bypass==original.bypass,"Restore storage wait lost independent fields or enabled old mode");
        } else {
            const auto result=waiting.apply(config);
            check(!result.succeeded() && !result.mayHaveChanged && setCalls==0,"Apply storage wait overwrote an external native edit");
        }
        check(changed && states[""].proxy=="http=external-during-storage.invalid:8899" && states[""].pac==original.pac,
              "Storage wait lost external proxy or unmanaged PAC");
    }
    std::cout<<"PASS: Windows prewrite/restore checkpoints, lost confirmations, storage denials and external ownership\n";
}
