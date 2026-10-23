#pragma once
#include "tests/credentialstorefixture.h"
#include <QScopeGuard>
#include <QCryptographicHash>
#include <QUuid>

static void persistenceTests() {
    const QString key(64,'c'),other(64,'d');
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=user:fixture-secret@prior.invalid:3128","old.invalid","https://pac.invalid/?token=fixture"};
    const auto reset=[&] {
        states.clear();rasNames.clear();states[""]=original;
        denyQuery=denySet=ignoreSet=denyNotify=denyRas=false;
        writes=failAt=setCalls=queries=0;ignoreOption=0;beforeProxySet={};
    };
    const auto restored=[&] {
        check(states[""].flags==original.flags && states[""].proxy==original.proxy
              && states[""].bypass==original.bypass && states[""].pac==original.pac,
              "Protected Windows recovery lost original values");
    };
    QJsonObject record;WinState installed;
    reset();
    {
        MemoryCredentialStore store;store.values[other]="unrelated credential";int reads=0;
        store.beforeRead=[&]{++reads;};
        const auto releaseHook=qScopeGuard([]{beforeProxySet={};});
        beforeProxySet=[&] {
            const auto bytes=store.values.value(key);const auto document=QJsonDocument::fromJson(bytes);
            const auto entries=document.object()["connections"].toArray();
            check(document.isObject() && document.toJson(QJsonDocument::Compact)==bytes && entries.size()==1,
                  "Native Windows mutation preceded canonical protected publication");
            const auto entry=entries[0].toObject();
            check(entry["intent"].toInteger()!=0 && (entry["pending_restore"].toInteger()!=0 || entry["written"].toInteger()==0),
                  "Native Windows mutation preceded its protected intent");
        };
        {
            PersistentProxyBackend owner(store,key,WindowsProxyApi{query,set,entries});
            check(reads==0 && queries==0 && setCalls==0,"Persistent constructor performed I/O before recovery ownership");
            check(owner.apply(config).succeeded(),"Apply through the shared protected Windows adapter");
            record=QJsonDocument::fromJson(store.values.value(key)).object();
            installed=states[""];
        }
        PersistentProxyBackend fresh(store,key,WindowsProxyApi{query,set,entries});
        const auto result=fresh.check(config);
        check(result.result.succeeded() && result.conflict && !result.active && !store.values.contains(key)
              && store.values[other]=="unrelated credential","Fresh protected check lost prior recovery or touched another credential");restored();
        check(fresh.apply(config).succeeded() && fresh.clear().succeeded() && !store.values.contains(key),
              "Protected Windows owner could not be reused after recovery");restored();
    }
    reset();
    {
        MemoryCredentialStore store;auto ambiguous=record;auto connections=record["connections"].toArray();
        auto connection=connections[0].toObject();connection["written"]=0;connections[0]=connection;ambiguous["connections"]=connections;
        store.values[key]=QJsonDocument(ambiguous).toJson(QJsonDocument::Compact);states[""]=installed;
        PersistentProxyBackend fresh(store,key,WindowsProxyApi{query,set,entries});
        check(!fresh.apply(config).succeeded() && !fresh.check(config).result.succeeded() && setCalls==0 && store.values.contains(key)
              && states[""].proxy==installed.proxy,"Unresolved protected Windows ownership allowed a new application");
        states[""]=original;
        check(fresh.apply(config).succeeded() && QJsonDocument::fromJson(store.values[key]).object()["owner"]!=record["owner"],
              "Resolved protected Windows ownership did not permit a new owner");
        check(fresh.clear().succeeded() && !store.values.contains(key),"New protected Windows owner did not release its record");restored();
    }
    for(const auto failure:{CredentialStatus::Locked,CredentialStatus::Unavailable,CredentialStatus::PermissionDenied,CredentialStatus::Cancelled}) {
        reset();MemoryCredentialStore store;store.failure=failure;
        PersistentProxyBackend owner(store,key,WindowsProxyApi{query,set,entries});const auto result=owner.apply(config);
        check(!result.succeeded() && result.mayHaveChanged && queries==0 && setCalls==0,"Unavailable protected store reached native Windows settings");
        store.failure=CredentialStatus::Success;
        check(owner.apply(config).succeeded(),"Temporary protected-store failure could not be retried");
        const auto before=setCalls;store.failure=CredentialStatus::PermissionDenied;
        check(!owner.clear().succeeded() && setCalls==before && store.values.contains(key),"Denied protected checkpoint allowed native restoration");
        store.failure=CredentialStatus::Success;check(owner.clear().succeeded() && !store.values.contains(key),"Protected checkpoint retry did not finish");restored();
    }
    auto foreign=record;foreign["machine"]="foreign";
    for(const auto &invalid:QList<QByteArray>{QByteArray{},"not-json","{}",QJsonDocument(record).toJson(QJsonDocument::Indented),
            QJsonDocument(foreign).toJson(QJsonDocument::Compact),QByteArray(CredentialStore::MaxBytes+1,'x')}) {
        reset();MemoryCredentialStore store;store.values[key]=invalid;int reads=0;store.beforeRead=[&]{++reads;};
        PersistentProxyBackend owner(store,key,WindowsProxyApi{query,set,entries});const auto result=owner.clear();
        check(!result.succeeded() && !result.mayHaveChanged && queries==0 && setCalls==0 && store.values[key]==invalid,
              "Invalid protected Windows data reached a native API or was overwritten");
        const auto observed=reads;store.values.remove(key);
        check(!owner.clear().succeeded() && !owner.apply(config).succeeded() && reads==observed && queries==0 && setCalls==0,
              "External deletion reinterpreted rejected Windows ownership as successful recovery");
    }
    reset();
    {
        MemoryCredentialStore store;PersistentProxyBackend owner(store,key,WindowsProxyApi{query,set,entries});
        check(owner.apply(config).succeeded(),"Apply before protected Windows record replacement");
        const auto installed=states[""];store.values[key]="external record";const auto before=setCalls;
        check(!owner.clear().succeeded() && setCalls==before && store.values[key]=="external record" && states[""].proxy==installed.proxy,
              "External protected Windows record was replaced or allowed native rollback");
    }
    reset();
    {
        MemoryCredentialStore store;PersistentProxyBackend owner(store,key,WindowsProxyApi{query,set,entries});
        denySet=true;const auto result=owner.apply(config);denySet=false;
        check(!result.succeeded() && !result.mayHaveChanged && !store.values.contains(key),"Cancelled Windows write retained a false protected responsibility");restored();
    }
    scopedProxyTests(WindowsProxyApi{query,set,entries},reset,restored,[]{return setCalls;});
    std::cout<<"PASS: shared protected Windows recovery, lazy reads, native write ordering, store failures and scope rejection\n";
}
