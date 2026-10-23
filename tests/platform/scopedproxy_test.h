#pragma once
#include "infrastructure/platform/persistentproxy.h"
#include "tests/credentialstorefixture.h"
#include <QJsonDocument>
#include <QUuid>

template<class Api,class Reset,class Verify,class Mutations>
static void scopedProxyTests(Api api,Reset reset,Verify restored,Mutations mutations) {
    const QString key(64,'a'),other(64,'b');
    const auto first=QUuid::createUuid().toString(QUuid::WithoutBraces);
    const auto second=QUuid::createUuid().toString(QUuid::WithoutBraces);
    const auto foreign=QUuid::createUuid().toString(QUuid::WithoutBraces);
    reset();MemoryCredentialStore store;store.values[other]="unrelated";
    {
        PersistentProxyBackend owner(store,key,api);
        check(owner.configureRecovery(first,false).succeeded() && owner.apply(config).succeeded(),"Apply scoped native owner");
        const auto record=QJsonDocument::fromJson(store.values[key]).object();
        check(record["scope"]==first && record["native"].isObject(),"Pending snapshot lost its caller scope");
    }
    {
        PersistentProxyBackend replacement(store,key,api);
        check(replacement.configureRecovery(first,true).succeeded() && replacement.clear().succeeded(),"Resume matching scoped native record");restored();
        check(!replacement.apply(config).succeeded(),"Completed scope was reused for a new native application");
    }
    check(!store.values.contains(key) && store.values[other]=="unrelated" && store.values.size()==2,
          "Scoped completion retained a sensitive snapshot or changed another credential");
    QString proofKey;for(auto i=store.values.cbegin();i!=store.values.cend();++i)if(i.key()!=other)proofKey=i.key();
    const auto proof=store.values[proofKey];
    check(QJsonDocument::fromJson(proof).object().size()==3,"Completion proof retained native snapshot fields");
    PersistentProxyBackend next(store,key,api);
    check(next.configureRecovery(second,false).succeeded() && next.apply(config).succeeded(),"Apply a distinct scoped native owner");
    const auto pending=store.values[key];const auto before=mutations();
    {
        PersistentProxyBackend wrong(store,key,api);
        check(wrong.configureRecovery(foreign,true).succeeded() && !wrong.clear().succeeded() && !wrong.clear().succeeded()
              && mutations()==before && store.values[key]==pending,"Foreign scope or EOF adopted another native owner");
    }
    {
        PersistentProxyBackend completed(store,key,api);
        check(completed.configureRecovery(first,true).succeeded() && completed.clear().succeeded() && completed.clear().succeeded()
              && store.values[key]==pending && mutations()==before,"Old completion proof consumed a later owner's snapshot");
    }
    store.values.remove(key);
    {
        PersistentProxyBackend missing(store,key,api);
        check(missing.configureRecovery(second,true).succeeded() && !missing.clear().succeeded() && mutations()==before,
              "Missing snapshot or old completion proof became confirmed cleanup");
        store.values[key]=pending;
        check(!missing.clear().succeeded() && mutations()==before,"Rejected missing data was rebound in the same instance");
    }
    {
        PersistentProxyBackend repair(store,key,api);
        check(repair.configureRecovery(second,true).succeeded() && repair.clear().succeeded(),"Recover restored matching protected data");restored();
    }
    store.values[key]=pending;const auto released=mutations();
    {
        PersistentProxyBackend releasedOwner(store,key,api);
        check(releasedOwner.configureRecovery(second,true).succeeded() && releasedOwner.clear().succeeded()
              && store.values[key]==pending && mutations()==released,"Completed scope removed a recreated same-value snapshot");
    }
    store.values.remove(key);
    reset();MemoryCredentialStore startup;
    {
        PersistentProxyBackend abandoned(startup,key,api);
        check(abandoned.configureRecovery(first,false).succeeded() && abandoned.apply(config).succeeded(),"Apply old scope before fresh startup");
    }
    {
        PersistentProxyBackend fresh(startup,key,api);
        check(fresh.configureRecovery(second,false).succeeded() && fresh.apply(config).succeeded(),"Fresh startup did not restore the previous owner before applying");
        check(startup.values.size()==1 && startup.values.contains(key),"Startup recovery prematurely confirmed the new operation");
        check(fresh.clear().succeeded() && !startup.values.contains(key),"Fresh startup skipped clearing its new native application");restored();
    }
    const auto completed=store.values[proofKey];auto bad=QJsonDocument::fromJson(completed).object();bad["machine"]="foreign";
    for(const auto &invalid:QList<QByteArray>{"invalid",QJsonDocument(bad).toJson(QJsonDocument::Compact),
                                           QJsonDocument::fromJson(completed).toJson(QJsonDocument::Indented)}) {
        store.values[proofKey]=invalid;PersistentProxyBackend rejected(store,key,api);
        check(rejected.configureRecovery(second,true).succeeded() && !rejected.clear().succeeded() && store.values[proofKey]==invalid
              && mutations()==released,"Invalid completion proof reached native settings or was overwritten");
    }
    reset();MemoryCredentialStore denied;
    PersistentProxyBackend owner(denied,key,api);
    check(owner.configureRecovery(first,false).succeeded() && owner.apply(config).succeeded(),"Apply before completion storage denial");
    denied.beforeWrite=[&](const QString &,const QByteArray &bytes) {
        if(QJsonDocument::fromJson(bytes).object().contains("version"))denied.failure=CredentialStatus::PermissionDenied;
    };
    check(!owner.clear().succeeded() && !denied.values.contains(key),"Completion denial was acknowledged or retained a removed snapshot");restored();
    denied.beforeWrite={};denied.failure=CredentialStatus::Success;const auto restoredWrites=mutations();
    {
        PersistentProxyBackend unconfirmed(denied,key,api);
        check(unconfirmed.configureRecovery(first,true).succeeded() && !unconfirmed.clear().succeeded()
              && mutations()==restoredWrites,"Missing completion proof after snapshot deletion was treated as success");
    }
    check(owner.clear().succeeded() && mutations()==restoredWrites,"Completion retry rewrote released native settings");restored();
    std::cout<<"PASS: scoped native recovery, protected completion, missing/foreign/recreated records and confirmation retry\n";
}
