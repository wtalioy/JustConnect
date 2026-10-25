#pragma once
#include "infrastructure/systemproxy/platformsystemproxybackend.h"
#include "infrastructure/systemproxy/persistentproxy.h"
#include "infrastructure/credentialstore/macos/credentialstore.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QScopeGuard>
#include <iostream>
#include <cstdlib>

static void number(CFMutableDictionaryRef values, CFStringRef key, int value) {
    auto native=CFNumberCreate(nullptr,kCFNumberIntType,&value);CFDictionarySetValue(values,key,native);CFRelease(native);
}
static CFStringRef path(SCNetworkServiceRef service) {
    return CFStringCreateWithFormat(nullptr,nullptr,CFSTR("/%@/%@/%@"),kSCPrefNetworkServices,SCNetworkServiceGetServiceID(service),kSCEntNetProxies);
}
static int changes=0,failAt=0,commits=0,changesAtCommit=0;
static bool ignoreSet=false,failCommit=false,failApply=false;
static std::function<void()> beforeSet;
static Boolean set(SCPreferencesRef prefs, CFStringRef key, CFDictionaryRef value) {
    if (beforeSet) beforeSet();
    if(++changes==failAt)return false;
    return ignoreSet || SCPreferencesPathSetValue(prefs,key,value);
}
static Boolean nativeCommit(SCPreferencesRef prefs) {
    const auto result=SCPreferencesCommitChanges(prefs);
    if(!result)std::cerr<<"Native preferences commit error "<<SCError()<<": "<<SCErrorString(SCError())<<'\n';
    return result;
}
static Boolean commit(SCPreferencesRef prefs) { ++commits;changesAtCommit=changes;return !failCommit && nativeCommit(prefs); }
static Boolean apply(SCPreferencesRef prefs) { return !failApply && SCPreferencesApplyChanges(prefs); }

static void backendTests() {
    QTemporaryDir directory;check(directory.isValid(),"private SystemConfiguration directory");
    const auto filename=directory.filePath("preferences.plist");
    auto file=CFStringCreateWithCharacters(nullptr,reinterpret_cast<const UniChar *>(filename.utf16()),filename.size());
    const auto releaseFile=qScopeGuard([&]{CFRelease(file);});
    MacProxyApi api;int opens=0;SCPreferencesRef opened=nullptr;
    api.open=[&](AuthorizationRef *authorization){++opens;*authorization=nullptr;opened=SCPreferencesCreate(nullptr,CFSTR("JustConnect tests"),file);return opened;};
    api.set=set;api.commit=commit;api.apply=apply;
    AuthorizationRef unused=nullptr;auto prefs=api.open(&unused);check(prefs,"open private native preferences");
    const auto releasePrefs=qScopeGuard([&]{CFRelease(prefs);});
    auto interfaces=SCNetworkInterfaceCopyAll();check(interfaces,"read native interface metadata");
    const auto releaseInterfaces=qScopeGuard([&]{CFRelease(interfaces);});
    SCNetworkInterfaceRef interface=nullptr;
    for(CFIndex i=0;i<CFArrayGetCount(interfaces);++i) {
        auto candidate=static_cast<SCNetworkInterfaceRef>(CFArrayGetValueAtIndex(interfaces,i));
        if(CFEqual(SCNetworkInterfaceGetInterfaceType(candidate),kSCNetworkInterfaceTypeEthernet)){interface=candidate;break;}
    }
    check(interface,"native Ethernet metadata for private service fixtures");
    auto first=SCNetworkServiceCreate(prefs,interface),second=SCNetworkServiceCreate(prefs,interface),disabled=SCNetworkServiceCreate(prefs,interface);
    check(first && second && disabled,"create services only in private preferences");
    const auto releaseServices=qScopeGuard([&]{CFRelease(first);CFRelease(second);CFRelease(disabled);});
    check(SCNetworkServiceSetEnabled(first,true) && SCNetworkServiceSetEnabled(second,true) && SCNetworkServiceSetEnabled(disabled,false),"native enabled and disabled services");
    check(nativeCommit(prefs),"persist private service metadata before fixture synchronization");
    auto firstPath=path(first),secondPath=path(second),disabledPath=path(disabled);
    const auto releasePaths=qScopeGuard([&]{CFRelease(firstPath);CFRelease(secondPath);CFRelease(disabledPath);});
    auto original=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    const auto releaseOriginal=qScopeGuard([&]{CFRelease(original);});
    number(original,kSCPropNetProxiesHTTPEnable,1);number(original,kSCPropNetProxiesHTTPPort,3128);
    CFDictionarySetValue(original,kSCPropNetProxiesHTTPProxy,CFSTR("prior.invalid"));
    number(original,CFSTR("HTTPProxyAuthenticated"),1);CFDictionarySetValue(original,CFSTR("HTTPProxyUsername"),CFSTR("fixture-user"));
    CFDictionarySetValue(original,CFSTR("HTTPProxyPassword"),CFSTR("fixture-secret"));
    CFDictionarySetValue(original,CFSTR("FixtureBoolean"),kCFBooleanTrue);
    const UInt8 opaque[]{0,1,0xfe,0xff};auto binary=CFDataCreate(nullptr,opaque,sizeof(opaque));
    check(binary,"create opaque native fixture value");CFDictionarySetValue(original,CFSTR("FixtureBinary"),binary);CFRelease(binary);
    number(original,kSCPropNetProxiesProxyAutoConfigEnable,1);number(original,kSCPropNetProxiesProxyAutoDiscoveryEnable,1);
    CFDictionarySetValue(original,kSCPropNetProxiesProxyAutoConfigURLString,CFSTR("https://pac.invalid/original.pac"));
    const void *domain[]{CFSTR("old.invalid")};auto domains=CFArrayCreate(nullptr,domain,1,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(original,kSCPropNetProxiesExceptionsList,domains);CFRelease(domains);
    CFDictionarySetValue(original,CFSTR("FixtureMarker"),CFSTR("retained"));
    const auto seed=[&] {
        SCPreferencesSynchronize(prefs);
        check(SCPreferencesPathSetValue(prefs,firstPath,original) && SCPreferencesPathSetValue(prefs,disabledPath,original),"seed native proxy/PAC/bypass");
        if(SCPreferencesPathGetValue(prefs,secondPath))check(SCPreferencesPathRemoveValue(prefs,secondPath),"seed absent original proxy configuration");
        check(nativeCommit(prefs),"commit private native fixture");
    };
    const auto value=[&](CFStringRef key){SCPreferencesSynchronize(prefs);return SCPreferencesPathGetValue(prefs,key);};
    const auto restored=[&] {
        check(value(firstPath) && CFEqual(value(firstPath),original),"exact original proxy/PAC/bypass/authentication dictionary restored");
        check(!value(secondPath),"absent original proxy configuration restored without fabricated fields");
        check(value(disabledPath) && CFEqual(value(disabledPath),original),"disabled service remains untouched");
    };
    seed();PlatformSystemProxyBackend backend(api);
    auto firstParent=CFStringCreateWithFormat(nullptr,nullptr,CFSTR("/%@/%@"),kSCPrefNetworkServices,SCNetworkServiceGetServiceID(first));
    const auto releaseFirstParent=qScopeGuard([&]{CFRelease(firstParent);});
    auto malformed=CFDictionaryCreateMutableCopy(nullptr,0,SCPreferencesPathGetValue(prefs,firstParent));
    CFDictionarySetValue(malformed,kSCEntNetProxies,CFSTR("invalid"));
    check(SCPreferencesPathSetValue(prefs,firstParent,malformed) && nativeCommit(prefs),"seed malformed native proxy data");CFRelease(malformed);
    const auto beforeRead=changes;
    check(!backend.apply(config).succeeded() && changes==beforeRead,"invalid native data fails before the first mutation");
    auto repaired=CFDictionaryCreateMutableCopy(nullptr,0,SCPreferencesPathGetValue(prefs,firstParent));
    CFDictionarySetValue(repaired,kSCEntNetProxies,original);
    check(SCPreferencesPathSetValue(prefs,firstParent,repaired) && nativeCommit(prefs),"repair malformed fixture through its dictionary parent");CFRelease(repaired);
    seed();
    check(backend.clear().succeeded(),"unknown native settings are not cleared");restored();
    check(backend.apply(config).succeeded(),"native private preferences apply/readback");
    check(!backend.apply(config).succeeded(),"repeated application cannot replace the original snapshot");
    check(!backend.check(config).conflict && backend.check(config).active,"native endpoints and authentication flags verified");
    auto active=static_cast<CFDictionaryRef>(value(firstPath));
    check(!CFDictionaryContainsKey(active,CFSTR("HTTPProxyUsername")),"old authentication identity is absent from the local endpoint");
    check(backend.clear().succeeded(),"native private preferences restoration");restored();
    check(backend.clear().succeeded(),"repeated clear is a no-op");
    QJsonObject record;
    {
        PlatformSystemProxyBackend owner(api);check(owner.apply(config).succeeded(),"Apply private native snapshot owner");
        record=QJsonDocument::fromJson(QJsonDocument(owner.recoverySnapshot()).toJson()).object();
    }
    const auto reject=[&](const QJsonObject &invalid) {
        const auto beforeChanges=changes,beforeOpens=opens;PlatformSystemProxyBackend fresh(api);
        check(!fresh.recover(invalid).succeeded() && changes==beforeChanges && opens==beforeOpens,
              "Invalid macOS recovery record opened or changed native preferences");
    };
    reject({});
    for (const auto *field:{"schema_version","platform","machine","uid","owner","config","services","restoration_committed"}) {
        auto invalid=record;invalid.remove(field);reject(invalid);
    }
    for (const auto *field:{"platform","machine","uid","owner"}) {auto invalid=record;invalid[field]="foreign";reject(invalid);}
    auto invalid=record;invalid["machine"]=QString(65536,'x');reject(invalid);
    invalid=record;invalid["extra"]=true;reject(invalid);
    invalid=record;invalid["restoration_committed"]="true";reject(invalid);
    invalid=record;invalid["schema_version"]=1;reject(invalid);
    for (const auto *field : {"released","intent","written","uncertain","pending_restore"}) {
        auto entries=record["services"].toArray();auto entry=entries[0].toObject();entry.remove(field);entries[0]=entry;
        invalid=record;invalid["services"]=entries;reject(invalid);
        for (auto value : {QJsonValue(-1),QJsonValue(64),QJsonValue(1.5),QJsonValue(true),QJsonValue("1")}) {
            entry=record["services"].toArray()[0].toObject();entry[field]=value;entries[0]=entry;
            invalid=record;invalid["services"]=entries;reject(invalid);
        }
    }
    for (const auto *field : {"uncertain","pending_restore"}) {
        auto entries=record["services"].toArray();auto entry=entries[0].toObject();entry["released"]=63;entry[field]=1;entries[0]=entry;
        invalid=record;invalid["services"]=entries;reject(invalid);
    }
    auto services=record["services"].toArray();services.append(services[0]);invalid=record;invalid["services"]=services;reject(invalid);
    for (const auto *id:{"../foreign",".","..",""}) {
        services=record["services"].toArray();auto service=services[0].toObject();service["id"]=id;services[0]=service;
        invalid=record;invalid["services"]=services;reject(invalid);
    }
    services=record["services"].toArray();auto service=services[0].toObject();service["before"]="not-base64";services[0]=service;
    invalid=record;invalid["services"]=services;reject(invalid);
    auto array=CFArrayCreate(nullptr,nullptr,0,&kCFTypeArrayCallBacks);
    auto arrayData=CFPropertyListCreateData(nullptr,array,kCFPropertyListBinaryFormat_v1_0,0,nullptr);CFRelease(array);
    check(arrayData,"Create a valid non-dictionary native recovery payload");
    service["before"]=QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(arrayData)),CFDataGetLength(arrayData)).toBase64());CFRelease(arrayData);
    services[0]=service;invalid=record;invalid["services"]=services;reject(invalid);
    PlatformSystemProxyBackend recovered(api);
    check(recovered.recover(record).succeeded() && recovered.recoverySnapshot().isEmpty(),"Fresh native snapshot restoration");restored();
    check(recovered.apply(config).succeeded(),"Apply before active ownership import rejection");
    const auto beforeImport=changes,beforeImportOpens=opens;
    check(!recovered.recover(record).succeeded() && changes==beforeImport && opens==beforeImportOpens,"Import replaced active macOS ownership");
    check(recovered.clear().succeeded(),"Release imported fixture test owner");restored();
    changes=0;failAt=2;
    auto partial=backend.apply(config);check(!partial.succeeded() && !partial.mayHaveChanged,"uncommitted partial native edits are discarded");
    failAt=0;restored();
    ignoreSet=true;check(!backend.apply(config).succeeded(),"successful setter without mutation fails readback");ignoreSet=false;restored();
    const auto beforeCommits=commits;
    failCommit=true;const auto rejectedCommit=backend.apply(config);failCommit=false;
    check(!rejectedCommit.succeeded() && !rejectedCommit.mayHaveChanged && backend.recoverySnapshot().isEmpty()
          && commits==beforeCommits+1 && changes==changesAtCommit,
          "Rejected commit repeated unchanged restoration writes or retained recovered responsibility");
    check(backend.clear().succeeded(),"commit failure recovery can be retried");restored();
    const auto beforeOriginalChanges=changes,beforeOriginalCommits=commits;
    failAt=changes+1;failCommit=true;PlatformSystemProxyBackend alreadyOriginal(api);
    const auto recoveredOriginal=alreadyOriginal.recover(record);failAt=0;failCommit=false;
    check(recoveredOriginal.succeeded() && alreadyOriginal.recoverySnapshot().isEmpty()
          && changes==beforeOriginalChanges && commits==beforeOriginalCommits,
          "Fresh restoration of original native values attempted a setter or commit");restored();
    std::cout<<"PASS: native macOS original-value recovery needs no setter or commit after denied publication\n";
    failApply=true;check(!backend.apply(config).succeeded(),"notification failure propagated");failApply=false;
    check(backend.clear().succeeded(),"notification failure recovery can be retried");restored();
    check(backend.apply(config).succeeded(),"apply before restore failure");changes=0;failAt=1;
    check(!backend.clear().succeeded(),"native restore failure retains its original snapshot");failAt=0;
    check(backend.clear().succeeded(),"native restore resumes after failure");restored();
    check(backend.apply(config).succeeded(),"apply private notification retry fixture");
    auto recreated=static_cast<CFDictionaryRef>(CFPropertyListCreateDeepCopy(nullptr,value(firstPath),kCFPropertyListImmutable));
    check(recreated && CFGetTypeID(recreated)==CFDictionaryGetTypeID(),"save installed native fixture dictionary");
    const auto releaseRecreated=qScopeGuard([&]{CFRelease(recreated);});
    failApply=true;check(!backend.clear().succeeded(),"retain notification after committed restoration");failApply=false;
    SCPreferencesSynchronize(prefs);
    check(SCPreferencesPathSetValue(prefs,firstPath,recreated) && nativeCommit(prefs),"externally recreate a formerly installed native value");
    changes=0;check(backend.clear().succeeded() && changes==0 && CFEqual(value(firstPath),recreated),
                    "Notification retry rewrote a confirmed native restoration");
    check(SCPreferencesPathSetValue(prefs,firstPath,original) && nativeCommit(prefs),"clean only the explicitly recreated fixture");restored();
    {
        PlatformSystemProxyBackend owner(api);check(owner.apply(config).succeeded(),"Apply before committed-restoration handoff");
        failApply=true;check(!owner.clear().succeeded(),"Keep native committed restoration responsibility");record=owner.recoverySnapshot();failApply=false;
    }
    SCPreferencesSynchronize(prefs);
    check(SCPreferencesPathSetValue(prefs,firstPath,recreated) && nativeCommit(prefs),"Recreate an external value after committed restoration handoff");
    changes=0;PlatformSystemProxyBackend notifyOnly(api);
    check(notifyOnly.recover(record).succeeded() && changes==0 && CFEqual(value(firstPath),recreated),
          "Fresh macOS recovery rewrote already committed restoration");
    SCPreferencesSynchronize(prefs);check(SCPreferencesPathSetValue(prefs,firstPath,original) && nativeCommit(prefs),"Clean the owned handoff fixture");restored();
    std::cout<<"PASS: native macOS snapshot handoff, typed sensitive values, strict scope rejection and committed restoration\n";
    const auto hasMask=[](const QJsonObject &record,const char *field) {
        for (const auto &value : record["services"].toArray()) if (value.toObject()[field].toInteger()!=0) return true;
        return false;
    };
    const auto denied=[] {return PlatformOperationResult{Status::PermissionDenied,"injected checkpoint denial"};};
    {
        const auto beforeChanges=changes,beforeCommits=commits;
        PlatformSystemProxyBackend rejected(api,[&](const QJsonObject &){return denied();});
        const auto result=rejected.apply(config);
        check(!result.succeeded() && !result.mayHaveChanged && rejected.recoverySnapshot().isEmpty()
              && changes==beforeChanges && commits==beforeCommits,"Initial Mac checkpoint rejection mutated preferences or retained ownership");
    }
    {
        QJsonObject stored;int publications=0;
        PlatformSystemProxyBackend owner(api,[&](const QJsonObject &record) {
            if (++publications==2) return denied();
            stored=record;return PlatformOperationResult{};
        });
        const auto beforeChanges=changes,beforeCommits=commits;
        const auto result=owner.apply(config);
        check(!result.succeeded() && result.mayHaveChanged && changes==beforeChanges && commits==beforeCommits
              && !stored.isEmpty() && !hasMask(stored,"intent"),"Denied application intent reached native setters or lost its initial record");
        check(owner.clear().succeeded() && stored.isEmpty(),"Remove an unpublished Mac application intent");restored();
    }
    {
        QJsonObject stored;bool denyRestore=false;
        PlatformSystemProxyBackend owner(api,[&](const QJsonObject &record) {
            if (denyRestore && hasMask(record,"pending_restore")) return denied();
            stored=record;return PlatformOperationResult{};
        });
        beforeSet=[&] {check(!stored.isEmpty() && hasMask(stored,"intent"),"Native Mac setter preceded protected write intent");};
        check(owner.apply(config).succeeded() && hasMask(stored,"written"),"Native Mac write confirmation was not checkpointed");
        beforeSet={};denyRestore=true;const auto beforeChanges=changes,beforeCommits=commits;
        const auto result=owner.clear();
        check(!result.succeeded() && result.mayHaveChanged && changes==beforeChanges && commits==beforeCommits,
              "Denied Mac restore checkpoint reached native writes");
        denyRestore=false;check(owner.clear().succeeded() && stored.isEmpty(),"Mac checkpoint restore retry or confirmed removal failed");restored();
    }
    {
        QJsonObject stored;bool replace=true;
        auto external=CFDictionaryCreateMutableCopy(nullptr,0,original);
        const auto releaseExternal=qScopeGuard([&]{CFRelease(external);});
        CFDictionarySetValue(external,kSCPropNetProxiesHTTPProxy,CFSTR("127.0.0.1"));number(external,kSCPropNetProxiesHTTPPort,config.httpPort);
        PlatformSystemProxyBackend owner(api,[&](const QJsonObject &record) {
            stored=record;
            if (replace && hasMask(record,"intent")) {
                replace=false;
                check(SCPreferencesPathSetValue(opened,firstPath,external) && nativeCommit(opened),"Change private native state during intent publication");
            }
            return PlatformOperationResult{};
        });
        const auto beforeChanges=changes;
        check(!owner.apply(config).succeeded() && owner.clear().succeeded() && changes==beforeChanges && stored.isEmpty()
              && CFEqual(value(firstPath),external),"Uncommitted Mac application claimed an external installed-looking value");seed();restored();
    }
    {
        QJsonObject stored;int restorePublications=0;
        PlatformSystemProxyBackend owner(api,[&](const QJsonObject &record) {
            stored=record;
            if (hasMask(record,"pending_restore") && ++restorePublications==2) {
                auto external=CFDictionaryCreateMutableCopy(nullptr,0,SCPreferencesPathGetValue(opened,firstPath));
                CFDictionarySetValue(external,CFSTR("FixtureMarker"),CFSTR("changed-during-storage"));
                check(SCPreferencesPathSetValue(opened,firstPath,external) && nativeCommit(opened),"Change native Mac state during restoration storage");CFRelease(external);
            }
            return PlatformOperationResult{};
        });
        check(owner.apply(config).succeeded(),"Apply native Mac storage-wait fixture");const auto beforeChanges=changes;
        check(!owner.clear().succeeded() && changes==beforeChanges && !stored.isEmpty(),"Mac restoration overwrote a dictionary changed during storage");
        check(owner.clear().succeeded() && stored.isEmpty(),"Retry native Mac restoration after storage-wait conflict");
        auto expected=CFDictionaryCreateMutableCopy(nullptr,0,original);
        CFDictionarySetValue(expected,CFSTR("FixtureMarker"),CFSTR("changed-during-storage"));
        check(CFEqual(value(firstPath),expected),"Mac restoration lost an external unmanaged field");CFRelease(expected);seed();restored();
    }
    for (int boundary : {0,1,2}) {
        QJsonObject stored;bool interrupted=false;
        CFDictionaryRef firstInstalled=nullptr,secondInstalled=nullptr;
        const auto releaseInstalled=qScopeGuard([&]{if(firstInstalled)CFRelease(firstInstalled);if(secondInstalled)CFRelease(secondInstalled);});
        {
            PlatformSystemProxyBackend owner(api,[&](const QJsonObject &record) {
                if ((boundary==0 && (hasMask(record,"written") || hasMask(record,"pending_restore")))
                    || (interrupted && !record.isEmpty() && !hasMask(record,"pending_restore") && hasMask(record,"released"))) return denied();
                stored=record;return PlatformOperationResult{};
            });
            const auto applied=owner.apply(config);
            check(boundary==0 ? !applied.succeeded() && applied.mayHaveChanged : applied.succeeded(),"Prepare native Mac interrupted publication");
            firstInstalled=static_cast<CFDictionaryRef>(CFRetain(value(firstPath)));
            secondInstalled=static_cast<CFDictionaryRef>(CFRetain(value(secondPath)));
            if (boundary!=0) {
                if (boundary==1) seed();
                interrupted=true;const auto result=owner.clear();
                check(!result.succeeded() && result.mayHaveChanged,"Lose native Mac restore or observation confirmation");
            }
        }
        check(!stored.isEmpty() && (boundary==0 ? !hasMask(stored,"written") : hasMask(stored,"pending_restore")),
              "Interrupted Mac fixture lost its last durable uncertain record");
        if (boundary!=0) {
            SCPreferencesSynchronize(prefs);
            check(SCPreferencesPathSetValue(prefs,firstPath,firstInstalled) && SCPreferencesPathSetValue(prefs,secondPath,secondInstalled)
                  && nativeCommit(prefs),"Externally recreate unconfirmed native Mac values");
        }
        const auto beforeChanges=changes,beforeCommits=commits;
        PlatformSystemProxyBackend fresh(api,[&](const QJsonObject &record){stored=record;return PlatformOperationResult{};});
        const auto result=fresh.recover(stored);
        check(!result.succeeded() && result.mayHaveChanged && hasMask(stored,"uncertain")
              && changes==beforeChanges && commits==beforeCommits && CFEqual(value(firstPath),firstInstalled) && CFEqual(value(secondPath),secondInstalled),
              "Fresh Mac recovery overwrote an unconfirmed matching application or restoration");
        seed();check(fresh.clear().succeeded() && stored.isEmpty(),"Mac uncertainty did not resolve after external original restoration");restored();
    }
    {
        QJsonObject stored;bool denyRemoval=true;
        PlatformSystemProxyBackend owner(api,[&](const QJsonObject &record) {
            if (record.isEmpty() && denyRemoval) return denied();
            stored=record;return PlatformOperationResult{};
        });
        check(owner.apply(config).succeeded(),"Apply native Mac removal retry owner");
        auto installed=static_cast<CFDictionaryRef>(CFRetain(value(firstPath)));
        const auto releaseInstalled=qScopeGuard([&]{CFRelease(installed);});
        check(!owner.clear().succeeded() && stored["restoration_committed"]==true,"Mac record removal failure lost committed restoration");restored();
        SCPreferencesSynchronize(prefs);
        check(SCPreferencesPathSetValue(prefs,firstPath,installed) && nativeCommit(prefs),"Externally recreate Mac settings after denied record removal");
        denyRemoval=false;const auto beforeChanges=changes,beforeCommits=commits;
        check(owner.clear().succeeded() && stored.isEmpty() && changes==beforeChanges && commits==beforeCommits
              && CFEqual(value(firstPath),installed),"Mac record removal retry rewrote a released native dictionary");seed();restored();
    }
    std::cout<<"PASS: native macOS write-ahead checkpoints, interrupted apply/observation/restore, uncertainty and record removal retry\n";
    {
        const auto keychainPath=directory.filePath("recovery.keychain-db").toUtf8();
        const QByteArray password="private proxy recovery fixture";
        SecKeychainRef keychain=nullptr;
        check(SecKeychainCreate(keychainPath.constData(),UInt32(password.size()),password.constData(),false,nullptr,&keychain)==errSecSuccess,
              "Create private recovery keychain");
        const auto removeKeychain=qScopeGuard([&]{SecKeychainDelete(keychain);CFRelease(keychain);});
        const auto unlock=[&] {check(SecKeychainUnlock(keychain,UInt32(password.size()),password.constData(),true)==errSecSuccess,
                                    "Unlock private recovery keychain");};
        unlock();auto credentials=createMacCredentialStore(keychain);
        const auto key=PersistentProxyBackend::credentialKey();const QString other(64,'d');
        check(credentials->write(other,"unrelated credential").succeeded(),"Seed separate private credential");
        bool restoring=false;
        beforeSet=[&] {
            const auto stored=credentials->read(key);const auto document=QJsonDocument::fromJson(stored.value);
            check(stored.succeeded() && document.isObject() && document.toJson(QJsonDocument::Compact)==stored.value
                  && hasMask(document.object(),restoring?"pending_restore":"intent"),
                  "Mac native mutation preceded canonical protected intent");
        };
        const auto resetHook=qScopeGuard([]{beforeSet={};});
        QByteArray saved;
        {
            const auto beforeOpens=opens;
            PersistentProxyBackend owner(*credentials,key,api);
            check(opens==beforeOpens,"Protected Mac construction opened native preferences before ownership");
            check(owner.apply(config).succeeded(),"Apply with real private Keychain checkpoints");
            const auto record=credentials->read(key);saved=record.value;
            check(record.succeeded() && hasMask(QJsonDocument::fromJson(saved).object(),"written"),
                  "Real Keychain lost confirmed Mac application");
        }
        credentials.reset();
        SecKeychainRef reopened=nullptr;
        check(SecKeychainOpen(keychainPath.constData(),&reopened)==errSecSuccess,"Reopen private recovery keychain");
        credentials=createMacCredentialStore(reopened);CFRelease(reopened);
        check(credentials->read(key).value==saved,"Fresh native credential provider lost recovery bytes");
        check(SecKeychainLock(keychain)==errSecSuccess,"Lock private recovery keychain");
        PersistentProxyBackend fresh(*credentials,key,api);
        const auto beforeOpens=opens,beforeChanges=changes;
        const auto denied=fresh.clear();
        check(denied.status==Status::PermissionDenied && denied.mayHaveChanged && opens==beforeOpens && changes==beforeChanges,
              "Locked Mac recovery storage reached native preferences or discarded responsibility");
        unlock();restoring=true;
        const auto recovered=fresh.check(config);
        check(recovered.result.succeeded() && recovered.conflict && recovered.active
              && credentials->read(key).status==CredentialStatus::NotFound
              && credentials->read(other).value=="unrelated credential",
              "Fresh protected Mac query failed to restore/remove only its recovery record");restored();
        beforeSet={};
        auto foreign=QJsonDocument::fromJson(saved).object();foreign["machine"]="foreign";
        const auto invalid=QJsonDocument(foreign).toJson(QJsonDocument::Compact);
        check(credentials->write(key,invalid).succeeded(),"Seed foreign private recovery record");
        PersistentProxyBackend rejected(*credentials,key,api);
        const auto beforeRejectOpens=opens,beforeRejectChanges=changes;
        const auto result=rejected.apply(config);
        check(!result.succeeded() && !result.mayHaveChanged && opens==beforeRejectOpens && changes==beforeRejectChanges
              && credentials->read(key).value==invalid,"Foreign protected Mac record reached native preferences or was replaced");
        check(credentials->remove(key).succeeded(),"Remove only the owned invalid fixture record");
        check(!rejected.clear().succeeded() && opens==beforeRejectOpens && changes==beforeRejectChanges,
              "External record deletion reinterpreted rejected Mac ownership as successful recovery");restored();
        std::cout<<"PASS: native macOS private Keychain recovery, write ordering, fresh provider, locked retry and foreign scope refusal\n";
    }
    scopedProxyTests(api,seed,restored,[]{return changes;});
    check(SCNetworkServiceSetEnabled(first,false) && SCNetworkServiceSetEnabled(second,false) && nativeCommit(prefs),"disable private fixture services");
    check(backend.apply(config).status==PlatformOperationResult::Status::Unsupported,"no enabled services is explicitly unsupported");
    check(SCNetworkServiceSetEnabled(first,true) && SCNetworkServiceSetEnabled(second,true) && nativeCommit(prefs),"reenable private fixture services");
    check(backend.apply(config).succeeded(),"apply before external changes");
    const auto externalRecord=QJsonDocument::fromJson(QJsonDocument(backend.recoverySnapshot()).toJson()).object();
    auto external=CFDictionaryCreateMutableCopy(nullptr,0,static_cast<CFDictionaryRef>(value(firstPath)));
    const auto releaseExternal=qScopeGuard([&]{CFRelease(external);});
    CFDictionarySetValue(external,kSCPropNetProxiesHTTPProxy,CFSTR("external.invalid"));
    CFDictionarySetValue(external,kSCPropNetProxiesProxyAutoConfigURLString,CFSTR("https://pac.invalid/new.pac"));
    const void *newDomain[]{CFSTR("external.invalid")};auto newDomains=CFArrayCreate(nullptr,newDomain,1,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(external,kSCPropNetProxiesExceptionsList,newDomains);CFRelease(newDomains);
    check(SCPreferencesPathSetValue(prefs,firstPath,external) && nativeCommit(prefs),"commit private external state");
    auto added=SCNetworkServiceCreate(prefs,interface);check(added,"create new external private service");
    const auto releaseAdded=qScopeGuard([&]{CFRelease(added);});
    auto addedPath=path(added);const auto releaseAddedPath=qScopeGuard([&]{CFRelease(addedPath);});
    check(SCPreferencesPathSetValue(prefs,addedPath,original) && SCNetworkServiceRemove(second) && nativeCommit(prefs),"external service addition and deletion");
    PlatformSystemProxyBackend externalRecovery(api);
    check(externalRecovery.recover(externalRecord).succeeded(),"fresh native restoration respects external changes");
    check(value(addedPath) && CFEqual(value(addedPath),original),"new service is not changed by restoration");
    auto secondParent=CFStringCreateWithFormat(nullptr,nullptr,CFSTR("/%@/%@"),kSCPrefNetworkServices,SCNetworkServiceGetServiceID(second));
    check(!SCPreferencesPathGetValue(prefs,secondParent),"deleted service must not be recreated by restoration");CFRelease(secondParent);
    auto actual=static_cast<CFDictionaryRef>(value(firstPath));
    for(const auto key:{kSCPropNetProxiesHTTPProxy,kSCPropNetProxiesProxyAutoConfigURLString,kSCPropNetProxiesExceptionsList,kSCPropNetProxiesProxyAutoConfigEnable})
        check(CFEqual(CFDictionaryGetValue(actual,key),CFDictionaryGetValue(external,key)),"external proxy/PAC/bypass and dependent mode retained");
    check(!CFDictionaryContainsKey(actual,CFSTR("HTTPProxyUsername")),"old proxy identity is not restored onto an external endpoint");
    std::cout<<"PASS: native SystemConfiguration snapshots, rollback, retries and external ownership in a private preferences file\n";
}
