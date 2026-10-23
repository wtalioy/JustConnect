#pragma once
#include "infrastructure/platform/platformsystemproxybackend.h"
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
static Boolean set(SCPreferencesRef prefs, CFStringRef key, CFDictionaryRef value) {
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
    MacProxyApi api;int opens=0;
    api.open=[&](AuthorizationRef *authorization){++opens;*authorization=nullptr;return SCPreferencesCreate(nullptr,CFSTR("JustConnect tests"),file);};
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
