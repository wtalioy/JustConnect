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
static int changes=0,failAt=0;
static bool ignoreSet=false,failCommit=false,failApply=false;
static Boolean set(SCPreferencesRef prefs, CFStringRef key, CFDictionaryRef value) {
    if(++changes==failAt)return false;
    return ignoreSet || SCPreferencesPathSetValue(prefs,key,value);
}
static Boolean commit(SCPreferencesRef prefs) { return !failCommit && SCPreferencesCommitChanges(prefs); }
static Boolean apply(SCPreferencesRef prefs) { return !failApply && SCPreferencesApplyChanges(prefs); }

static void backendTests() {
    QTemporaryDir directory;check(directory.isValid(),"private SystemConfiguration directory");
    const auto filename=directory.filePath("preferences.plist");
    auto file=CFStringCreateWithCharacters(nullptr,reinterpret_cast<const UniChar *>(filename.utf16()),filename.size());
    const auto releaseFile=qScopeGuard([&]{CFRelease(file);});
    MacProxyApi api;
    api.open=[&](AuthorizationRef *authorization){*authorization=nullptr;return SCPreferencesCreate(nullptr,CFSTR("JustConnect tests"),file);};
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
    auto firstPath=path(first),secondPath=path(second),disabledPath=path(disabled);
    const auto releasePaths=qScopeGuard([&]{CFRelease(firstPath);CFRelease(secondPath);CFRelease(disabledPath);});
    auto original=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    const auto releaseOriginal=qScopeGuard([&]{CFRelease(original);});
    number(original,kSCPropNetProxiesHTTPEnable,1);number(original,kSCPropNetProxiesHTTPPort,3128);
    CFDictionarySetValue(original,kSCPropNetProxiesHTTPProxy,CFSTR("prior.invalid"));
    number(original,CFSTR("HTTPProxyAuthenticated"),1);CFDictionarySetValue(original,CFSTR("HTTPProxyUsername"),CFSTR("fixture-user"));
    number(original,kSCPropNetProxiesProxyAutoConfigEnable,1);number(original,kSCPropNetProxiesProxyAutoDiscoveryEnable,1);
    CFDictionarySetValue(original,kSCPropNetProxiesProxyAutoConfigURLString,CFSTR("https://pac.invalid/original.pac"));
    const void *domain[]{CFSTR("old.invalid")};auto domains=CFArrayCreate(nullptr,domain,1,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(original,kSCPropNetProxiesExceptionsList,domains);CFRelease(domains);
    CFDictionarySetValue(original,CFSTR("FixtureMarker"),CFSTR("retained"));
    const auto seed=[&] {
        SCPreferencesSynchronize(prefs);
        check(SCPreferencesPathSetValue(prefs,firstPath,original) && SCPreferencesPathSetValue(prefs,disabledPath,original),"seed native proxy/PAC/bypass");
        if(SCPreferencesPathGetValue(prefs,secondPath))check(SCPreferencesPathRemoveValue(prefs,secondPath),"seed absent original proxy configuration");
        check(SCPreferencesCommitChanges(prefs),"commit private native fixture");
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
    check(SCPreferencesPathSetValue(prefs,firstParent,malformed) && SCPreferencesCommitChanges(prefs),"seed malformed native proxy data");CFRelease(malformed);
    const auto beforeRead=changes;
    check(!backend.apply(config).succeeded() && changes==beforeRead,"invalid native data fails before the first mutation");
    seed();
    check(backend.clear().succeeded(),"unknown native settings are not cleared");restored();
    check(backend.apply(config).succeeded(),"native private preferences apply/readback");
    check(!backend.apply(config).succeeded(),"repeated application cannot replace the original snapshot");
    check(!backend.check(config).conflict && backend.check(config).active,"native endpoints and authentication flags verified");
    auto active=static_cast<CFDictionaryRef>(value(firstPath));
    check(!CFDictionaryContainsKey(active,CFSTR("HTTPProxyUsername")),"old authentication identity is absent from the local endpoint");
    check(backend.clear().succeeded(),"native private preferences restoration");restored();
    check(backend.clear().succeeded(),"repeated clear is a no-op");
    changes=0;failAt=2;
    auto partial=backend.apply(config);check(!partial.succeeded() && !partial.mayHaveChanged,"uncommitted partial native edits are discarded");
    failAt=0;restored();
    ignoreSet=true;check(!backend.apply(config).succeeded(),"successful setter without mutation fails readback");ignoreSet=false;restored();
    failCommit=true;check(!backend.apply(config).succeeded(),"commit failure propagated");failCommit=false;
    check(backend.clear().succeeded(),"commit failure recovery can be retried");restored();
    failApply=true;check(!backend.apply(config).succeeded(),"notification failure propagated");failApply=false;
    check(backend.clear().succeeded(),"notification failure recovery can be retried");restored();
    check(backend.apply(config).succeeded(),"apply before restore failure");changes=0;failAt=1;
    check(!backend.clear().succeeded(),"native restore failure retains its original snapshot");failAt=0;
    check(backend.clear().succeeded(),"native restore resumes after failure");restored();
    check(SCNetworkServiceSetEnabled(first,false) && SCNetworkServiceSetEnabled(second,false) && SCPreferencesCommitChanges(prefs),"disable private fixture services");
    check(backend.apply(config).status==PlatformOperationResult::Status::Unsupported,"no enabled services is explicitly unsupported");
    check(SCNetworkServiceSetEnabled(first,true) && SCNetworkServiceSetEnabled(second,true) && SCPreferencesCommitChanges(prefs),"reenable private fixture services");
    check(backend.apply(config).succeeded(),"apply before external changes");
    auto external=CFDictionaryCreateMutableCopy(nullptr,0,static_cast<CFDictionaryRef>(value(firstPath)));
    const auto releaseExternal=qScopeGuard([&]{CFRelease(external);});
    CFDictionarySetValue(external,kSCPropNetProxiesHTTPProxy,CFSTR("external.invalid"));
    CFDictionarySetValue(external,kSCPropNetProxiesProxyAutoConfigURLString,CFSTR("https://pac.invalid/new.pac"));
    const void *newDomain[]{CFSTR("external.invalid")};auto newDomains=CFArrayCreate(nullptr,newDomain,1,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(external,kSCPropNetProxiesExceptionsList,newDomains);CFRelease(newDomains);
    check(SCPreferencesPathSetValue(prefs,firstPath,external) && SCPreferencesCommitChanges(prefs),"commit private external state");
    auto added=SCNetworkServiceCreate(prefs,interface);check(added,"create new external private service");
    const auto releaseAdded=qScopeGuard([&]{CFRelease(added);});
    auto addedPath=path(added);const auto releaseAddedPath=qScopeGuard([&]{CFRelease(addedPath);});
    check(SCPreferencesPathSetValue(prefs,addedPath,original) && SCNetworkServiceRemove(second) && SCPreferencesCommitChanges(prefs),"external service addition and deletion");
    check(backend.clear().succeeded(),"native restoration respects external changes");
    check(value(addedPath) && CFEqual(value(addedPath),original),"new service is not changed by restoration");
    auto secondParent=CFStringCreateWithFormat(nullptr,nullptr,CFSTR("/%@/%@"),kSCPrefNetworkServices,SCNetworkServiceGetServiceID(second));
    check(!SCPreferencesPathGetValue(prefs,secondParent),"deleted service must not be recreated by restoration");CFRelease(secondParent);
    auto actual=static_cast<CFDictionaryRef>(value(firstPath));
    for(const auto key:{kSCPropNetProxiesHTTPProxy,kSCPropNetProxiesProxyAutoConfigURLString,kSCPropNetProxiesExceptionsList,kSCPropNetProxiesProxyAutoConfigEnable})
        check(CFEqual(CFDictionaryGetValue(actual,key),CFDictionaryGetValue(external,key)),"external proxy/PAC/bypass and dependent mode retained");
    check(!CFDictionaryContainsKey(actual,CFSTR("HTTPProxyUsername")),"old proxy identity is not restored onto an external endpoint");
    std::cout<<"PASS: native SystemConfiguration snapshots, rollback, retries and external ownership in a private preferences file\n";
}
