#pragma once
#include "infrastructure/credentialstore/macos/credentialstore.h"
#include "infrastructure/systemproxy/persistentproxy.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLockFile>
#include <QProcessEnvironment>
#include <QScopeGuard>
#include <QStandardPaths>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

class NativeMacKeychain {
    QTemporaryDir directory{"/tmp/jcpr-keychain-XXXXXX"};
    SecKeychainRef previous=nullptr,keychain=nullptr;
    CFArrayRef searchList=nullptr;
    OSStatus previousStatus=errSecNoDefaultKeychain;
    bool restore() {
        bool okay=true;
        if (keychain) {
            // Retain the protected evidence if a failing worker test still owns native changes.
            const auto record=createMacCredentialStore(keychain)->read(PersistentProxyBackend::credentialKey());
            const bool retained=record.status!=CredentialStatus::NotFound;
            if (previous) okay=SecKeychainSetDefault(previous)==errSecSuccess;
            if (retained) {directory.setAutoRemove(false);okay=false;}
            else okay=(SecKeychainDelete(keychain)==errSecSuccess) && okay;
            CFRelease(keychain);keychain=nullptr;
        }
        if (searchList) {
            okay=(SecKeychainSetSearchList(searchList)==errSecSuccess) && okay;
            CFArrayRef currentList=nullptr;
            okay=(SecKeychainCopySearchList(&currentList)==errSecSuccess && currentList && CFEqual(searchList,currentList)) && okay;
            if (currentList) CFRelease(currentList);
            CFRelease(searchList);searchList=nullptr;
            SecKeychainRef current=nullptr;const auto status=SecKeychainCopyDefault(&current);
            okay=(previous ? status==errSecSuccess && current && CFEqual(previous,current) : status==previousStatus) && okay;
            if (current) CFRelease(current);
        }
        if (previous) {CFRelease(previous);previous=nullptr;}
        return okay;
    }
public:
    NativeMacKeychain() {
        nativeWorkerCheck(qEnvironmentVariable("GITHUB_ACTIONS")=="true" && directory.isValid(),
                          "Private default Keychain fixture requires a disposable runner");
        const QFileInfo accountDirectory(qEnvironmentVariable("HOME"));
        nativeWorkerCheck(accountDirectory.isDir() && accountDirectory.ownerId()==geteuid(),
                          "Private Keychain fixture requires the effective account's own home directory");
        bool ready=false;const auto failed=qScopeGuard([&]{if(!ready)restore();});
        previousStatus=SecKeychainCopyDefault(&previous);
        nativeWorkerCheck(previousStatus==errSecSuccess || previousStatus==errSecNoDefaultKeychain,"Read original default Keychain scope");
        nativeWorkerCheck(SecKeychainCopySearchList(&searchList)==errSecSuccess,"Save original Keychain search scope");
        const auto file=directory.filePath("worker.keychain-db").toUtf8();const QByteArray password="private worker fixture";
        nativeWorkerCheck(SecKeychainCreate(file.constData(),UInt32(password.size()),password.constData(),false,nullptr,&keychain)==errSecSuccess
                          && SecKeychainUnlock(keychain,UInt32(password.size()),password.constData(),true)==errSecSuccess,
                          "Create unlocked private worker Keychain");
        const void *items[]{keychain};auto selected=CFArrayCreate(nullptr,items,1,&kCFTypeArrayCallBacks);
        const auto releaseSelected=qScopeGuard([&]{CFRelease(selected);});
        nativeWorkerCheck(SecKeychainSetDefault(keychain)==errSecSuccess && SecKeychainSetSearchList(selected)==errSecSuccess,
                          "Select private native worker credential scope");ready=true;
    }
    ~NativeMacKeychain() {if(!restore())std::cerr<<"Private worker Keychain cleanup incomplete; protected evidence retained if unresolved\n";}
    void finish() {nativeWorkerCheck(restore(),"Restore original default Keychain/search scope and delete private provider");}
};

static void nativeMacLockProbe(bool foreign) {
    nativeWorkerCheck(qEnvironmentVariable("GITHUB_ACTIONS")=="true","Mac scope probe requires a disposable runner");
    if (foreign) {
        const auto *account=getpwnam("nobody");
        nativeWorkerCheck(geteuid()==0 && account && account->pw_uid!=0,"Foreign scope probe requires root and a nobody account");
        const auto uid=account->pw_uid;const auto gid=account->pw_gid;
        nativeWorkerCheck(setgroups(0,nullptr)==0 && setgid(gid)==0 && setuid(uid)==0 && getuid()==uid && geteuid()==uid,
                          "Permanently drop the directly owned scope probe to another account");
        nativeWorkerCheck(QFileInfo(MacProxyRecoveryLockFile).ownerId()!=uid,"Foreign scope fixture shares its lock owner's account");
    }
    QLockFile lock(MacProxyRecoveryLockFile);lock.setStaleLockTime(0);
    nativeWorkerCheck(!lock.tryLock() && QFile::exists(MacProxyRecoveryLockFile),"Mac scope probe acquired or removed another owner's lock");
}

static void nativeMacOwnership() {
    nativeWorkerCheck(qEnvironmentVariable("GITHUB_ACTIONS")=="true" && geteuid()!=0,"Mac ownership test requires an ordinary disposable runner account");
    nativeWorkerCheck(!QFile::exists(MacProxyRecoveryLockFile),"An unknown Mac system proxy owner already exists");
    NativeMacKeychain credentials;
    QTemporaryDir root("/tmp/jcpr-scope-XXXXXX");
    nativeWorkerCheck(root.isValid() && QDir().mkpath(root.filePath("tmp")),"Create distinct Mac scope probe roots");
    const auto contents=[] {
        QFile file(MacProxyRecoveryLockFile);nativeWorkerCheck(file.open(QIODevice::ReadOnly),"Read the owned Mac scope lock");return file.readAll();
    };
    const auto probe=[&](bool foreign) {
        QProcess process;process.setWorkingDirectory(root.path());
        auto environment=QProcessEnvironment::systemEnvironment();environment.insert("TMPDIR",root.filePath("tmp"));
        process.setProcessEnvironment(environment);
        if (foreign) process.start("/usr/bin/sudo",{"-n","/usr/bin/env","GITHUB_ACTIONS=true",QCoreApplication::applicationFilePath(),"--native-foreign-scope-probe"});
        else process.start(QCoreApplication::applicationFilePath(),{"--native-scope-probe"});
        nativeWorkerCheck(process.waitForStarted(5000) && process.waitForFinished(5000)
                          && process.exitStatus()==QProcess::NormalExit && process.exitCode()==0,
                          qPrintable("Native Mac scope probe failed: "+QString::fromUtf8(process.readAllStandardError())));
    };
    {
        NativeProxyWorker owner;const auto before=contents();
        probe(false);probe(true);
        { NativeProxyWorker concurrent(false); }
        nativeWorkerCheck(contents()==before,"A rejected Mac owner changed the active scope lock");
        owner.stop();
    }
    nativeWorkerCheck(!QFile::exists(MacProxyRecoveryLockFile),"Normal Mac recovery worker exit retained its scope lock");
    const auto applicationName=QCoreApplication::applicationName();QCoreApplication::setApplicationName("JustConnect");
    const auto directory=QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);QCoreApplication::setApplicationName(applicationName);
    {
        QLockFile legacy(directory+"/proxy-recovery.lock");legacy.setStaleLockTime(0);
        nativeWorkerCheck(legacy.tryLock(),"Acquire the legacy Mac directory lock");
        NativeProxyWorker refused(false);
        nativeWorkerCheck(!QFile::exists(MacProxyRecoveryLockFile),"Legacy Mac refusal retained a system scope lock");
    }
    {
        NativeProxyWorker owner;const auto before=contents();owner.crash();
        probe(true);nativeWorkerCheck(contents()==before,"Another account removed a stale Mac ownership lock");
    }
    { NativeProxyWorker fresh;fresh.stop(); }
    nativeWorkerCheck(!QFile::exists(MacProxyRecoveryLockFile),"Fresh Mac worker did not release recovered stale ownership");
    credentials.finish();
    std::cout<<"PASS: product macOS system scope excludes distinct roots/accounts, retains foreign stale ownership, honors legacy locks and recovers after owned termination\n";
}

static void nativeMacPersistentRecovery() {
    nativeWorkerCheck(qEnvironmentVariable("GITHUB_ACTIONS")=="true" && geteuid()==0,
                      "Native Mac persistent recovery requires root on a disposable runner");
    nativeWorkerCheck(!QFile::exists(MacProxyRecoveryLockFile),"An unknown Mac system proxy owner already exists");
    NativeMacKeychain provider;
    const auto key=PersistentProxyBackend::credentialKey();
    // Observe item identity without requesting another executable's protected secret or weakening its ACL.
    const auto recordReference=[&] {
        auto query=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        const auto releaseQuery=qScopeGuard([&]{CFRelease(query);});
        CFDictionarySetValue(query,kSecClass,kSecClassGenericPassword);CFDictionarySetValue(query,kSecAttrService,MacCredentialService);
        auto account=CFStringCreateWithCharacters(nullptr,reinterpret_cast<const UniChar *>(key.utf16()),key.size());
        CFDictionarySetValue(query,kSecAttrAccount,account);CFRelease(account);
        CFDictionarySetValue(query,kSecUseAuthenticationUI,kSecUseAuthenticationUIFail);
        CFDictionarySetValue(query,kSecReturnPersistentRef,kCFBooleanTrue);
        CFDictionarySetValue(query,kSecMatchLimit,kSecMatchLimitOne);
        CFTypeRef reference=nullptr;const auto status=SecItemCopyMatching(query,&reference);
        const auto releaseReference=qScopeGuard([&]{if(reference)CFRelease(reference);});
        nativeWorkerCheck(status==errSecSuccess || status==errSecItemNotFound,
                          qPrintable(QString("Observe native recovery item identity: %1").arg(status)));
        if(status==errSecItemNotFound)return QByteArray{};
        nativeWorkerCheck(reference && CFGetTypeID(reference)==CFDataGetTypeID(),"Native recovery item identity type");
        auto data=static_cast<CFDataRef>(reference);nativeWorkerCheck(CFDataGetLength(data)>0,"Native recovery item identity is empty");
        return QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(data)),CFDataGetLength(data));
    };
    nativeWorkerCheck(recordReference().isEmpty(),"Native Mac recovery record already exists");
    AuthorizationRef authorization=nullptr;auto preferences=createMacProxyPreferences(&authorization);
    nativeWorkerCheck(preferences,"Open disposable runner proxy preferences");
    const auto releasePreferences=qScopeGuard([&]{CFRelease(preferences);if(authorization)AuthorizationFree(authorization,kAuthorizationFlagDefaults);});
    QMap<QString,CFPropertyListRef> original;
    const auto releaseOriginal=qScopeGuard([&]{for(auto value:original)if(value)CFRelease(value);});
    const auto read=[&] {
        SCPreferencesSynchronize(preferences);auto services=SCNetworkServiceCopyAll(preferences);
        nativeWorkerCheck(services,"Read disposable runner network services");
        const auto releaseServices=qScopeGuard([&]{CFRelease(services);});
        QMap<QString,CFPropertyListRef> values;
        for(CFIndex i=0;i<CFArrayGetCount(services);++i) {
            auto service=static_cast<SCNetworkServiceRef>(CFArrayGetValueAtIndex(services,i));auto location=path(service);
            values[QString::fromCFString(location)]=SCPreferencesPathGetValue(preferences,location);CFRelease(location);
        }
        return values;
    };
    original=read();nativeWorkerCheck(!original.isEmpty(),"Disposable runner has no proxy service fixture");
    for(auto value:original)if(value)CFRetain(value);
    const auto restored=[&] {
        const auto current=read();nativeWorkerCheck(current.keys()==original.keys(),"Native Mac worker changed the network service set");
        for(auto i=original.cbegin();i!=original.cend();++i) {
            auto value=current.value(i.key());nativeWorkerCheck(i.value()?value && CFEqual(value,i.value()):!value,
                                                              "Native Mac worker lost original typed proxy/PAC/bypass values");
        }
        nativeWorkerCheck(recordReference().isEmpty(),"Native Mac worker retained a restored record");
    };
    auto cleanup=qScopeGuard([&] {
        try {
            if(recordReference().isEmpty())return;
            NativeProxyWorker recovery;recovery.call("clear");recovery.stop();
        } catch(const std::exception &) {std::cerr<<"Disposable Mac worker recovery remains unresolved\n";}
    });
    {
        NativeProxyWorker owner;owner.call("apply");const auto record=recordReference();
        nativeWorkerCheck(!record.isEmpty(),"Product Mac worker changed preferences without protected recovery data");
        PlatformSystemProxyBackend observation;const auto active=observation.check(config);
        nativeWorkerCheck(active.result.succeeded() && active.active && !active.conflict,"Product Mac endpoints failed native readback");
        {NativeProxyWorker refused(false);nativeWorkerCheck(recordReference()==record,"Refused Mac owner replaced protected recovery data");}
        owner.stop();restored();
    }
    QString previousOwner;
    {
        NativeProxyWorker owner;owner.call("apply");
        nativeWorkerCheck(!recordReference().isEmpty(),"Missing protected product Mac crash record");owner.crash();
        previousOwner=owner.recoveryOwner();
    }
    {NativeProxyWorker fresh(true,previousOwner,true);fresh.call("clear");restored();fresh.stop();}
    nativeWorkerCheck(!QFile::exists(MacProxyRecoveryLockFile),"Persistent Mac recovery left a machine owner lock");
    cleanup.dismiss();provider.finish();
    std::cout<<"PASS: product macOS persistent worker, native endpoints, concurrent refusal, EOF and fresh process after owned termination\n";
}
