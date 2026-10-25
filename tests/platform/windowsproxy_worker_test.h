#pragma once
#include "infrastructure/systemproxy/windows/proxyrecoverylock.h"
#include <QLockFile>
#include <QStandardPaths>
#include <QDir>

static void nativePersistentRecovery() {
    nativeWorkerCheck(qEnvironmentVariable("GITHUB_ACTIONS")=="true","Native persistent recovery requires a disposable runner");
    auto credentials=createSystemCredentialStore();const auto key=PersistentProxyBackend::credentialKey();
    nativeWorkerCheck(credentials->read(key).status==CredentialStatus::NotFound,"Native product recovery record already exists");
    nativeWorkerCheck(nativeRead(nativeOriginal),"Read native persistent baseline");nativeSaved=true;std::atexit(nativeRestore);
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=prior.invalid:3128","old.invalid","https://pac.invalid/original.pac"};
    nativeWorkerCheck(nativeWrite(original),"Seed native persistent recovery baseline");
    const auto restored=[&] {
        WinState current;
        nativeWorkerCheck(nativeRead(current) && current.flags==original.flags && current.proxy==original.proxy && current.bypass==original.bypass
              && current.pac==original.pac && credentials->read(key).status==CredentialStatus::NotFound,
              "Native product recovery lost original settings or its confirmed record removal");
    };
    {
        NativeProxyWorker owner;owner.call("apply");const auto stored=credentials->read(key);
        nativeWorkerCheck(stored.succeeded(),"Product worker changed WinINet without a protected record");
        {NativeProxyWorker concurrent(false);nativeWorkerCheck(credentials->read(key).value==stored.value,"Refused user owner changed the protected record");}
        owner.stop();restored();
    }
    const auto applicationName=QCoreApplication::applicationName();QCoreApplication::setApplicationName("JustConnect");
    const auto directory=QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);QCoreApplication::setApplicationName(applicationName);
    {
        QLockFile legacy(directory+"/proxy-recovery.lock");legacy.setStaleLockTime(0);nativeWorkerCheck(legacy.tryLock(),"Acquire legacy native directory lock");
        NativeProxyWorker refused(false);restored();
    }
    QString previousOwner;
    {
        NativeProxyWorker owner;owner.call("apply");nativeWorkerCheck(credentials->read(key).succeeded(),"Missing protected worker crash record");owner.crash();
        previousOwner=owner.recoveryOwner();
    }
    {
        NativeProxyWorker fresh(true,previousOwner,true);fresh.call("clear");restored();fresh.stop();
    }
    std::cout<<"PASS: product Windows persistent worker, user/legacy ownership refusal, EOF recovery and fresh process after worker termination\n";
}
