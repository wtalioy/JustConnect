#pragma once
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLockFile>
#include <QProcessEnvironment>
#include <QStandardPaths>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

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
    std::cout<<"PASS: product macOS system scope excludes distinct roots/accounts, retains foreign stale ownership, honors legacy locks and recovers after owned termination\n";
}
