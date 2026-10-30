#include "infrastructure/autostart/autostart.h"
#include "infrastructure/process/command.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QSettings>
#include <QTemporaryDir>
#include <QUuid>
#include <QStandardPaths>
#include <QElapsedTimer>
#include <QThread>
#include <QDeadlineTimer>
#include <QSet>
#include <iostream>
#include <cstdlib>

static void check(bool ok, const char *message) { if (!ok) { std::cerr << message << '\n'; std::exit(1); } }
int main(int argc, char **argv) {
#ifdef Q_OS_MACOS
    QDeadlineTimer compilationDeadline(JC_AUTOSTART_TEST_BUDGET_MS - PlatformCommandCleanupTimeoutMs);
#endif
    QCoreApplication app(argc,argv);
    app.setApplicationName("JustConnect-autostart-test-" + QUuid::createUuid().toString(QUuid::Id128));
    using Status = PlatformOperationResult::Status;
    QTemporaryDir directory;
    check(directory.isValid(), "isolated autostart storage");
#ifdef Q_OS_LINUX
    qputenv("XDG_CONFIG_HOME", directory.path().toUtf8());
    const auto executable = directory.filePath("Application \"quote\" $cash `tick` %f \\ slash.AppImage");
    const auto marker = directory.filePath("launched");
    QFile script(executable);
    check(script.open(QIODevice::WriteOnly),"create application script");
    script.write(("#!/bin/sh\nprintf '%s' \"$0\" > '" + marker + "'\n").toUtf8()); script.close();
    check(script.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner), "executable script");
    qputenv("APPIMAGE", executable.toUtf8());
    auto result = AutoStart::setEnabled(true);
    check(result.succeeded(),qPrintable(result.detail));
    const auto entry = directory.filePath("autostart/"+app.applicationName()+".desktop");
    check(runPlatformCommand("gio",{"launch",entry}).result.succeeded(),"actual desktop Exec parser accepts escaped path");
    QElapsedTimer timer; timer.start();
    while (!QFileInfo::exists(marker) && timer.elapsed()<5000) QThread::msleep(10);
    QFile launched(marker);
    check(launched.open(QIODevice::ReadOnly) && launched.readAll()==executable.toUtf8(),"desktop launch used exact executable path, not shell expansions");
    QFile previous(entry); check(previous.open(QIODevice::ReadOnly),"read saved entry"); const auto contents=previous.readAll(); previous.close();
    qputenv("APPIMAGE",directory.filePath("missing").toUtf8());
    check(!AutoStart::setEnabled(true).succeeded(),"invalid executable rejected");
    check(previous.open(QIODevice::ReadOnly) && previous.readAll()==contents,"failed enable preserved existing entry"); previous.close();
    check(AutoStart::setEnabled(false).succeeded() && !QFileInfo::exists(entry),"disable verified without requiring old executable");
    check(AutoStart::setEnabled(false).succeeded(),"repeated disable idempotent");
    check(QFile::link(executable,entry),"symlink fixture");
    check(!AutoStart::setEnabled(true).succeeded(),"symlink entry rejected"); QFile::remove(entry);
    qputenv("APPIMAGE",executable.toUtf8());
    check(QFile(entry).open(QIODevice::WriteOnly),"existing entry fixture");
    const auto folder = directory.filePath("autostart");
    check(QFile::setPermissions(folder,QFileDevice::ReadOwner|QFileDevice::ExeOwner),"restrict autostart directory");
    check(!AutoStart::setEnabled(true).succeeded(),"unwritable directory failure propagated");
    QFile::setPermissions(folder,QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner);
#elif defined(Q_OS_WIN)
    QSettings run(R"(HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run)",QSettings::NativeFormat);
    check(!run.contains(app.applicationName()), "test owns a fresh Run value");
    static const QString ownedName = app.applicationName();
    std::atexit([] {
        QSettings cleanup(R"(HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run)", QSettings::NativeFormat);
        cleanup.remove(ownedName); cleanup.sync();
    });
    auto result=AutoStart::setEnabled(true);
    check(result.succeeded(),qPrintable(result.detail));
    run.sync();
    check(run.value(app.applicationName()).toString()==('"'+QDir::toNativeSeparators(app.applicationFilePath())+'"'),"actual Run entry uses quoted executable");
    result=AutoStart::setEnabled(false); run.sync();
    check(result.succeeded() && !run.contains(app.applicationName()),"only test Run value removed");
    check(AutoStart::setEnabled(false).succeeded(),"disable idempotent");
#elif defined(Q_OS_MACOS)
    int calls=0, count=0;
    bool deny=false, ignore=false, malformed=false;
    QSet<QString> scripts;
    PlatformCommandRunner runner=[&](const QString &program,const QStringList &args) -> PlatformCommandResult {
        check(program=="/usr/bin/osascript" && args.size()==2,"fixed AppleScript interpreter, no shell");
        ++calls;
        if (deny) return {{Status::Cancelled,"authorization cancelled"},{}};
        const auto script=args[1];
        scripts.insert(script);
        if (script.contains("return count")) return {{}, malformed ? QString("invalid") : QString::number(count)};
        check(script.contains("path is not") && script.contains("path is "),"mutation limited to matching application item");
        if (!ignore) count=script.contains("make login item") ? 1 : 0;
        return {};
    };
    deny=true;
    check(AutoStart::setEnabled(true,runner).status==Status::Cancelled && calls==1,"query cancellation performs no mutation");
    deny=false; malformed=true;
    check(!AutoStart::setEnabled(true,runner).succeeded(),"malformed item query rejected");
    malformed=false; ignore=true;
    auto result=AutoStart::setEnabled(true,runner);
    check(!result.succeeded() && result.mayHaveChanged,"zero exit without actual item rejected");
    ignore=false;
    check(AutoStart::setEnabled(true,runner).succeeded(),"login item creation and verification");
    check(AutoStart::setEnabled(false,runner).succeeded() && count==0,"login item deletion and verification");
    check(AutoStart::setEnabled(false,runner).succeeded(),"missing item disable idempotent");
    QString compilation;
    int handler = 0;
    for (const auto &script : scripts) {
        const QString name = "autostart_fixture_" + QString::number(handler++);
        compilation += "on " + name + "()\n" + script + "\nend " + name + "\n";
    }
    // Load the real dictionary once, compiling every distinct production script within the existing test budget.
    const auto compiled = runPlatformCommand("/usr/bin/osacompile",
        {"-o",directory.filePath("login-item.scpt"),"-e",compilation}, int(compilationDeadline.remainingTime()));
    check(compiled.result.succeeded(), qPrintable("Compile actual AppleScript: " + compiled.result.detail + '\n' + compiled.standardError));
    std::cout << "UNVERIFIED: interactive System Events authorization; tests use an isolated command boundary\n";
#endif
    app.setApplicationName("invalid/name");
    check(!AutoStart::setEnabled(true).succeeded(),"invalid item name rejected before mutation");
    std::cout << "PASS: autostart results, readback and isolated changes\n";
}
