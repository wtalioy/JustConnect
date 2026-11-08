#include "infrastructure/process/applicationinstancelock.h"

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QScopeGuard>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QUuid>
#include <cstdio>

namespace
{
constexpr int waitMs = 5000;

bool acquired(QProcess &process)
{
    if (!process.canReadLine()) process.waitForReadyRead(waitMs);
    return process.readLine().trimmed() == "locked";
}

bool exitedWith(QProcess &process, int code)
{
    return (process.state() == QProcess::NotRunning || process.waitForFinished(waitMs))
        && process.error() != QProcess::FailedToStart
        && process.exitStatus() == QProcess::NormalExit && process.exitCode() == code;
}

bool release(QProcess &process)
{
    process.closeWriteChannel();
    return exitedWith(process, QLockFile::NoError);
}

int fail(const char *message)
{
    qCritical() << message;
    return 1;
}
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QStandardPaths::setTestModeEnabled(true);
    if (argc == 2) {
        QCoreApplication::setApplicationName(QString::fromUtf8(argv[1]));
        const ApplicationInstanceLock lock;
        if (lock.error() != QLockFile::NoError) return lock.error();
        std::puts("locked");
        std::fflush(stdout);
        std::getchar();
        return QLockFile::NoError;
    }

    const auto name = "JustConnect-instance-test-" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    QCoreApplication::setApplicationName(name);
    const auto dataPath = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (dataPath.isEmpty() || QFileInfo(dataPath).fileName() != name)
        return fail("Could not isolate the test data directory");
    const auto cleanup = qScopeGuard([&] { QDir(dataPath).removeRecursively(); });
    const auto executable = QCoreApplication::applicationFilePath();
    QTemporaryDir copyDirectory;
    if (!copyDirectory.isValid()) return fail("Could not create an alternate executable directory");
    const auto copy = copyDirectory.filePath(QFileInfo(executable).fileName());
    if (!QFile::copy(executable, copy)) return fail("Could not copy the test executable");

    QProcess first, second;
    first.start(executable, {name});
    second.start(copy, {name});
    const bool firstAcquired = acquired(first);
    const bool secondAcquired = acquired(second);
    auto &owner = firstAcquired ? first : second;
    auto &duplicate = firstAcquired ? second : first;
    if (firstAcquired == secondAcquired || !exitedWith(duplicate, QLockFile::LockFailedError))
        return fail("Simultaneous launches from different directories must have exactly one owner");

    duplicate.start(owner.program(), {name});
    if (!exitedWith(duplicate, QLockFile::LockFailedError))
        return fail("A second launch from the same directory must be rejected");
    if (!release(owner)) return fail("The owning process failed to exit normally");

    first.start(executable, {name});
    if (!acquired(first)) return fail("Could not acquire the lock after normal exit");
    first.kill();
    if (!first.waitForFinished(waitMs) || first.exitStatus() != QProcess::CrashExit)
        return fail("The lock holder was not forcibly terminated");

    second.start(copy, {name});
    if (!acquired(second) || !release(second)) return fail("Could not recover the lock after forced termination");
    return 0;
}
