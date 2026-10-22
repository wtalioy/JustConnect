#include "platformcommand.h"
#include <QDeadlineTimer>
#include <QProcess>
#include <QProcessEnvironment>

PlatformCommandResult runPlatformCommand(const QString &program, const QStringList &arguments, int timeoutMs, const QByteArray &input)
{
    using Status = PlatformOperationResult::Status;
    QProcess process;
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert("LC_ALL", "C");
    process.setProcessEnvironment(environment);
    QDeadlineTimer deadline(timeoutMs);
    process.start(program, arguments);
    if (!process.waitForStarted(int(deadline.remainingTime()))) {
        const auto status = process.error() == QProcess::Timedout ? Status::TimedOut : Status::Failed;
        if (process.state() != QProcess::NotRunning) { process.kill(); process.waitForFinished(1000); }
        return {{status, program + ": " + process.errorString()}, {}};
    }
    if (!input.isEmpty()) {
        if (process.write(input) != input.size()) {
            process.kill();
            process.waitForFinished(1000);
            return {{Status::Failed, program + ": cannot submit command input"}, {}};
        }
        process.closeWriteChannel();
    }
    if (!process.waitForFinished(int(deadline.remainingTime()))) {
        process.kill();
        process.waitForFinished(1000);
        return {{Status::TimedOut, program + ": operation timed out"}, {}, QString::fromUtf8(process.readAllStandardError())};
    }
    const QString output = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
    const QString error = QString::fromUtf8(process.readAllStandardError());
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0 || output.startsWith("You need administrator access")) {
        const QString diagnostic = output + error;
        Status status = Status::Failed;
        if ((diagnostic.contains("(-128)") || diagnostic.contains("(-60006)"))) status = Status::Cancelled;
        else if (diagnostic.contains("(-1743)") || diagnostic.contains("(-60005)") || output.startsWith("You need administrator access") || diagnostic.contains("permission denied", Qt::CaseInsensitive)
                 || diagnostic.contains("operation not permitted", Qt::CaseInsensitive)
                 || diagnostic.contains("not authorized", Qt::CaseInsensitive)) status = Status::PermissionDenied;
        return {{status, program + ": exit " + QString::number(process.exitCode())}, output, error};
    }
    return {{}, output, error};
}
