#include "externalcoreprocess.h"
#include "infrastructure/coreprocess/corecommandbuilder.h"
#include "infrastructure/coreprocess/consoleoutputdecoder.h"
#include "infrastructure/coreprocess/coreoutputparser.h"
#include "infrastructure/platform/privileges.h"
#include "infrastructure/storage/applicationpaths.h"
#include <qcontainerfwd.h>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

ExternalCoreProcess::ExternalCoreProcess(QObject *parent) : CoreProcess(parent)
{
    process = new QProcess(this);

    connect(process, &QProcess::readyReadStandardOutput, this, [this]()
    {
        processOutput(standardOutputBuffer, process->readAllStandardOutput());
    });

    connect(process, &QProcess::readyReadStandardError, this, [this]()
    {
        processOutput(standardErrorBuffer, process->readAllStandardError());
    });

    connect(process, &QProcess::errorOccurred, this, [&](QProcess::ProcessError err)
    {
        if (stopRequested)
        {
            return;
        }
        QString errorString = process->errorString();
        qWarning().noquote() << "退出原因：" + errorString;

        if (errorString.contains("No such file or directory") || errorString.contains("not found") || errorString.contains("找不到"))
        {
            qWarning().noquote() << "核心路径：" + process->program();
            emit error(ConnectionError::PROGRAM_NOT_FOUND);
        }
    });

    connect(process, &QProcess::finished, this, [&]()
    {
        processOutput(standardOutputBuffer, process->readAllStandardOutput(), true);
        processOutput(standardErrorBuffer, process->readAllStandardError(), true);
        stopRequested = false;
        qInfo().noquote() << "退出原因：进程已结束";
        emit finished();
    });
}

void ExternalCoreProcess::processOutput(CoreOutputBuffer &buffer, const QByteArray &data, bool flushPending)
{
    QList<QByteArray> lines = buffer.append(data);

    if (buffer.hasPendingData())
    {
        if (flushPending || CoreOutputParser::hasInteractivePrompt(buffer.pendingData()))
        {
            lines.append(buffer.takePendingData());
        }
    }

    processOutputLines(lines);
}

void ExternalCoreProcess::processOutputLines(const QList<QByteArray> &lines)
{
    if (lines.isEmpty())
    {
        return;
    }

    QStringList outputLines;
    outputLines.reserve(lines.size());
    for (const QByteArray &line : lines)
    {
        outputLines.append(ConsoleOutputDecoder::decode(line));
    }

    const QString output = outputLines.join('\n');
    emit outputRead(output);

    for (const QString &line : outputLines)
    {
        switch (CoreOutputParser::parse(line))
        {
        case CoreOutputEvent::AskSudoPassword:
            emit askSudoPass();
            break;
        case CoreOutputEvent::GraphCaptcha:
            emit graphCaptcha(CoreOutputParser::graphCaptchaFile(line));
            break;
        case CoreOutputEvent::SmsCodeWithSkipOption:
            emit smsCode(true);
            break;
        case CoreOutputEvent::SmsCode:
            emit smsCode(false);
            break;
        case CoreOutputEvent::TotpCode:
            emit totpCode();
            break;
        case CoreOutputEvent::RandCode:
            emit randCode();
            break;
        case CoreOutputEvent::RadiusCodeWithSkipOption:
            emit radiusCode(true);
            break;
        case CoreOutputEvent::SsoCallback:
            emit ssoAuth();
            break;
        case CoreOutputEvent::ClientStarted:
            emit connectionEstablished();
            break;
        case CoreOutputEvent::CaptchaFailed:
            emit error(ConnectionError::CAPTCHA_FAILED);
            break;
        case CoreOutputEvent::AccessDenied:
            emit error(ConnectionError::ACCESS_DENIED);
            break;
        case CoreOutputEvent::ListenFailed:
            emit error(ConnectionError::LISTEN_FAILED);
            break;
        case CoreOutputEvent::InvalidCredentials:
            emit error(ConnectionError::INVALID_DETAIL);
            break;
        case CoreOutputEvent::BruteForceBlocked:
            emit error(ConnectionError::BRUTE_FORCE);
            break;
        case CoreOutputEvent::LoginFailed:
            emit error(ConnectionError::OTHER_LOGIN_FAILED);
            break;
        case CoreOutputEvent::InteractiveError:
            emit error(ConnectionError::INTERACTIVE_ERROR);
            break;
        case CoreOutputEvent::AuthNotAvailable:
            emit error(ConnectionError::AUTH_NOT_AVAILABLE);
            break;
        case CoreOutputEvent::AuthExpired:
            emit error(ConnectionError::AUTH_EXPIRED);
            break;
        case CoreOutputEvent::ClientFailed:
            emit error(ConnectionError::CLIENT_FAILED);
            break;
        case CoreOutputEvent::CorePanic:
            emit error(ConnectionError::OTHER);
            break;
        case CoreOutputEvent::None:
            break;
        }
    }
}

QString ExternalCoreProcess::copyCoreForAppImage(const QString &programPath)
{
#if defined(Q_OS_UNIX)
    static QString cachedSourcePath;
    static QString cachedTempPath;

    if (!qEnvironmentVariableIsSet("APPIMAGE")) {
        return programPath;
    }

    if (cachedSourcePath == programPath && !cachedTempPath.isEmpty() && QFileInfo::exists(cachedTempPath)) {
        return cachedTempPath;
    }

    const QFileInfo sourceInfo(programPath);
    if (!sourceInfo.exists() || !sourceInfo.isFile()) {
        return programPath;
    }

    const QString tempRoot = QStandardPaths::writableLocation(QStandardPaths::TempLocation)
                             + "/JustConnect-" + QString::number(QCoreApplication::applicationPid());
    QDir().mkpath(tempRoot);

    const QString tempPath = tempRoot + "/" + sourceInfo.fileName();
    if (QFileInfo::exists(tempPath)) {
        QFile::remove(tempPath);
    }

    if (!QFile::copy(programPath, tempPath)) {
        return programPath;
    }

    QFile::setPermissions(tempPath,
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
                          QFileDevice::ReadGroup | QFileDevice::ExeGroup |
                          QFileDevice::ReadOther | QFileDevice::ExeOther);
    cachedSourcePath = programPath;
    cachedTempPath = tempPath;
    return tempPath;
#else
    return programPath;
#endif
}

void ExternalCoreProcess::start(const ConnectionProfile &profile)
{
    CoreRuntimePaths runtimePaths;

    // Both protocols can require a graph captcha. The UI chooses the response
    // format according to the active protocol.
    if (tempDir == nullptr)
    {
        tempDir = new QTemporaryDir;
        tempDir->setAutoRemove(true);
    }
    runtimePaths.graphCodeFile = tempDir->filePath("graph.jpg");

    if (profile.endpoint.protocol == "atrust")
    {
        runtimePaths.clientDataFile = ApplicationPaths::clientDataFile(profile.profileId);
    }

    const ApplicationPaths::DebugArtifactPaths debugPaths =
        ApplicationPaths::createDebugArtifactFiles(
            profile.profileId,
            profile.debug.capturePcap,
            profile.debug.exportTlsKeys
        );
    runtimePaths.debugPcapFile = debugPaths.pcapFile;
    runtimePaths.debugTlsLogFile = debugPaths.tlsLogFile;

    const CoreCommand command = CoreCommandBuilder::build(profile, runtimePaths);
    qInfo().noquote() << "VPN 启动！参数：" + command.loggableCommandLine();

    if (!profile.credentials.totpSecret.isEmpty())
    {
        qInfo().noquote() << "使用了 TOTP";
    }
    if (profile.endpoint.protocol == "easyconnect"
        && !profile.credentials.certFile.isEmpty())
    {
        qInfo().noquote() << "使用了证书文件";
    }

    QString programToStart = profile.program;
    QStringList finalArgs = command.arguments;
    QProcessEnvironment processEnvironment = QProcessEnvironment::systemEnvironment();
    for (const QString &name : command.clearedEnvironmentVariables)
    {
        processEnvironment.remove(name);
    }
    for (auto iterator = command.environmentVariables.cbegin();
         iterator != command.environmentVariables.cend(); ++iterator)
    {
        processEnvironment.insert(iterator.key(), iterator.value());
    }

#if defined(Q_OS_UNIX)
    if (profile.tunnel.tunMode && !Privileges::isElevated())
    {
        programToStart = copyCoreForAppImage(programToStart);

        QStringList sudoArgs;
        sudoArgs << "-p" << "SUDO_ASK_PASS";
        sudoArgs << "-S";
        if (!command.environmentVariables.isEmpty())
        {
            sudoArgs << "--preserve-env=" + command.environmentVariables.keys().join(',');
        }
        sudoArgs << programToStart << finalArgs;
        programToStart = "sudo";
        finalArgs = sudoArgs;
    }
#endif

    process->setProcessEnvironment(processEnvironment);
    process->start(programToStart, finalArgs);
    process->waitForStarted();
    if (process->state() == QProcess::NotRunning)
    {
        emit finished();
    }
    else
    {
        emit started();
    }
}

void ExternalCoreProcess::stop()
{
    if (process->state() == QProcess::NotRunning)
    {
        return;
    }

    if (!stopRequested)
    {
        stopRequested = true;
        process->terminate();
    }
    else
    {
        process->kill();
    }
}

void ExternalCoreProcess::writeInput(const QByteArray &data)
{
    process->write(data);
}

ExternalCoreProcess::~ExternalCoreProcess()
{
    disconnect(process, nullptr, this, nullptr);

    if (process->state() == QProcess::NotRunning)
    {
        return;
    }

    process->terminate();
    if (!process->waitForFinished(3000))
    {
        process->kill();
        process->waitForFinished();
    }
}
