#ifndef EXTERNALCOREPROCESS_H
#define EXTERNALCOREPROCESS_H

#include <QtCore>

#include "application/coreprocess.h"
#include "infrastructure/coreprocess/coreoutputbuffer.h"

class ExternalCoreProcess : public CoreProcess
{
Q_OBJECT

public:
    explicit ExternalCoreProcess(QObject *parent = nullptr);

    ~ExternalCoreProcess() override;

    void start(const ConnectionProfile &profile) override;

    void stop() override;

    void writeInput(const QByteArray &data) override;

private:
    QString copyCoreForAppImage(const QString &programPath);

    void processOutput(CoreOutputBuffer &buffer, const QByteArray &data, bool flushPending = false);

    void processOutputLines(const QList<QByteArray> &lines);

    QProcess *process;

    QTemporaryDir *tempDir = nullptr;

    CoreOutputBuffer standardOutputBuffer;
    CoreOutputBuffer standardErrorBuffer;
    bool stopRequested = false;

};

#endif // EXTERNALCOREPROCESS_H
