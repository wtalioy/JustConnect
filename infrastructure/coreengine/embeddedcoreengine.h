#pragma once

#include <QThread>
#include "application/coreengine.h"

class CoreEventPump;

class EmbeddedCoreEngine final : public CoreEngine
{
    Q_OBJECT
public:
    explicit EmbeddedCoreEngine(QObject *parent = nullptr);
    ~EmbeddedCoreEngine() override;
    bool start(const ConnectionProfile &profile, Operation operation = Operation::Connect) override;
    void stop() override;
    void respond(const QJsonObject &response) override;
    void updatePolicy(const QJsonObject &policy) override;
    void readSnapshot(Snapshot kind, const QString &generation) override;
    void attachTUN(const QString &generation, qint32 descriptor, quint32 mtu, bool publishDNSRoutes = false) override;
    void acknowledgeDNSRoutes(const QString &generation, const QString &request, bool applied) override;
    static ConnectionError validateConfiguration(const ConnectionProfile &profile);
    static QJsonObject buildInfo();
    static QJsonObject selfTest();

private:
    void deliver(quint64 serial, const QJsonObject &event, const QJsonObject &initialPolicy);
    QThread thread;
    CoreEventPump *pump;
    quint64 serial = 0;
    bool active = false;
    bool stopping = false;
};
