#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QObject>

#include "core/connectionerror.h"
#include "core/connectionprofile.h"

// Authentication keeps the ABI's string generation/request IDs through the UI.
class CoreEngine : public QObject
{
    Q_OBJECT
public:
    enum class Operation { Connect, AuthMethods };
    using QObject::QObject;
    virtual bool start(const ConnectionProfile &profile, Operation operation = Operation::Connect) = 0;
    virtual void stop() = 0;
    virtual void respond(const QJsonObject &response) = 0;

signals:
    void authenticationRequired(const QJsonObject &request);
    void authMethodsReady(const QJsonArray &methods);
    void diagnostic(const QString &code);
    void connectionEstablished();
    void finished(ConnectionError error);
    void responseRejected();
};
