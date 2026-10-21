#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QDateTime>

#include "core/connectionerror.h"
#include "core/connectionprofile.h"

// Authentication keeps the ABI's string generation/request IDs through the UI.
class CoreEngine : public QObject
{
    Q_OBJECT
public:
    enum class Operation { Connect, AuthMethods };
    enum class PolicyUpdateStatus { Applied, Stale, Invalid, Unavailable, Failed };
    Q_ENUM(PolicyUpdateStatus)
    using QObject::QObject;
    virtual bool start(const ConnectionProfile &profile, Operation operation = Operation::Connect) = 0;
    virtual void stop() = 0;
    virtual void respond(const QJsonObject &response) = 0;
    virtual void updatePolicy(const QJsonObject &policy) {
        emit policyUpdated(policy["generation"].toString(), policy["revision"].toString(), PolicyUpdateStatus::Unavailable);
    }

    static QJsonObject responseFor(const QJsonObject &request, QJsonObject fields) {
        fields["schema_version"] = request["schema_version"];
        fields["generation"] = request["generation"];
        fields["request_id"] = request["request_id"];
        return fields;
    }

signals:
    void sessionStarted(const QString &generation);
    void policyUpdated(const QString &generation, const QString &revision, CoreEngine::PolicyUpdateStatus status);
    void authenticationRequired(const QJsonObject &request);
    void authMethodsReady(const QJsonArray &methods);
    void diagnostic(const QString &code);
    void observation(const QString &stage, const QString &result, const QDateTime &observedAt);
    void authenticationCacheUpdated(const AuthenticationCache &cache);
    void authenticationCacheInvalidated();
    void connectionEstablished();
    void finished(ConnectionError error);
    void responseAccepted();
    void responseRejected();
};
