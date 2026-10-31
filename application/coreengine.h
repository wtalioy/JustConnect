#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
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
    enum class RequestStatus { Success, Pending, Stale, Invalid, Unavailable, Limit, Failed };
    Q_ENUM(RequestStatus)
    enum class Snapshot { Network, Resources, Coexistence };
    Q_ENUM(Snapshot)
    using QObject::QObject;
    virtual bool start(const ConnectionProfile &profile, Operation operation = Operation::Connect) = 0;
    virtual void stop() = 0;
    virtual void respond(const QJsonObject &response) = 0;
    virtual void updatePolicy(const QJsonObject &policy) {
        emit policyUpdated(policy["generation"].toString(), policy["revision"].toString(), RequestStatus::Unavailable);
    }
    virtual void updateCoexistence(const QString &generation, const QStringList &, bool = false, const QJsonArray & = {}) {
        emit coexistenceUpdated(generation, RequestStatus::Unavailable);
    }
    virtual void readSnapshot(Snapshot kind, const QString &generation) {
        emit snapshotReady(kind, generation, {}, RequestStatus::Unavailable);
    }

    // Borrowed raw IPv4 TUN fd; queued implementations retain their own reference.
    virtual void attachTUN(const QString &generation, qint32, quint32, bool = false) {
        emit tunAttached(generation, RequestStatus::Unavailable);
    }

    virtual void attachWindowsPipe(const QString &generation, quint64, quint32, quint32, const QString &, const QString &, bool = false) {
        emit tunAttached(generation, RequestStatus::Unavailable);
    }

    virtual void acknowledgeDNSRoutes(const QString &, const QString &, bool) {}

    virtual void prepareOriginalDNS(const QString &generation, const QJsonArray &) {
        emit originalDNSPrepared(generation, {}, RequestStatus::Unavailable);
    }

    static QJsonObject responseFor(const QJsonObject &request, QJsonObject fields) {
        fields["schema_version"] = request["schema_version"];
        fields["generation"] = request["generation"];
        fields["request_id"] = request["request_id"];
        return fields;
    }

signals:
    void sessionStarted(const QString &generation);
    void initialProtectionApplied(const QJsonObject &policy);
    void policyUpdated(const QString &generation, const QString &revision, CoreEngine::RequestStatus status);
    void coexistenceUpdated(const QString &generation, CoreEngine::RequestStatus status);
    void snapshotReady(CoreEngine::Snapshot kind, const QString &generation, const QJsonObject &snapshot, CoreEngine::RequestStatus status);
    void dnsRoutesRequired(const QJsonObject &request);
    void originalDNSPrepared(const QString &generation, const QJsonObject &listeners, CoreEngine::RequestStatus status);
    void dnsRoutesAcknowledged(const QString &generation, const QString &request, CoreEngine::RequestStatus status);
    void tunAttached(const QString &generation, CoreEngine::RequestStatus status);
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
