#pragma once
#include <QString>
#include <QJsonArray>
#include <QMetaType>
#include "core/authenticationcache.h"

struct ConnectionCredentials { QString username, password, totpSecret; };
struct ConnectionEndpoint {
    QString authType, loginDomain, phone, server, authId, authSubType;
    int port = 0;
};
struct DnsOptions {
    QString secondary;
    int ttl = 3600;
    bool disableRemoteDns = false;
    QString localDnsServer;
};
struct ProxyOptions { QString socksBind, httpBind; };
struct ConnectionBehavior { QString bindInterface; bool autoDetectInterface = false; bool rememberAuthentication = false; };
struct TlsOptions { bool verify = true; QString caPem; };
struct ConnectionProfile {
    TlsOptions tls;
    ConnectionCredentials credentials;
    ConnectionEndpoint endpoint;
    DnsOptions dns;
    ProxyOptions proxy;
    ConnectionBehavior behavior;
    AuthenticationCache authenticationCache;
    bool matchesCacheAccount(const QString &account) const {
        return !account.isEmpty() && ((endpoint.authType!="cas" && endpoint.authType!="httpsOauth2") || credentials.username==account);
    }
    QJsonArray authenticationIdentity() const {
        return {endpoint.server.toLower(),endpoint.port,endpoint.authType,endpoint.loginDomain,
            endpoint.authId,endpoint.authSubType,endpoint.phone,credentials.username};
    }

};

Q_DECLARE_METATYPE(TlsOptions)
