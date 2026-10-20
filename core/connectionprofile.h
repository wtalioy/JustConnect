#pragma once
#include <QString>

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
struct ConnectionBehavior { QString bindInterface; bool autoDetectInterface = false; };
struct ConnectionProfile {
    ConnectionCredentials credentials;
    ConnectionEndpoint endpoint;
    DnsOptions dns;
    ProxyOptions proxy;
    ConnectionBehavior behavior;
    bool hasSameAuthentication(const ConnectionProfile &other) const {
        return endpoint.authId == other.endpoint.authId && endpoint.authSubType == other.endpoint.authSubType
            && endpoint.server == other.endpoint.server && endpoint.port == other.endpoint.port
            && endpoint.authType == other.endpoint.authType && endpoint.loginDomain == other.endpoint.loginDomain
            && endpoint.phone == other.endpoint.phone && credentials.username == other.credentials.username
            && credentials.password == other.credentials.password && credentials.totpSecret == other.credentials.totpSecret;
    }
};
