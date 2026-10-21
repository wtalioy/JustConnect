#pragma once
#include "coreengine.h"

class AuthMethodsQuery : public QObject {
    Q_OBJECT
public:
    explicit AuthMethodsQuery(CoreEngine *engine,QObject *parent=nullptr);
    bool start(const ConnectionProfile &profile);
    void stop();
    bool isActive() const { return active; }
signals:
    void settled();
    void ready(const QJsonArray &methods);
    void failed(ConnectionError error);
private:
    CoreEngine *engine;
    bool active=false,cancelled=false,received=false;
    QJsonArray methods;
};
