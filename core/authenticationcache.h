#pragma once
#include <QByteArray>
#include <QString>
#include <QMetaType>

struct AuthenticationCache {
    QString account;
    QByteArray data;
};

Q_DECLARE_METATYPE(AuthenticationCache)
