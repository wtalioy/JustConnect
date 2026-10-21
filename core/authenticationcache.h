#pragma once
#include <QByteArray>
#include <QString>

struct AuthenticationCache {
    QString account;
    QByteArray data;
};
