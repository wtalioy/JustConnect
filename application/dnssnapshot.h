#pragma once
#include "application/platformoperationresult.h"
#include <QJsonObject>

struct DnsSnapshot
{
    PlatformOperationResult result;
    QJsonObject data;
};
