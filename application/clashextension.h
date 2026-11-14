#pragma once

#include "core/connectionoptions.h"
#include <QJsonObject>

namespace ClashExtension {
QString script(const ConnectionOptions &options, const QString &connectionName, const QJsonObject &resources);
}
