#pragma once

#include "core/connectionoptions.h"
#include <QJsonObject>

namespace ClashExtension {
QString script(const ConnectionOptions &options, const QString &connectionName, const QJsonObject &resources);
QString vergeGlobalScriptPath();
enum class ImportResult { Saved, Unavailable, Conflict, FileError };
ImportResult importScript(const QString &path, const ConnectionOptions &options,
    const QString &connectionName, const QJsonObject &resources);
}
