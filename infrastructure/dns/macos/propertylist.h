#pragma once
#include <CoreFoundation/CoreFoundation.h>
#include <QJsonValue>
#include <optional>

// Preserve native DNS value types; reject unsupported, deep or oversized containers.
std::optional<QJsonValue> macDnsProperties(CFTypeRef value);
