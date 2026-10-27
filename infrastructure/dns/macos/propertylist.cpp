#include "infrastructure/dns/macos/propertylist.h"
#include "infrastructure/dns/domainlimits.h"
#include <QJsonArray>
#include <QJsonObject>
#include <vector>

namespace {
QJsonValue json(CFTypeRef value, int depth, bool &valid)
{
    if (!value || depth > 8) { valid = false; return {}; }
    const auto type = CFGetTypeID(value);
    if (type == CFStringGetTypeID()) return QString::fromCFString(static_cast<CFStringRef>(value));
    if (type == CFBooleanGetTypeID()) return bool(CFBooleanGetValue(static_cast<CFBooleanRef>(value)));
    if (type == CFNumberGetTypeID()) {
        long long result = 0;
        if (CFNumberGetValue(static_cast<CFNumberRef>(value), kCFNumberLongLongType, &result)) return qint64(result);
    } else if (type == CFArrayGetTypeID()) {
        const auto array = static_cast<CFArrayRef>(value);
        const auto count = CFArrayGetCount(array);
        if (count > CFIndex(NetworkDnsDomainLimit)) { valid = false; return {}; }
        QJsonArray result;
        for (CFIndex i = 0; i < count && valid; ++i) result.append(json(CFArrayGetValueAtIndex(array, i), depth + 1, valid));
        return result;
    } else if (type == CFDictionaryGetTypeID()) {
        const auto dictionary = static_cast<CFDictionaryRef>(value);
        const auto count = CFDictionaryGetCount(dictionary);
        if (count > CFIndex(NetworkDnsDomainLimit)) { valid = false; return {}; }
        std::vector<const void *> keys(count), values(count);
        CFDictionaryGetKeysAndValues(dictionary, keys.data(), values.data());
        QJsonObject result;
        for (CFIndex i = 0; i < count && valid; ++i) {
            if (CFGetTypeID(keys[i]) != CFStringGetTypeID()) { valid = false; break; }
            result.insert(QString::fromCFString(static_cast<CFStringRef>(keys[i])), json(values[i], depth + 1, valid));
        }
        return result;
    }
    valid = false;
    return {};
}
}

std::optional<QJsonValue> macDnsProperties(CFTypeRef value)
{
    bool valid = true;
    const auto result = json(value,0,valid);
    if (!valid) return {};
    return result;
}
