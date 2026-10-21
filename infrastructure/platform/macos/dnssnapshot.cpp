#include "dnssnapshot.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QScopeGuard>
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
        if (count > 4096) { valid = false; return {}; }
        QJsonArray result;
        for (CFIndex i = 0; i < count && valid; ++i) result.append(json(CFArrayGetValueAtIndex(array, i), depth + 1, valid));
        return result;
    } else if (type == CFDictionaryGetTypeID()) {
        const auto dictionary = static_cast<CFDictionaryRef>(value);
        const auto count = CFDictionaryGetCount(dictionary);
        if (count > 4096) { valid = false; return {}; }
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

DnsSnapshot readMacDnsSnapshot(MacDnsRead read)
{
    using Status = PlatformOperationResult::Status;
    const auto store = SCDynamicStoreCreate(nullptr, CFSTR("JustConnect DNS snapshot"), nullptr, nullptr);
    if (!store) return {{Status::Failed, "Cannot open system resolver store"}, {}};
    const auto releaseStore = qScopeGuard([&] { CFRelease(store); });
    const void *pattern = CFSTR("^(State|Setup):/Network/.*/DNS$");
    const auto patterns = CFArrayCreate(nullptr, &pattern, 1, &kCFTypeArrayCallBacks);
    if (!patterns) return {{Status::Failed, "Cannot prepare system resolver query"}, {}};
    const auto releasePatterns = qScopeGuard([&] { CFRelease(patterns); });
    const auto values = read(store, nullptr, patterns);
    if (!values) return {{Status::Failed, "Cannot read system resolver store"}, {}};
    const auto releaseValues = qScopeGuard([&] { CFRelease(values); });
    bool valid = true;
    const auto entries = json(values, 0, valid).toObject();
    for (const auto &value : entries) if (!value.isObject()) valid = false;
    if (!valid) return {{Status::Failed, "Unsupported system resolver property"}, {}};
    const QJsonObject data{{"dynamic_store", entries}};
    if (QJsonDocument(data).toJson(QJsonDocument::Compact).size() > 262144)
        return {{Status::Failed, "System resolver snapshot too large"}, {}};
    return {{}, data};
}
