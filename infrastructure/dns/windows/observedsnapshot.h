#pragma once
#include "infrastructure/dns/windows/configurationchanges.h"
#include "application/dnssnapshot.h"
#include <functional>
#include <memory>
#include <mutex>
#include <optional>

class WindowsObservedDnsSnapshot {
public:
    explicit WindowsObservedDnsSnapshot(std::function<DnsSnapshot()> reader,
        std::shared_ptr<WindowsDNS::Changes> changes = std::make_shared<WindowsDNS::Changes>())
        : reader(std::move(reader)),changes(std::move(changes)) {}
    DnsSnapshot read()
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (changes->changed()) snapshot.reset();
        if (snapshot) return *snapshot;
        const auto result = reader();
        if (result.result.succeeded() && changes->available() && !changes->pending()) snapshot = result;
        return result;
    }
private:
    std::function<DnsSnapshot()> reader;
    std::shared_ptr<WindowsDNS::Changes> changes;
    std::optional<DnsSnapshot> snapshot;
    std::mutex mutex;
};
