#include "infrastructure/systemproxy/proxychanges.h"
#include <SystemConfiguration/SystemConfiguration.h>

struct ProxyChanges::Watch {
    SCDynamicStoreRef store = nullptr;
    CFRunLoopSourceRef source = nullptr;
    ~Watch() {
        if (source) {
            CFRunLoopRemoveSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
            CFRelease(source);
        }
        if (store) CFRelease(store);
    }
};

ProxyChanges::ProxyChanges(QObject *parent) : QObject(parent), watch(std::make_unique<Watch>()) {
    SCDynamicStoreContext context{0, this, nullptr, nullptr, nullptr};
    watch->store = SCDynamicStoreCreate(nullptr, CFSTR("JustConnect proxy observer"),
        [](SCDynamicStoreRef, CFArrayRef, void *info) {
            emit static_cast<ProxyChanges *>(info)->changed();
        }, &context);
    if (!watch->store) return;
    const auto key = SCDynamicStoreKeyCreateProxies(nullptr);
    if (!key) return;
    const void *entry = key;
    const auto keys = CFArrayCreate(nullptr, &entry, 1, &kCFTypeArrayCallBacks);
    CFRelease(key);
    if (!keys) return;
    const bool subscribed = SCDynamicStoreSetNotificationKeys(watch->store, keys, nullptr);
    CFRelease(keys);
    if (!subscribed) return;
    watch->source = SCDynamicStoreCreateRunLoopSource(nullptr, watch->store, 0);
    if (watch->source) CFRunLoopAddSource(CFRunLoopGetMain(), watch->source, kCFRunLoopCommonModes);
}

ProxyChanges::~ProxyChanges() = default;
