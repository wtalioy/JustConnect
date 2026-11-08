#include "infrastructure/systemproxy/proxychanges.h"
#include <SystemConfiguration/SystemConfiguration.h>
#include <dispatch/dispatch.h>

struct ProxyChanges::Watch {
    SCDynamicStoreRef store = nullptr;
    dispatch_queue_t queue = nullptr;
    ~Watch() {
        if (queue) {
            SCDynamicStoreSetDispatchQueue(store, nullptr);
            dispatch_sync(queue, ^{});
            dispatch_release(queue);
        }
        if (store) CFRelease(store);
    }
};

ProxyChanges::ProxyChanges(QObject *parent) : QObject(parent), watch(std::make_unique<Watch>()) {
    SCDynamicStoreContext context{0, this, nullptr, nullptr, nullptr};
    watch->store = SCDynamicStoreCreate(nullptr, CFSTR("JustConnect proxy observer"),
        [](SCDynamicStoreRef, CFArrayRef, void *info) {
            auto *observer = static_cast<ProxyChanges *>(info);
            QMetaObject::invokeMethod(observer, &ProxyChanges::changed, Qt::QueuedConnection);
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
    watch->queue = dispatch_queue_create("JustConnect.proxy.observer", DISPATCH_QUEUE_SERIAL);
    SCDynamicStoreSetDispatchQueue(watch->store, watch->queue);
}

ProxyChanges::~ProxyChanges() = default;
