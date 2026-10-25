#include "infrastructure/systemproxy/platformsystemproxybackend.h"
SystemProxyCheck PlatformSystemProxyBackend::check(const SystemProxyConfig &) {
    return {{PlatformOperationResult::Status::Unsupported, "System proxy is unsupported on this platform"}, false};
}
PlatformOperationResult PlatformSystemProxyBackend::apply(const SystemProxyConfig &) { return check({}).result; }
PlatformOperationResult PlatformSystemProxyBackend::clear() { return check({}).result; }
