#pragma once
#include <SystemConfiguration/SystemConfiguration.h>
#include <Security/Authorization.h>
#include <functional>

SCPreferencesRef createMacProxyPreferences(AuthorizationRef *authorization);
struct MacProxyApi
{
    std::function<SCPreferencesRef(AuthorizationRef *)> open = createMacProxyPreferences;
    decltype(&SCPreferencesPathSetValue) set = &SCPreferencesPathSetValue;
    decltype(&SCPreferencesPathRemoveValue) remove = &SCPreferencesPathRemoveValue;
    decltype(&SCPreferencesCommitChanges) commit = &SCPreferencesCommitChanges;
    decltype(&SCPreferencesApplyChanges) apply = &SCPreferencesApplyChanges;
};
