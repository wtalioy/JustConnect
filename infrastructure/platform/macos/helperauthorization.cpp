#include "helperauthorization.h"
#include <QScopeGuard>
#include <cstring>

OSStatus acquireMacNetworkAuthorization(AuthorizationRef *authorization)
{
    *authorization = nullptr;
    auto status = AuthorizationCreate(nullptr,nullptr,kAuthorizationFlagDefaults,authorization);
    if (status != errAuthorizationSuccess) return status;
    AuthorizationItem right{MacHelperAuthorizationRight,0,nullptr,0};
    AuthorizationRights rights{1,&right};
    status = AuthorizationCopyRights(*authorization,&rights,kAuthorizationEmptyEnvironment,
        kAuthorizationFlagExtendRights|kAuthorizationFlagInteractionAllowed|kAuthorizationFlagPreAuthorize,nullptr);
    if (status != errAuthorizationSuccess) { AuthorizationFree(*authorization,kAuthorizationFlagDestroyRights); *authorization = nullptr; }
    return status;
}
bool authorizedMacNetworkMessage(xpc_object_t message)
{
    const auto value = xpc_dictionary_get_value(message,"authorization");
    if (!value || xpc_get_type(value) != XPC_TYPE_DATA || xpc_data_get_length(value) != sizeof(AuthorizationExternalForm)) return false;
    AuthorizationExternalForm external{};
    std::memcpy(&external,xpc_data_get_bytes_ptr(value),sizeof(external));
    AuthorizationRef authorization = nullptr;
    if (AuthorizationCreateFromExternalForm(&external,&authorization) != errAuthorizationSuccess) return false;
    const auto release = qScopeGuard([&] { AuthorizationFree(authorization,kAuthorizationFlagDefaults); });
    AuthorizationItem right{MacHelperAuthorizationRight,0,nullptr,0}; AuthorizationRights rights{1,&right};
    // Only validate an already granted right; the daemon never prompts or extends rights.
    return AuthorizationCopyRights(authorization,&rights,kAuthorizationEmptyEnvironment,kAuthorizationFlagDefaults,nullptr) == errAuthorizationSuccess;
}
