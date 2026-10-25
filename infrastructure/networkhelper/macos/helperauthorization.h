#pragma once
#include "infrastructure/networkhelper/macos/networkhelper.h"
#include <Security/Authorization.h>
#include <xpc/xpc.h>

OSStatus acquireMacNetworkAuthorization(AuthorizationRef *authorization);
bool authorizedMacNetworkMessage(xpc_object_t message);
