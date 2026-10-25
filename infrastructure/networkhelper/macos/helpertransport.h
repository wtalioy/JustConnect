#pragma once

#include "infrastructure/networkhelper/macos/networkhelper.h"
#include <xpc/xpc.h>
#include <Security/Authorization.h>

xpc_object_t macHelperMessage(const QJsonObject &packet, int descriptor = -1, const AuthorizationExternalForm *authorization = nullptr);
bool readMacHelperMessage(xpc_object_t message, QJsonObject &packet, int *descriptor = nullptr);
