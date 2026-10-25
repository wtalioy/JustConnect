#pragma once

#include <QByteArray>
#include <Security/Security.h>
#include <xpc/xpc.h>

class MacHelperIdentity
{
public:
    MacHelperIdentity(const char *ownIdentifier, const char *peerIdentifier);
    ~MacHelperIdentity();
    MacHelperIdentity(const MacHelperIdentity &) = delete;
    MacHelperIdentity &operator=(const MacHelperIdentity &) = delete;
    bool ready() const { return certificate && requirement; }
    bool constrain(xpc_connection_t connection) const;
    bool accepts(xpc_object_t message) const;
private:
    CFDataRef certificate = nullptr;
    SecRequirementRef requirement = nullptr;
    QByteArray expression;
};
