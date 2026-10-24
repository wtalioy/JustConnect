#include "helperidentity.h"
#include <QScopeGuard>
#include <CommonCrypto/CommonDigest.h>

namespace {
bool hardened(CFDictionaryRef information)
{
    auto value = CFDictionaryGetValue(information,kSecCodeInfoFlags);
    quint32 flags = 0;
    // CS_RUNTIME is part of the public SecCodeSignatureFlags contract.
    if (!value || CFGetTypeID(value) != CFNumberGetTypeID() || !CFNumberGetValue(CFNumberRef(value),kCFNumberSInt32Type,&flags)
        || !(flags & kSecCodeSignatureRuntime)) return false;
    auto raw = CFDictionaryGetValue(information,kSecCodeInfoEntitlementsDict);
    if (!raw) return true;
    if (CFGetTypeID(raw) != CFDictionaryGetTypeID()) return false;
    const auto entitlements = CFDictionaryRef(raw);
    for (auto key : {CFSTR("com.apple.security.get-task-allow"),CFSTR("com.apple.security.cs.disable-library-validation")})
        if (auto entry = CFDictionaryGetValue(entitlements,key); entry && entry != kCFBooleanFalse) return false;
    return true;
}
CFDataRef leaf(CFDictionaryRef information)
{
    auto value = CFDictionaryGetValue(information,kSecCodeInfoCertificates);
    if (!value || CFGetTypeID(value) != CFArrayGetTypeID() || CFArrayGetCount(CFArrayRef(value)) < 1) return nullptr;
    auto certificate = CFArrayGetValueAtIndex(CFArrayRef(value),0);
    if (CFGetTypeID(certificate) != SecCertificateGetTypeID()) return nullptr;
    return SecCertificateCopyData(SecCertificateRef(certificate));
}
}

MacHelperIdentity::MacHelperIdentity(const char *ownIdentifier, const char *peerIdentifier)
{
    SecCodeRef self = nullptr;
    if (SecCodeCopySelf(kSecCSDefaultFlags,&self) != errSecSuccess) return;
    const auto release = qScopeGuard([&] { CFRelease(self); });
    CFDictionaryRef information = nullptr;
    if (SecCodeCheckValidity(self,kSecCSStrictValidate,nullptr) != errSecSuccess
        || SecCodeCopySigningInformation(self,kSecCSSigningInformation,&information) != errSecSuccess) return;
    const auto releaseInformation = qScopeGuard([&] { CFRelease(information); });
    const auto own = CFStringCreateWithCString(nullptr,ownIdentifier,kCFStringEncodingUTF8);
    const auto identifier = CFDictionaryGetValue(information,kSecCodeInfoIdentifier);
    const bool matches = own && identifier && CFGetTypeID(identifier) == CFStringGetTypeID() && CFEqual(own,identifier);
    if (own) CFRelease(own);
    if (!matches || !hardened(information)) return;
    certificate = leaf(information);
    if (!certificate) return;
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    // The platform requirement language defines certificate hashes as SHA-1; DER is also compared below.
    CC_SHA1(CFDataGetBytePtr(certificate),CC_LONG(CFDataGetLength(certificate)),digest);
    expression = "identifier \""+QByteArray(peerIdentifier)+"\" and certificate leaf = H\""
        +QByteArray(reinterpret_cast<const char *>(digest),sizeof(digest)).toHex()+"\"";
    const auto text = CFStringCreateWithCString(nullptr,expression.constData(),kCFStringEncodingUTF8);
    if (text) { SecRequirementCreateWithString(text,kSecCSDefaultFlags,&requirement); CFRelease(text); }
}
MacHelperIdentity::~MacHelperIdentity()
{
    if (requirement) CFRelease(requirement);
    if (certificate) CFRelease(certificate);
}
bool MacHelperIdentity::constrain(xpc_connection_t connection) const
{
    return ready() && xpc_connection_set_peer_code_signing_requirement(connection,expression.constData()) == 0;
}
bool MacHelperIdentity::accepts(xpc_object_t message) const
{
    if (!ready() || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return false;
    SecCodeRef guest = nullptr;
    if (SecCodeCreateWithXPCMessage(message,kSecCSDefaultFlags,&guest) != errSecSuccess) return false;
    const auto release = qScopeGuard([&] { CFRelease(guest); });
    CFDictionaryRef information = nullptr;
    if (SecCodeCheckValidity(guest,kSecCSStrictValidate,requirement) != errSecSuccess
        || SecCodeCopySigningInformation(guest,kSecCSSigningInformation,&information) != errSecSuccess) return false;
    const auto releaseInformation = qScopeGuard([&] { CFRelease(information); });
    auto actual = leaf(information);
    const bool same = actual && CFEqual(actual,certificate) && hardened(information);
    if (actual) CFRelease(actual);
    return same;
}
