#include "infrastructure/credentialstore/macos/credentialstore.h"
#include <QScopeGuard>

namespace {
CredentialResult result(OSStatus code) {
    CredentialStatus status=CredentialStatus::Failed;
    switch(code) {
    case errSecSuccess: status=CredentialStatus::Success;break;
    case errSecItemNotFound: status=CredentialStatus::NotFound;break;
    case errSecInteractionNotAllowed: status=CredentialStatus::Locked;break;
    case errSecAuthFailed: case errSecMissingEntitlement: status=CredentialStatus::PermissionDenied;break;
    case errSecUserCanceled: status=CredentialStatus::Cancelled;break;
    case errSecNotAvailable: case errSecNoDefaultKeychain: case errSecNoSuchKeychain: case errSecInvalidKeychain: status=CredentialStatus::Unavailable;break;
    }
    return {status,{},code};
}
class Store final : public CredentialStore {
    SecKeychainRef keychain;
    CredentialResult unlocked() const {
        SecKeychainRef selected=keychain;
        if (selected) CFRetain(selected);
        else {
            const auto code=SecKeychainCopyDefault(&selected);
            if (code!=errSecSuccess) return result(code);
        }
        const auto release=qScopeGuard([&]{CFRelease(selected);});
        SecKeychainStatus flags=0;
        const auto code=SecKeychainGetStatus(selected,&flags);
        if (code!=errSecSuccess) return result(code);
        return {flags&kSecUnlockStateStatus ? CredentialStatus::Success : CredentialStatus::Locked,{}};
    }
    CFMutableDictionaryRef query(const QString &key,bool adding=false) const {
        auto dict=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(dict,kSecClass,kSecClassGenericPassword);
        CFDictionarySetValue(dict,kSecAttrService,MacCredentialService);
        auto account=CFStringCreateWithCharacters(nullptr,reinterpret_cast<const UniChar *>(key.utf16()),key.size());
        CFDictionarySetValue(dict,kSecAttrAccount,account);CFRelease(account);
        CFDictionarySetValue(dict,kSecUseAuthenticationUI,kSecUseAuthenticationUIFail);
        if (keychain) {
            if (adding) CFDictionarySetValue(dict,kSecUseKeychain,keychain);
            else {
                const void *items[]{keychain};
                auto list=CFArrayCreate(nullptr,items,1,&kCFTypeArrayCallBacks);
                CFDictionarySetValue(dict,kSecMatchSearchList,list);CFRelease(list);
            }
        }
        return dict;
    }
public:
    explicit Store(SecKeychainRef keychain):keychain(keychain) {if(keychain)CFRetain(keychain);}
    ~Store() override {if(keychain)CFRelease(keychain);}
    CredentialResult read(const QString &key) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        const auto availability=unlocked(); if (!availability.succeeded()) return availability;
        auto dict=query(key);const auto release=qScopeGuard([&]{CFRelease(dict);});
        CFDictionarySetValue(dict,kSecReturnData,kCFBooleanTrue);CFDictionarySetValue(dict,kSecMatchLimit,kSecMatchLimitOne);
        CFTypeRef data=nullptr;const auto code=SecItemCopyMatching(dict,&data);
        if (code!=errSecSuccess) return result(code);
        const auto releaseData=qScopeGuard([&]{if(data)CFRelease(data);});
        if (!data || CFGetTypeID(data)!=CFDataGetTypeID()) return {CredentialStatus::Failed,{}};
        auto bytes=static_cast<CFDataRef>(data);const auto length=CFDataGetLength(bytes);
        if(length>MaxBytes)return {CredentialStatus::Limit,{}};
        return {CredentialStatus::Success,QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(bytes)),length)};
    }
    CredentialResult write(const QString &key,const QByteArray &value) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        if (value.size()>MaxBytes) return {CredentialStatus::Limit,{}};
        const auto availability=unlocked(); if (!availability.succeeded()) return availability;
        auto data=CFDataCreate(nullptr,reinterpret_cast<const UInt8 *>(value.constData()),value.size());
        const auto releaseData=qScopeGuard([&]{CFRelease(data);});
        auto dict=query(key,true);const auto release=qScopeGuard([&]{CFRelease(dict);});
        CFDictionarySetValue(dict,kSecValueData,data);
        auto code=SecItemAdd(dict,nullptr);
        if (code==errSecDuplicateItem) {
            auto match=query(key);const auto releaseMatch=qScopeGuard([&]{CFRelease(match);});
            const void *keys[]{kSecValueData};const void *values[]{data};
            auto changes=CFDictionaryCreate(nullptr,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
            code=SecItemUpdate(match,changes);CFRelease(changes);
        }
        return result(code);
    }
    CredentialResult remove(const QString &key) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        const auto availability=unlocked(); if (!availability.succeeded()) return availability;
        auto dict=query(key);const auto release=qScopeGuard([&]{CFRelease(dict);});
        return result(SecItemDelete(dict));
    }
};
}
std::unique_ptr<CredentialStore> createMacCredentialStore(SecKeychainRef keychain) {return std::make_unique<Store>(keychain);}
std::unique_ptr<CredentialStore> createSystemCredentialStore() {return createMacCredentialStore(nullptr);}
