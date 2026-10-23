#pragma once
#include "infrastructure/platform/systemcredentialstore.h"
#include <Security/Security.h>

inline CFStringRef const MacCredentialService=CFSTR("com.github.wtalioy.JustConnect.credentials.v1");

// An explicit keychain lets the native integration test avoid the user's keychain.
std::unique_ptr<CredentialStore> createMacCredentialStore(SecKeychainRef keychain);
