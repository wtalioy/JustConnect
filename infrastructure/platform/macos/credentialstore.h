#pragma once
#include "infrastructure/platform/systemcredentialstore.h"
#include <Security/Security.h>

// An explicit keychain lets the native integration test avoid the user's keychain.
std::unique_ptr<CredentialStore> createMacCredentialStore(SecKeychainRef keychain);
