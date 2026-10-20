#pragma once
#include <memory>
#include "application/credentialstore.h"

std::unique_ptr<CredentialStore> createSystemCredentialStore();
