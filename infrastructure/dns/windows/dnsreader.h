#pragma once
#include <string>
#include <vector>

namespace WindowsDNS {
// Include built-in DoH and configured DoH/DoT entries before treating an NRPT upstream as plain DNS.
std::vector<std::wstring> knownNrptEncryptedServers();
}
