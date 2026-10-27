#pragma once
#include <string>
#include <vector>

namespace WindowsDNS {
// NRPT uses DoH for servers in the native known-server table, independently of namespace matching.
std::vector<std::wstring> knownNrptDohServers();
}
