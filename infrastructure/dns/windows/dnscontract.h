#pragma once
#include <cstddef>

namespace WindowsDNS {
// MS-GPNRPT local and managed policy stores; neither is owned by the reader.
inline constexpr wchar_t LocalPolicy[]=L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";
inline constexpr wchar_t ManagedPolicy[]=L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig";
inline constexpr std::size_t SnapshotBytes=262144;
inline constexpr unsigned SnapshotTimeoutMs=10000;
inline constexpr unsigned ConsistencyPollMs=50;
}
