#pragma once
#include <cstddef>

namespace WindowsDNS {
// MS-GPNRPT local and managed policy stores; neither is owned by the reader.
inline constexpr wchar_t LocalPolicy[]=L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";
inline constexpr wchar_t ManagedPolicy[]=L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig";
inline constexpr std::size_t SnapshotBytes=262144;
inline constexpr unsigned SnapshotTimeoutMs=10000;
inline constexpr unsigned ConsistencyPollMs=50;
// DNS uses port 53 when IP Helper's server sockaddr leaves the port unspecified.
inline constexpr unsigned ServerPort=53;
// netioapi.h DNS_SERVER_PROPERTY_VERSION1 and DNS_SERVER_PROPERTY_TYPE; shared with the portable decoder.
inline constexpr unsigned PropertyVersion=1, DohProperty=1, DotProperty=2;
// WinError.h: absent settings or unsupported API version, never access/transport failures.
inline constexpr bool settingsUnavailable(unsigned long status)
{
    return status==2 || status==50 || status==87 || status==232 || status==1168 || status==1306;
}
}
