#pragma once
#include "application/networkpolicysession.h"
#include "infrastructure/networkhelper/linux/networkhelperprotocol.h"

// This read-only projection grants no authority to restore native state.
// The filter subtracts the helper-owned TUN interface, its route rows and,
// in resolved DNS mode, the whole per-link resolver entry the helper installed
// on that link. The device row is subtracted by its name and index identity
// regardless of the administrative up flag: desktop network managers briefly
// flip foreign TUN devices while adopting them, and the packet queue rides
// the borrowed descriptor either way.
NetworkPolicySession::OriginalViewFilter linuxOriginalNetworkView(const LinuxHelperConfiguration &configuration,
    const LinuxHelperDevice &device, const QString &dnsMode);
