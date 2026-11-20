#pragma once
#include <QString>

// Pre-flight usability report for automatic (TUN) routing on this host, shown
// by the UI before a connection starts so the user is never told "unknown
// error" after entering a polkit password.
struct LinuxHelperAvailability {
    bool available = false;
    QString helperDetail;   // why the helper binary or pkexec is unusable
    QString routingDetail;  // why DNS mechanism is unusable, when relevant
    QString remedy;         // concrete steps that make automatic routing usable
};

LinuxHelperAvailability linuxNetworkHelperAvailability();

// The helper executable pkexec may run: only the root-owned copy at the
// annotated system path qualifies. pkexec refuses programs it does not own and
// executes exactly the annotated path, so anything else — including a copy
// shipped inside an extracted archive — is empty.
QString linuxNetworkHelperExecutable();
