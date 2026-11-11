#pragma once

#include <QDebug>
#include <windows.h>

namespace WindowsConsoleTermination {
// Process-owned: a callback may still be running after the Qt owner is destroyed.
inline HANDLE notification = nullptr;
inline HANDLE finished = nullptr;

inline void notify() { if (notification) SetEvent(notification); }

inline BOOL WINAPI request(DWORD event)
{
    switch (event) {
    case CTRL_C_EVENT: case CTRL_BREAK_EVENT: case CTRL_CLOSE_EVENT: case CTRL_LOGOFF_EVENT: case CTRL_SHUTDOWN_EVENT:
        notify();
        if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && finished)
            WaitForSingleObject(finished, 14000);
        return TRUE;
    default: return FALSE;
    }
}

inline HANDLE install()
{
    if (!notification) notification = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!finished) finished = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!notification || !finished || !SetConsoleCtrlHandler(request, TRUE))
        qWarning() << "Could not register console termination handler";
    return notification;
}

inline void finish()
{
    if (finished) SetEvent(finished);
    SetConsoleCtrlHandler(request, FALSE);
}
}
