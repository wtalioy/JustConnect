#pragma once

#include <QDebug>
#include <windows.h>

namespace WindowsConsoleTermination {
inline volatile LONG pending = 0;
// Process-owned: a callback may still be waiting after the Qt owner is destroyed.
inline HANDLE finished = nullptr;

inline BOOL WINAPI request(DWORD event)
{
    switch (event) {
    case CTRL_C_EVENT: case CTRL_BREAK_EVENT: case CTRL_CLOSE_EVENT: case CTRL_LOGOFF_EVENT: case CTRL_SHUTDOWN_EVENT:
        InterlockedExchange(&pending, 1);
        if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && finished)
            WaitForSingleObject(finished, 14000);
        return TRUE;
    default: return FALSE;
    }
}

inline void install()
{
    if (!finished) finished = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!finished || !SetConsoleCtrlHandler(request, TRUE))
        qWarning() << "Could not register console termination handler";
}

inline bool takePending() { return InterlockedExchange(&pending, 0) != 0; }

inline void finish()
{
    if (finished) SetEvent(finished);
    SetConsoleCtrlHandler(request, FALSE);
}
}
