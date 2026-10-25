#pragma once

#include <windows.h>
#include <cstdint>
#include <string>

struct WindowsProcessIdentity {
    DWORD pid = 0;
    std::uint64_t created = 0;
    std::wstring sid;
    bool valid() const;
    bool alive() const;
};

// Retain the process object throughout authorization so PID reuse cannot change its owner.
class WindowsProcess final {
public:
    explicit WindowsProcess(DWORD pid,DWORD access=PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE);
    ~WindowsProcess();
    WindowsProcess(const WindowsProcess &) = delete;
    WindowsProcess &operator=(const WindowsProcess &) = delete;
    const WindowsProcessIdentity &identity() const { return owner; }
    HANDLE handle() const { return process; }
private:
    HANDLE process = nullptr;
    WindowsProcessIdentity owner;
};
