#pragma once

#include <windows.h>
#include <mutex>
#include <string>
#include <vector>

// Callers initialize the Windows Runtime on their control thread before using JSON records.
class WindowsRegistryJournal final {
public:
    WindowsRegistryJournal();
    ~WindowsRegistryJournal();
    WindowsRegistryJournal(const WindowsRegistryJournal &) = delete;
    WindowsRegistryJournal &operator=(const WindowsRegistryJournal &) = delete;
    std::string read(const GUID &owner);
    void write(const GUID &owner,const std::string &data);
    void remove(const GUID &owner);
    std::vector<GUID> owners();
    void close();
    static void validateSecurity(PSECURITY_DESCRIPTOR descriptor);
private:
    void protectedKey() const;
    HKEY key = nullptr;
    std::mutex lock;
};
