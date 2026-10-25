#pragma once

#include <windows.h>
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

using WindowsControlElevation = std::function<HANDLE(const std::wstring &,const std::wstring &)>;

class WindowsHelperInstallation final {
public:
    static bool identityReady() noexcept;
    static std::unique_ptr<WindowsHelperInstallation> prepare();
    static std::unique_ptr<WindowsHelperInstallation> openInstalled();
    // Run in an ordinary launcher process; its lifetime isolates the GUI from the synchronous UAC API.
    static int authorizeControl(DWORD caller,std::uint64_t created,const GUID &session,const WindowsControlElevation &elevate={});
    ~WindowsHelperInstallation();
    WindowsHelperInstallation(const WindowsHelperInstallation &) = delete;
    WindowsHelperInstallation &operator=(const WindowsHelperInstallation &) = delete;
    const std::wstring &image() const { return executable; }
    const std::wstring &driver() const { return library; }
    void close();
private:
    WindowsHelperInstallation() = default;
    void pinDirectory(const std::wstring &path,bool create,bool allowNewChildren);
    void pinInstallation(const std::wstring &hash,bool create);
    std::wstring executable,library;
    std::vector<HANDLE> directories;
};
