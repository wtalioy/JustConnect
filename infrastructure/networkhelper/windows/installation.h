#pragma once

#include <windows.h>
#include <memory>
#include <string>
#include <vector>

class WindowsHelperInstallation final {
public:
    static std::unique_ptr<WindowsHelperInstallation> prepare();
    ~WindowsHelperInstallation();
    WindowsHelperInstallation(const WindowsHelperInstallation &) = delete;
    WindowsHelperInstallation &operator=(const WindowsHelperInstallation &) = delete;
    const std::wstring &image() const { return executable; }
    const std::wstring &driver() const { return library; }
    void close();
private:
    WindowsHelperInstallation() = default;
    void pinDirectory(const std::wstring &path,bool create,bool allowNewChildren);
    std::wstring executable,library;
    std::vector<HANDLE> directories;
};
