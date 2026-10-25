#pragma once
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>

struct WindowsDnsRule {
    GUID id{},marker{};
    std::vector<std::wstring> domains;
    IN_ADDR server{};
    static WindowsDnsRule create(const std::vector<std::wstring> &domains,IN_ADDR server);
    bool valid() const;
    void apply(HKEY parent) const;
    void restore(HKEY parent) const;
};
