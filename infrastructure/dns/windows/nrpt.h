#pragma once
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace WindowsDNS { void refreshCache(); }

struct WindowsDnsRule {
    GUID id{},marker{};
    std::vector<std::wstring> domains;
    IN_ADDR server{};
    static WindowsDnsRule create(const std::vector<std::wstring> &domains,IN_ADDR server);
    bool valid() const;
    void apply(HKEY parent) const;
    void restore(HKEY parent) const;
    void applySystem() const;
    void restoreSystem() const;
};

// Changes only an existing provider's server group; namespace, policy and security remain provider-owned.
struct WindowsNrptRedirect {
    GUID id{},marker{};
    std::wstring policyClass,original;
    std::vector<std::wstring> namespaces;
    IN_ADDR server{};
    std::uint64_t globalPolicy=0;
    bool released=false;
    static WindowsNrptRedirect prepare(HKEY parent,const std::vector<std::wstring> &names,
        const std::vector<std::wstring> &servers,IN_ADDR listen);
    static WindowsNrptRedirect prepareSystem(const std::vector<std::wstring> &names,
        const std::vector<std::wstring> &servers,IN_ADDR listen);
    bool valid() const;
    std::vector<std::wstring> servers() const;
    void apply(HKEY parent) const;
    void restore(HKEY parent) const;
    void applySystem() const;
    void restoreSystem() const;
};
