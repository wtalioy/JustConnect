#pragma once
#include <cstdint>
#include <array>
#include <guiddef.h>

struct WindowsNetworkFingerprint {
    std::array<unsigned char,32> dns{},interfaces{};
};

struct WindowsControlFixtureInput {
    std::uintptr_t server=0;
    GUID dead{},live{},foreign{};
    WindowsNetworkFingerprint baseline;
    bool hasBaseline=false;
};

struct WindowsExitChangeFixtureInput {
    std::uint32_t interfaceIndex=0,address=0;
};
