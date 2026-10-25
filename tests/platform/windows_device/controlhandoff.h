#pragma once
#include <cstdint>
#include <guiddef.h>

struct WindowsControlFixtureInput {
    std::uintptr_t server=0;
    GUID dead{},live{},foreign{};
};
