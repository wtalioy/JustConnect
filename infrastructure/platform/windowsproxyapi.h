#pragma once
#include <windows.h>
#include <wininet.h>
#include <ras.h>

struct WindowsProxyApi
{
    decltype(&InternetQueryOptionW) query = &InternetQueryOptionW;
    decltype(&InternetSetOptionW) set = &InternetSetOptionW;
    decltype(&RasEnumEntriesW) entries = &RasEnumEntriesW;
};
