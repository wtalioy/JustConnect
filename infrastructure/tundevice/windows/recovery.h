#pragma once
#include <windows.h>

bool windowsAdapterPresent(const GUID &adapter);
// The caller holds the machine recovery lock and confirms the owner died or released its own device.
void restoreWindowsAdapter(const GUID &adapter);
