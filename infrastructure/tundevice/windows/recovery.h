#pragma once
#include <windows.h>

bool windowsAdapterPresent(const GUID &adapter);
// The caller must first confirm the owning helper is dead under its machine recovery lock.
void restoreWindowsAdapter(const GUID &adapter);
