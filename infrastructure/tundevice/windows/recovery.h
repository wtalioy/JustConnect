#pragma once
#include <windows.h>

bool windowsAdapterPresent(const GUID &adapter);
// The caller holds the machine recovery lock and confirms the owner died.
void restoreWindowsAdapter(const GUID &adapter);
// The live owner has called WintunCloseAdapter; wait for unplug before uninstalling its node.
void finishWindowsAdapterClose(const GUID &adapter);
