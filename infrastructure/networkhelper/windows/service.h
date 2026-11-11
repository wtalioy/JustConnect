#pragma once
#include <memory>
#include <string>
class WindowsHelperInstallation;
std::unique_ptr<WindowsHelperInstallation> installWindowsRecoveryService();
std::wstring installedWindowsRecoveryImage();
int runWindowsRecoveryService();
