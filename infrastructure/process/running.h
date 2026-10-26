#pragma once
#include <QString>
#include <optional>

// Native image basename without the Windows .exe suffix; nullopt means the scan was incomplete.
std::optional<bool> isProcessRunning(const QString &name);
