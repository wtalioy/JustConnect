#pragma once
#include <QJsonArray>
#include <QJsonObject>
#include <optional>

// At most three configured proxy listeners in each IP family.
inline constexpr int LinuxProxyListenerLimit = 6;
bool validLinuxListenerRequest(const QJsonObject &request);
bool validLinuxListenerProofs(const QJsonObject &request, const QJsonArray &proofs);
std::optional<QJsonArray> readLinuxListenerProofs(const QJsonObject &request);
