#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <optional>

// Each target retains references into the unchanged native network snapshot.
std::optional<QJsonArray> originalNetworkProtection(const QJsonObject &network);
