#pragma once
#include <QJsonObject>
#include <optional>

// Stable selected-interface and default exits; readers normalize volatile native flags.
std::optional<QJsonObject> originalExitSnapshot(const QJsonObject &network,const QString &preferred);
