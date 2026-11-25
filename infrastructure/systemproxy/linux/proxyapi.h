#pragma once
#include "application/platformoperationresult.h"
#include "infrastructure/process/command.h"
#include <QString>
#include <functional>
#include <optional>

// One GNOME gsettings read/write pair; values are GVariant textual representations,
// e.g. "'manual'", "8080" or "['localhost', '127.0.0.0/8']". A nullopt read means the
// schema, key or dconf session is unavailable.
struct LinuxProxyApi
{
    std::function<std::optional<QString>(const QString &schema, const QString &key)> read =
        [](const QString &schema, const QString &key) -> std::optional<QString> {
            const auto result = runPlatformCommand(QStringLiteral("gsettings"), {QStringLiteral("get"), schema, key});
            if (!result.result.succeeded()) return std::nullopt;
            return result.output;
        };
    std::function<PlatformOperationResult(const QString &schema, const QString &key, const QString &value)> write =
        [](const QString &schema, const QString &key, const QString &value) -> PlatformOperationResult {
            const auto result = runPlatformCommand(QStringLiteral("gsettings"),
                {QStringLiteral("set"), schema, key, value});
            if (!result.result.succeeded()) return result.result;
            return {PlatformOperationResult::Status::Success, {}, true};
        };
};
