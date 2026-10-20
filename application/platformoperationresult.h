#pragma once
#include <QString>

struct PlatformOperationResult
{
    enum class Status { Success, Failed, Cancelled, PermissionDenied, Unsupported, TimedOut };
    Status status = Status::Success;
    QString detail;
    bool mayHaveChanged = false;
    bool succeeded() const { return status == Status::Success; }
};
