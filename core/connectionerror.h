#pragma once

enum class ConnectionError
{
    NONE,
    INVALID_CONFIGURATION,
    CORE_UNAVAILABLE,
    AUTHENTICATION_CHANGED,
    CLIENT_FAILED,
    OTHER,
};
