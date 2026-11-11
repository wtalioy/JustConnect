#pragma once
#include "infrastructure/dns/domainlimits.h"
#include <QSet>
#include <QStringList>
#include <QStringView>

inline bool canonicalDnsDomain(const QString &name)
{
    if (name.isEmpty() || name.size() > 253) return false;
    for (const auto label : QStringView(name).tokenize(u'.')) {
        if (label.isEmpty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        for (const auto c : label) if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-') return false;
    }
    return true;
}
inline bool validTunDnsDomains(const QStringList &names)
{
    if (names.isEmpty() || names.size() > NetworkDnsDomainLimit) return false;
    QSet<QString> seen;
    for (const auto &name : names) {
        if (!canonicalDnsDomain(name) || seen.contains(name)) return false;
        seen.insert(name);
    }
    return true;
}
