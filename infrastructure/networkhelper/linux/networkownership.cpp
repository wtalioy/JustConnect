#include "infrastructure/networkhelper/linux/networkownership.h"
#include "infrastructure/networkaddress/ipv4.h"

NetworkPolicySession::OriginalViewFilter linuxOriginalNetworkView(const LinuxHelperConfiguration &configuration,
    const LinuxHelperDevice &device, const QString &dnsMode)
{
    if (!canonicalUnicastIpv4(configuration.address) || !canonicalUnicastIpv4(configuration.peer)
        || device.name.isEmpty() || device.name.size() > 15 || device.index <= 0) return {};
    // Automatic routing supports exactly one DNS mechanism: per-link settings
    // on the owned TUN link of an active systemd-resolved. There is no plain
    // resolv.conf fallback to describe.
    if (!dnsMode.isEmpty() && dnsMode != QLatin1String("resolved")) return {};
    QStringList installedDomains;
    for (const auto &domain : configuration.dnsDomains) installedDomains.append(QChar('~') + domain);
    installedDomains.sort();
    return [device, dnsMode, peer = configuration.peer, installedDomains](const QJsonObject &network, const QJsonObject &dns, QString *reason)
        -> std::optional<NetworkPolicySession::OriginalView> {
        const auto fail = [reason](const QString &detail) {
            if (reason) *reason = detail;
            return std::nullopt;
        };
        if (!network["interfaces"].isArray() || !network["routes"].isArray())
            return fail(QStringLiteral("the network snapshot lacks interfaces or routes arrays"));
        // Subtract the owned nonpersistent TUN device as a whole: nothing else
        // can hold addresses on it, and the kernel keeps interface names
        // unique, so a matching name and index pair identifies this session's
        // device. Its administrative up flag may flap while a desktop network
        // manager adopts and releases the foreign device; packet I/O rides the
        // borrowed descriptor, so a momentary down state does not change the
        // original network this view must describe. A destroyed device (its
        // row gone) still fails closed, because the capture cannot survive it.
        QJsonArray interfaces;
        bool found = false;
        for (const auto &value : network["interfaces"].toArray()) {
            const auto row = value.toObject();
            if (row["name"].toString() == device.name && row["index"].toInt() == device.index) {
                if (found)
                    return fail(QStringLiteral("the owned tunnel device %1 is duplicated in the network snapshot").arg(device.name));
                found = true;
                continue;
            }
            interfaces.append(value);
        }
        if (!found)
            return fail(QStringLiteral("the owned tunnel device %1 is missing from the network snapshot").arg(device.name));
        // Subtract every route row that points at the owned interface.
        QJsonArray routes;
        for (const auto &value : network["routes"].toArray()) {
            if (value.toObject()["interface_index"].toInt() == device.index) continue;
            routes.append(value);
        }
        auto original = network;
        original["interfaces"] = interfaces;
        original["routes"] = routes;
        auto originalDns = dns;
        if (dnsMode == QLatin1String("resolved")) {
            // Verify the owned DNS scopes before projecting the original network.
            const auto resolved = dns["resolved"].toObject();
            if (!resolved["links"].isArray())
                return fail(QStringLiteral("the per-link resolver snapshot lost its link list"));
            QJsonArray links;
            bool owned = false;
            for (const auto &value : resolved["links"].toArray()) {
                const auto row = value.toObject();
                if (row["interface"].toString() == device.name && row["index"].toInt() == device.index) {
                    if (owned)
                        return fail(QStringLiteral("the owned tunnel device %1 is duplicated in the resolver snapshot").arg(device.name));
                    QStringList domains;
                    for (const auto &entry : row["domains"].toArray()) domains.append(entry.toString());
                    domains.sort();
                    if (row["default_route"].toBool() || row["servers"].toArray() != QJsonArray{peer}
                        || domains != installedDomains)
                        return fail(QStringLiteral("the owned per-link resolver settings changed"));
                    owned = true;
                    continue;
                }
                links.append(value);
            }
            if (!owned)
                return fail(QStringLiteral("the owned per-link resolver is missing from the resolved snapshot"));
            auto updated = resolved;
            updated["links"] = links;
            originalDns["resolved"] = updated;
        }
        // An empty mode means this session owns no DNS at all.
        return NetworkPolicySession::OriginalView{original, originalDns};
    };
}
