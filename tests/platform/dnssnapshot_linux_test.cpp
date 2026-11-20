#include "infrastructure/dns/linux/dnssnapshot.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonObject>
#include <iostream>
#include <cstdlib>

static void check(bool ok, const char *message) { if (!ok) { std::cerr << message << '\n'; std::exit(1); } }

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    // Recorded verbatim from Debian 13 (systemd 257). Labels are right-aligned
    // inside their section, so the section's longest one ("Current DNS
    // Server:") is flush left while the "DNS Servers:"/"DNS Domain:" rows it
    // precedes are indented, and wrapped rows carry indented IPv6 addresses. A
    // parser that only accepts flush-left labels drops every per-link entry
    // and fails automatic routing with "the owned per-link resolver is missing
    // from the resolved snapshot".
    const auto status = QStringLiteral(
        "Global\n"
        "           Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\n"
        "    resolv.conf mode: stub\n"
        "  Current DNS Server: 223.5.5.5\n"
        "         DNS Servers: 223.5.5.5 119.29.29.29 223.6.6.6 114.114.114.114\n"
        "Fallback DNS Servers: 202.120.224.26 202.120.2.100\n"
        "\n"
        "Link 2 (enp3s0)\n"
        "    Current Scopes: DNS\n"
        "         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\n"
        "Current DNS Server: 180.168.255.18\n"
        "       DNS Servers: 116.228.111.118 180.168.255.18\n"
        "                    240e:58:c000:1600:180:168:255:118\n"
        "                    240e:58:c000:1000:116:228:111:18\n"
        "     Default Route: yes\n"
        "\n"
        "Link 42 (jctun0)\n"
        "    Current Scopes: DNS\n"
        "         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\n"
        "Current DNS Server: 10.8.0.1\n"
        "       DNS Servers: 10.8.0.1\n"
        "        DNS Domain: ~zb.fudan.edu.cn ~cloud.fudan.edu.cn ~fudan.edu.cn\n");

    const auto parsed = parseResolvedPerLinkStatus(status);
    check(parsed.has_value(), "resolvectl status fixture did not parse");
    const auto links = parsed->value("links").toArray();
    check(links.size() == 3, "the fixture's global and per-link entries were not all captured");
    const auto global = links.at(0).toObject();
    check(global["index"] == 0 && global["default_route"] == true
        && global["servers"].toArray().contains("223.5.5.5") && !global["servers"].toArray().contains("202.120.224.26"),
        "global and fallback servers were combined");
    const auto wan = links.at(1).toObject();
    check(wan["interface"] == "enp3s0" && wan["index"] == 2, "the first link identity was misread");
    const auto servers = wan["servers"].toArray();
    check(servers.contains("116.228.111.118") && servers.contains("180.168.255.18"),
        "an indented DNS Servers label lost its servers");
    check(servers.contains("240e:58:c000:1600:180:168:255:118"), "wrapped IPv6 continuation rows were dropped");
    check(wan["domains"].toArray().isEmpty(), "an absent DNS Domain label invented domains");
    const auto tun = links.at(2).toObject();
    check(tun["interface"] == "jctun0" && tun["index"] == 42, "the owned tunnel identity was misread");
    check(tun["servers"].toArray().contains("10.8.0.1"), "the owned tunnel's servers were dropped");
    const auto domains = tun["domains"].toArray();
    check(domains.contains("~fudan.edu.cn") && domains.contains("~zb.fudan.edu.cn")
        && domains.contains("~cloud.fudan.edu.cn"), "the owned tunnel's routing domains were dropped");
    std::cout << "dnssnapshot_linux_test passed" << std::endl;
    return 0;
}
