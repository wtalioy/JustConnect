#include "dnssnapshot.h"
#include <QJsonArray>
#include <QJsonDocument>
#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace {
const QString query = QString::fromLatin1(R"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
Import-Module (Join-Path $PSHOME 'Modules/DnsClient/DnsClient.psd1') -ErrorAction Stop
$policies=@(Get-DnsClientNrptPolicy -Effective | Select-Object Namespace,NameServers,DirectAccessEnabled,DirectAccessDnsServers,DirectAccessIPsecCARestriction,DirectAccessProxyName,DirectAccessProxyType,DirectAccessQueryIPsecEncryption,DirectAccessQueryIPsecRequired,DnsSecIPsecCARestriction,DnsSecQueryIPsecEncryption,DnsSecQueryIPsecRequired,DnsSecValidationRequired,NameEncoding,QueryPolicy,SecureNameQueryFallback)
foreach($row in $policies) {
    $row.Namespace=@($row.Namespace | Where-Object {$null -ne $_} | ForEach-Object {[string]$_})
    $row.NameServers=@($row.NameServers | Where-Object {$null -ne $_} | ForEach-Object {$_.ToString()})
    $row.DirectAccessDnsServers=@($row.DirectAccessDnsServers | Where-Object {$null -ne $_} | ForEach-Object {$_.ToString()})
}
$dohSupported=$null -ne (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
$doh=@()
if($dohSupported) { $doh=@(Get-DnsClientDohServerAddress | Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade) }
$interfaces=@(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
foreach($row in $interfaces) { $row.ServerAddresses=@($row.ServerAddresses | Where-Object {$null -ne $_} | ForEach-Object {[string]$_}) }
$clients=@(Get-DnsClient | Select-Object InterfaceIndex,ConnectionSpecificSuffix,ConnectionSpecificSuffixSearchList,RegisterThisConnectionsAddress,UseSuffixWhenRegistering)
foreach($row in $clients) {
    $row.ConnectionSpecificSuffix=[string]$row.ConnectionSpecificSuffix
    $row.ConnectionSpecificSuffixSearchList=@($row.ConnectionSpecificSuffixSearchList | Where-Object {$null -ne $_} | ForEach-Object {[string]$_})
}
$global=Get-DnsClientGlobalSetting | Select-Object SuffixSearchList,UseDevolution,DevolutionLevel,AppendParentSuffixes,AppendPrimarySuffixes
$global.SuffixSearchList=@($global.SuffixSearchList | Where-Object {$null -ne $_} | ForEach-Object {[string]$_})
$data=[ordered]@{
    interfaces=$interfaces
    clients=$clients
    global=$global
    nrpt=$policies
    doh_supported=$dohSupported
    doh=$doh
}
ConvertTo-Json -InputObject $data -Depth 6 -Compress
)PS");

bool strings(const QJsonValue &value)
{
    if (!value.isArray()) return false;
    for (const auto &item : value.toArray()) if (!item.isString()) return false;
    return true;
}

bool valid(const QJsonObject &data)
{
    for (const auto &key : {"interfaces", "clients", "nrpt", "doh"})
        if (!data[key].isArray()) return false;
    if (!data["global"].isObject() || !strings(data["global"].toObject()["SuffixSearchList"])
        || !data["doh_supported"].isBool()) return false;
    for (const auto &value : data["interfaces"].toArray()) {
        const auto row = value.toObject();
        const auto index = row["InterfaceIndex"].toInteger(-1);
        const auto family = row["AddressFamily"].toInteger(-1);
        if (!value.isObject() || index <= 0 || (family != 2 && family != 23)
            || !strings(row["ServerAddresses"])) return false;
    }
    for (const auto &value : data["clients"].toArray()) {
        const auto row = value.toObject();
        if (!value.isObject() || row["InterfaceIndex"].toInteger(-1) <= 0
            || !row["ConnectionSpecificSuffix"].isString() || !strings(row["ConnectionSpecificSuffixSearchList"])) return false;
    }
    for (const auto &value : data["nrpt"].toArray()) {
        const auto row = value.toObject();
        if (!value.isObject() || !strings(row["Namespace"]) || row["Namespace"].toArray().isEmpty()
            || !strings(row["NameServers"]) || !strings(row["DirectAccessDnsServers"])
            || !row["DirectAccessEnabled"].isBool() || !row["QueryPolicy"].isString()
            || !row["SecureNameQueryFallback"].isString()) return false;
    }
    for (const auto &value : data["doh"].toArray()) {
        const auto row = value.toObject();
        if (!value.isObject() || !row["ServerAddress"].isString() || !row["DohTemplate"].isString()
            || !row["AllowFallbackToUdp"].isBool() || !row["AutoUpgrade"].isBool()) return false;
    }
    return true;
}
}

DnsSnapshot readWindowsDnsSnapshot(const PlatformCommandRunner &runner)
{
    using Status = PlatformOperationResult::Status;
    QString program;
#ifdef Q_OS_WIN
    wchar_t directory[MAX_PATH]{};
    const auto length = GetSystemDirectoryW(directory, MAX_PATH);
    if (!length || length >= MAX_PATH) return {{Status::Failed, "Cannot locate system PowerShell"}, {}};
    program = QString::fromWCharArray(directory, int(length)) + "/WindowsPowerShell/v1.0/powershell.exe";
#else
    if (!runner) return {{Status::Unsupported, "Windows DNS snapshot unavailable on this platform"}, {}};
#endif
    const QStringList arguments{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query};
    const auto command = runner ? runner(program, arguments) : runPlatformCommand(program, arguments, 10000);
    if (!command.result.succeeded()) return {command.result, {}};
    const auto bytes = command.output.toUtf8();
    if (bytes.size() > 262144) return {{Status::Failed, "System resolver snapshot too large"}, {}};
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject() || !valid(document.object()))
        return {{Status::Failed, "Invalid system resolver snapshot"}, {}};
    return {{}, document.object()};
}
