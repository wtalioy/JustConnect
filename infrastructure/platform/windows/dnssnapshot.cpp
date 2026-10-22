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
Import-Module ($PSHOME+'\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
function Read-DnsRows([string]$class,[string[]]$fields) {
    # Select after reading so absent optional properties retain null on older providers.
    foreach($row in $session.QueryInstances('ROOT\StandardCimv2','WQL',('SELECT * FROM '+$class))) {
        try { $row | Select-Object -Property $fields } finally { $row.Dispose() }
    }
}
# NullString preserves a true local session; PowerShell binds $null as an empty string.
$session=[cimsession]::Create([NullString]::Value)
try {
    $parameters=[Microsoft.Management.Infrastructure.CimMethodParametersCollection]::new()
    $parameters.Add([Microsoft.Management.Infrastructure.CimMethodParameter]::Create('Effective',$true,[Microsoft.Management.Infrastructure.CimType]::Boolean,[Microsoft.Management.Infrastructure.CimFlags]::In))
    $result=$session.InvokeMethod('ROOT\Microsoft\Windows\DNS','PS_DnsClientNrptPolicy','Get',$parameters)
    try {
        if($result.ReturnValue.Value -ne 0) { throw 'Cannot read effective NRPT' }
        $policies=@(foreach($row in $result.OutParameters['CmdletOutput'].Value) {
            try { $row | Select-Object -Property @('Namespace','NameServers','DirectAccessEnabled','DirectAccessDnsServers','DirectAccessIPsecCARestriction','DirectAccessProxyName','DirectAccessProxyType','DirectAccessQueryIPsecEncryption','DirectAccessQueryIPsecRequired','DnsSecIPsecCARestriction','DnsSecQueryIPsecEncryption','DnsSecQueryIPsecRequired','DnsSecValidationRequired','NameEncoding','QueryPolicy','SecureNameQueryFallback') }
            finally { $row.Dispose() }
        })
    } finally { $result.Dispose() }
    foreach($row in $policies) {
        $row.Namespace=@($row.Namespace | Where-Object {$null -ne $_} | ForEach-Object {[string]$_})
        $row.NameServers=@($row.NameServers | Where-Object {$null -ne $_} | ForEach-Object {([Net.IPAddress]$_).ToString()})
        $row.DirectAccessDnsServers=@($row.DirectAccessDnsServers | Where-Object {$null -ne $_} | ForEach-Object {([Net.IPAddress]$_).ToString()})
    }
    try {
        $dohClass=$session.GetClass('ROOT\StandardCimv2','MSFT_DNSClientDohServerAddress')
        $dohClass.Dispose()
        $dohSupported=$true
    } catch [Microsoft.Management.Infrastructure.CimException] {
        if($_.Exception.NativeErrorCode -notin @([Microsoft.Management.Infrastructure.NativeErrorCode]::InvalidClass,[Microsoft.Management.Infrastructure.NativeErrorCode]::NotFound)) { throw }
        $dohSupported=$false
    }
    $doh=@()
    if($dohSupported) { $doh=@(Read-DnsRows 'MSFT_DNSClientDohServerAddress' @('ServerAddress','DohTemplate','AllowFallbackToUdp','AutoUpgrade')) }
    $interfaces=@(Read-DnsRows 'MSFT_DNSClientServerAddress' @('InterfaceIndex','AddressFamily','ServerAddresses'))
    foreach($row in $interfaces) { $row.ServerAddresses=@($row.ServerAddresses | Where-Object {$null -ne $_} | ForEach-Object {[string]$_}) }
    $clients=@(Read-DnsRows 'MSFT_DNSClient' @('InterfaceIndex','ConnectionSpecificSuffix','ConnectionSpecificSuffixSearchList','RegisterThisConnectionsAddress','UseSuffixWhenRegistering'))
    foreach($row in $clients) {
        $row.ConnectionSpecificSuffix=[string]$row.ConnectionSpecificSuffix
        $row.ConnectionSpecificSuffixSearchList=@($row.ConnectionSpecificSuffixSearchList | Where-Object {$null -ne $_} | ForEach-Object {[string]$_})
    }
    $settings=@(Read-DnsRows 'MSFT_DNSClientGlobalSetting' @('SuffixSearchList','UseDevolution','DevolutionLevel','AppendParentSuffixes','AppendPrimarySuffixes'))
    if($settings.Count -ne 1) { throw 'Invalid global DNS settings' }
    $global=$settings[0]
    $global.SuffixSearchList=@($global.SuffixSearchList | Where-Object {$null -ne $_} | ForEach-Object {[string]$_})
    $data=[ordered]@{interfaces=$interfaces;clients=$clients;global=$global;nrpt=$policies;doh_supported=$dohSupported;doh=$doh}
    ConvertTo-Json -InputObject $data -Depth 6 -Compress
} finally { $session.Dispose() }
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
