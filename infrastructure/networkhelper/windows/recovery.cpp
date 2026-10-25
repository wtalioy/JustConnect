#include "infrastructure/networkhelper/windows/recovery.h"
#include "windowsnetworkcontract.h"
#include "infrastructure/dns/domainlimits.h"
#include "infrastructure/tundevice/windows/recovery.h"
#include <ws2tcpip.h>
#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <algorithm>
#include <charconv>
#include <iterator>
#include <system_error>

using namespace winrt::Windows::Data::Json;
namespace {
[[noreturn]] void fail(const char *stage,LONG error=GetLastError()) { throw std::system_error(static_cast<int>(error),std::system_category(),stage); }
std::wstring text(const winrt::hstring &value) { return {value.data(),value.size()}; }
std::wstring guid(const GUID &value)
{
    wchar_t result[39]{};
    if (value==GUID{} || !StringFromGUID2(value,result,39)) fail("invalid network owner",ERROR_INVALID_DATA);
    return result;
}
GUID parseGuid(const winrt::hstring &value)
{
    GUID result{};
    if (FAILED(CLSIDFromString(value.c_str(),&result)) || result==GUID{} || guid(result)!=text(value)) fail("noncanonical network owner",ERROR_INVALID_DATA);
    return result;
}
void fields(const JsonObject &value,std::initializer_list<const wchar_t *> keys)
{
    if (value.Size()!=keys.size()) fail("unknown recovery record fields",ERROR_INVALID_DATA);
    for (const auto key:keys) if (!value.HasKey(key)) fail("missing recovery record field",ERROR_INVALID_DATA);
}
JsonObject process(const WindowsProcessIdentity &value)
{
    if (!value.valid()) fail("invalid recovery process",ERROR_INVALID_DATA);
    JsonObject result;
    result.SetNamedValue(L"pid",JsonValue::CreateNumberValue(value.pid));
    result.SetNamedValue(L"created",JsonValue::CreateStringValue(std::to_wstring(value.created)));
    result.SetNamedValue(L"sid",JsonValue::CreateStringValue(value.sid));
    return result;
}
WindowsProcessIdentity process(const JsonObject &value)
{
    fields(value,{L"pid",L"created",L"sid"});
    const auto pid=value.GetNamedNumber(L"pid");
    if (!(pid>=1 && pid<=MAXDWORD) || pid!=static_cast<DWORD>(pid)) fail("invalid saved process PID",ERROR_INVALID_DATA);
    const auto created=winrt::to_string(value.GetNamedString(L"created"));
    std::uint64_t ticks=0;
    const auto parsed=std::from_chars(created.data(),created.data()+created.size(),ticks);
    if (parsed.ec!=std::errc{} || parsed.ptr!=created.data()+created.size() || std::to_string(ticks)!=created) fail("invalid saved process creation time",ERROR_INVALID_DATA);
    WindowsProcessIdentity result{static_cast<DWORD>(pid),ticks,text(value.GetNamedString(L"sid"))};
    if (!result.valid()) fail("invalid saved process owner",ERROR_INVALID_DATA);
    return result;
}
JsonObject dns(const WindowsDnsRule &value)
{
    if (!value.valid()) fail("invalid saved DNS rule",ERROR_INVALID_DATA);
    JsonObject result;
    result.SetNamedValue(L"id",JsonValue::CreateStringValue(guid(value.id)));
    result.SetNamedValue(L"marker",JsonValue::CreateStringValue(guid(value.marker)));
    JsonArray names;
    for (const auto &name:value.domains) names.Append(JsonValue::CreateStringValue(name));
    result.SetNamedValue(L"domains",names);
    wchar_t server[INET_ADDRSTRLEN]{};
    if (!InetNtopW(AF_INET,&value.server,server,static_cast<DWORD>(std::size(server)))) fail("format saved DNS server");
    result.SetNamedValue(L"server",JsonValue::CreateStringValue(server));
    return result;
}
WindowsDnsRule dns(const JsonObject &value)
{
    fields(value,{L"id",L"marker",L"domains",L"server"});
    WindowsDnsRule result;
    result.id=parseGuid(value.GetNamedString(L"id"));result.marker=parseGuid(value.GetNamedString(L"marker"));
    const auto names=value.GetNamedArray(L"domains");
    if (!names.Size() || names.Size()>NetworkDnsDomainLimit) fail("invalid saved DNS namespace count",ERROR_INVALID_DATA);
    for (const auto &name:names) result.domains.push_back(text(name.GetString()));
    const auto server=value.GetNamedString(L"server");
    if (InetPtonW(AF_INET,server.c_str(),&result.server)!=1 || !result.valid()) fail("invalid saved DNS server or namespace",ERROR_INVALID_DATA);
    wchar_t canonical[INET_ADDRSTRLEN]{};
    if (!InetNtopW(AF_INET,&result.server,canonical,static_cast<DWORD>(std::size(canonical))) || text(server)!=canonical) fail("noncanonical saved DNS server",ERROR_INVALID_DATA);
    return result;
}
bool trusted(PSID sid) { return sid && (IsWellKnownSid(sid,WinBuiltinAdministratorsSid) || IsWellKnownSid(sid,WinLocalSystemSid)); }
void mutexSecurity(HANDLE mutex)
{
    PSID owner=nullptr;PACL acl=nullptr;PSECURITY_DESCRIPTOR security=nullptr;
    const auto status=GetSecurityInfo(mutex,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&security);
    if (status!=ERROR_SUCCESS) fail("read recovery lock security",status);
    struct Free { PSECURITY_DESCRIPTOR value;~Free(){LocalFree(value);} } free{security};
    SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;
    if (!trusted(owner) || !GetSecurityDescriptorControl(security,&control,&revision) || !(control&SE_DACL_PROTECTED) || !acl || !IsValidAcl(acl) || acl->AceCount!=2) fail("untrusted recovery lock",ERROR_ACCESS_DENIED);
    bool system=false,admin=false;
    for (DWORD i=0;i<acl->AceCount;++i) {
        void *value=nullptr;if (!GetAce(acl,i,&value)) fail("read recovery lock ACE");
        const auto ace=static_cast<ACCESS_ALLOWED_ACE *>(value);
        if (ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags || ace->Mask!=MUTEX_ALL_ACCESS) fail("untrusted recovery lock ACE",ERROR_ACCESS_DENIED);
        if (IsWellKnownSid(&ace->SidStart,WinLocalSystemSid) && !system) system=true;
        else if (IsWellKnownSid(&ace->SidStart,WinBuiltinAdministratorsSid) && !admin) admin=true;
        else fail("untrusted recovery lock trustee",ERROR_ACCESS_DENIED);
    }
}
bool same(const WindowsProcessIdentity &a,const WindowsProcessIdentity &b) { return a.pid==b.pid && a.created==b.created && a.sid==b.sid; }
}

std::string encodeWindowsNetworkRecord(const WindowsNetworkRecord &value)
{
    JsonObject result;
    result.SetNamedValue(L"version",JsonValue::CreateNumberValue(WindowsNetworkContract::StorageVersion));
    result.SetNamedValue(L"owner",JsonValue::CreateStringValue(guid(value.owner)));
    result.SetNamedValue(L"adapter",JsonValue::CreateStringValue(guid(value.adapter)));
    result.SetNamedValue(L"caller",process(value.caller));result.SetNamedValue(L"helper",process(value.helper));
    if (value.dns) result.SetNamedValue(L"dns",dns(*value.dns));
    else result.SetNamedValue(L"dns",JsonValue::CreateNullValue());
    const wchar_t *phase=nullptr;
    switch (value.phase) { case WindowsRecoveryPhase::Declared:phase=L"declared";break;case WindowsRecoveryPhase::Restoring:phase=L"restoring";break;case WindowsRecoveryPhase::Restored:phase=L"restored";break; }
    if (!phase) fail("invalid recovery phase",ERROR_INVALID_DATA);
    result.SetNamedValue(L"phase",JsonValue::CreateStringValue(phase));
    return winrt::to_string(result.Stringify());
}
WindowsNetworkRecord decodeWindowsNetworkRecord(const std::string &data) try
{
    if (data.empty() || data.size()>WindowsNetworkContract::MaxRecordBytes) fail("invalid recovery record size",ERROR_INVALID_DATA);
    const auto object=JsonObject::Parse(winrt::to_hstring(data));
    fields(object,{L"version",L"owner",L"adapter",L"caller",L"helper",L"dns",L"phase"});
    if (object.GetNamedNumber(L"version")!=WindowsNetworkContract::StorageVersion) fail("unknown recovery storage version",ERROR_NOT_SUPPORTED);
    WindowsNetworkRecord result;
    result.owner=parseGuid(object.GetNamedString(L"owner"));result.adapter=parseGuid(object.GetNamedString(L"adapter"));
    result.caller=process(object.GetNamedObject(L"caller"));result.helper=process(object.GetNamedObject(L"helper"));
    const auto rule=object.GetNamedValue(L"dns");
    if (rule.ValueType()!=JsonValueType::Null) result.dns=dns(rule.GetObject());
    const auto phase=object.GetNamedString(L"phase");
    if (phase==L"declared") result.phase=WindowsRecoveryPhase::Declared;
    else if (phase==L"restoring") result.phase=WindowsRecoveryPhase::Restoring;
    else if (phase==L"restored") result.phase=WindowsRecoveryPhase::Restored;
    else fail("unknown recovery phase",ERROR_INVALID_DATA);
    return result;
} catch (const winrt::hresult_error &) { fail("damaged native recovery record",ERROR_INVALID_DATA); }

WindowsNetworkLock::WindowsNetworkLock()
{
    PSECURITY_DESCRIPTOR security=nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",SDDL_REVISION_1,&security,nullptr)) fail("create recovery lock security");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),security,FALSE};
    mutex=CreateMutexExW(&attributes,WindowsNetworkContract::OwnershipMutex,0,MUTEX_ALL_ACCESS);
    const auto error=GetLastError();LocalFree(security);
    if (!mutex) fail("open machine recovery lock",error);
    try {
        mutexSecurity(mutex);
        constexpr DWORD LockTimeoutMs=30000;
        const auto state=WaitForSingleObject(mutex,LockTimeoutMs);
        if (state!=WAIT_OBJECT_0 && state!=WAIT_ABANDONED) fail("acquire machine recovery lock",state==WAIT_TIMEOUT?ERROR_TIMEOUT:GetLastError());
    } catch (...) {CloseHandle(mutex);mutex=nullptr;throw;}
}
WindowsNetworkLock::~WindowsNetworkLock() { if (mutex) {ReleaseMutex(mutex);CloseHandle(mutex);} }

void WindowsNetworkRecovery::declare(const WindowsNetworkRecord &record)
{
    WindowsNetworkLock lock;
    WindowsProcess current(GetCurrentProcessId());
    if (record.phase!=WindowsRecoveryPhase::Declared || !same(current.identity(),record.helper) || !record.caller.alive() || windowsAdapterPresent(record.adapter)) fail("invalid new network ownership",ERROR_INVALID_PARAMETER);
    for (const auto &owner:journal.owners()) {
        const auto previous=decodeWindowsNetworkRecord(journal.read(owner));
        if (previous.owner!=owner) fail("recovery key and record differ",ERROR_INVALID_DATA);
        if (owner==record.owner || previous.phase!=WindowsRecoveryPhase::Restored || previous.caller.sid==record.caller.sid) fail("previous network ownership requires recovery or acknowledgement",ERROR_ALREADY_EXISTS);
    }
    journal.write(record.owner,encodeWindowsNetworkRecord(record));
}
WindowsNetworkRecord WindowsNetworkRecovery::read(const GUID &owner)
{
    WindowsNetworkLock lock;
    auto result=decodeWindowsNetworkRecord(journal.read(owner));
    if (result.owner!=owner) fail("recovery key and record differ",ERROR_INVALID_DATA);
    return result;
}
std::vector<GUID> WindowsNetworkRecovery::owners() {WindowsNetworkLock lock;return journal.owners();}
bool WindowsNetworkRecovery::restoreAbandoned(const GUID &owner,const std::wstring &callerSid)
{
    WindowsNetworkLock lock;
    auto record=decodeWindowsNetworkRecord(journal.read(owner));
    if (record.owner!=owner) fail("recovery key and record differ",ERROR_INVALID_DATA);
    if (!callerSid.empty() && record.caller.sid!=callerSid) fail("network recovery belongs to another account",ERROR_ACCESS_DENIED);
    if (record.phase==WindowsRecoveryPhase::Restored) return true;
    if (record.helper.alive()) return false;
    if (record.phase!=WindowsRecoveryPhase::Restoring) {
        record.phase=WindowsRecoveryPhase::Restoring;journal.write(owner,encodeWindowsNetworkRecord(record));
    }
    if (record.dns) record.dns->restoreSystem();
    restoreWindowsAdapter(record.adapter);
    if (windowsAdapterPresent(record.adapter)) return false;
    record.phase=WindowsRecoveryPhase::Restored;journal.write(owner,encodeWindowsNetworkRecord(record));
    return true;
}
void WindowsNetworkRecovery::acknowledge(const GUID &owner,const std::wstring &callerSid)
{
    WindowsNetworkLock lock;
    const auto record=decodeWindowsNetworkRecord(journal.read(owner));
    if (record.owner!=owner || record.phase!=WindowsRecoveryPhase::Restored || record.caller.sid!=callerSid || windowsAdapterPresent(record.adapter)) fail("unconfirmed network recovery receipt",ERROR_ACCESS_DENIED);
    journal.remove(owner);
}
