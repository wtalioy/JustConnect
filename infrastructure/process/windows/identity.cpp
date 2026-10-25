#include "infrastructure/process/windows/identity.h"
#include <sddl.h>
#include <system_error>
#include <vector>

namespace {
[[noreturn]] void fail(const char *stage,DWORD error = GetLastError())
{
    throw std::system_error(static_cast<int>(error),std::system_category(),stage);
}
std::wstring userSid(HANDLE process)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(process,TOKEN_QUERY,&token)) fail("read process owner");
    struct Cleanup { HANDLE value; ~Cleanup() { CloseHandle(value); } } cleanup{token};
    DWORD size = 0;
    GetTokenInformation(token,TokenUser,nullptr,0,&size);
    if (GetLastError()!=ERROR_INSUFFICIENT_BUFFER) fail("size process owner");
    std::vector<unsigned char> data(size);
    if (!GetTokenInformation(token,TokenUser,data.data(),size,&size)) fail("read process owner SID");
    LPWSTR value = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid,&value)) fail("format process owner");
    struct Free { LPWSTR value; ~Free() { LocalFree(value); } } free{value};
    return value;
}
bool canonicalSid(const std::wstring &value)
{
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(value.c_str(),&sid)) return false;
    LPWSTR formatted = nullptr;
    const bool valid = ConvertSidToStringSidW(sid,&formatted) && value==formatted;
    if (formatted) LocalFree(formatted);
    LocalFree(sid);
    return valid;
}
}

WindowsProcess::WindowsProcess(DWORD pid)
{
    if (!pid) fail("invalid process identity",ERROR_INVALID_PARAMETER);
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);
    if (!process) fail("retain process identity");
    try {
        FILETIME created{},exited{},kernel{},user{};
        if (!GetProcessTimes(process,&created,&exited,&kernel,&user)) fail("read process creation time");
        owner = {pid,(std::uint64_t(created.dwHighDateTime)<<32)|created.dwLowDateTime,userSid(process)};
    } catch (...) {
        CloseHandle(process);
        process = nullptr;
        throw;
    }
}
WindowsProcess::~WindowsProcess() { if (process) CloseHandle(process); }

bool WindowsProcessIdentity::alive() const
{
    if (!pid || !created || !canonicalSid(sid)) fail("invalid saved process identity",ERROR_INVALID_DATA);
    try {
        WindowsProcess actual(pid);
        const auto &value = actual.identity();
        if (value.created!=created || value.sid!=sid) return false;
        const auto state = WaitForSingleObject(actual.handle(),0);
        if (state==WAIT_TIMEOUT) return true;
        if (state==WAIT_OBJECT_0) return false;
        fail("wait for process identity");
    } catch (const std::system_error &error) {
        if (error.code().value()==ERROR_INVALID_PARAMETER || error.code().value()==ERROR_NOT_FOUND) return false;
        throw;
    }
}
