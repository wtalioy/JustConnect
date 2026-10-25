#include "ordinarytoken.h"
#include <sddl.h>
#include <string>
#include <system_error>
#include <vector>
namespace {
[[noreturn]] void fail(const char *stage,DWORD error = GetLastError()) {
    throw std::system_error(static_cast<int>(error),std::system_category(),stage);
}
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value) CloseHandle(value); }
};
}

HANDLE ordinaryWindowsToken()
{
    Handle original, token;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_DEFAULT,&original.value)) fail("open fixture token");
    alignas(SID) unsigned char admin[SECURITY_MAX_SID_SIZE], medium[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(admin);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admin,&size)) fail("administrator SID");
    SID_AND_ATTRIBUTES denied{admin,0};
    if (!CreateRestrictedToken(original.value,DISABLE_MAX_PRIVILEGE|LUA_TOKEN,1,&denied,0,nullptr,0,nullptr,&token.value)) fail("restrict fixture token");
    size = sizeof(medium);
    if (!CreateWellKnownSid(WinMediumLabelSid,nullptr,medium,&size)) fail("medium SID");
    TOKEN_MANDATORY_LABEL label{{medium,SE_GROUP_INTEGRITY}};
    if (!SetTokenInformation(token.value,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(medium))) fail("set medium integrity");
    GetTokenInformation(token.value,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> data(size);
    if (!GetTokenInformation(token.value,TokenUser,data.data(),size,&size)) fail("read ordinary user SID");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid,&sid)) fail("format ordinary SID");
    const std::wstring sddl = std::wstring(L"D:P(A;;GA;;;SY)(A;;GA;;;")+sid+L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) fail("ordinary default DACL");
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    const bool read = GetSecurityDescriptorDacl(descriptor,&present,&acl,&defaulted) != FALSE;
    TOKEN_DEFAULT_DACL defaults{acl};
    const bool applied = read && present && SetTokenInformation(token.value,TokenDefaultDacl,&defaults,sizeof(defaults));
    const auto error = GetLastError();
    LocalFree(descriptor);
    if (!applied) fail("set ordinary process object DACL",error);
    HANDLE result = token.value;
    token.value = nullptr;
    return result;
}

