#include "infrastructure/networkhelper/windows/publisher.h"
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <system_error>

namespace {
[[noreturn]] void fail(const char *stage,LONG error = GetLastError())
{
    throw std::system_error(static_cast<int>(error),std::system_category(),stage);
}
}

void verifyWindowsPublisher(const std::wstring &path,HANDLE pinnedFile,const WindowsSha256 &expected)
{
    if (expected==WindowsSha256{}) fail("unconfigured helper publisher",ERROR_NOT_SUPPORTED);
    if (!pinnedFile || pinnedFile==INVALID_HANDLE_VALUE) fail("invalid signed file handle",ERROR_INVALID_HANDLE);
    WINTRUST_FILE_INFO file{};
    file.cbStruct=sizeof(file);
    file.pcwszFilePath=path.c_str();
    file.hFile=pinnedFile;
    WINTRUST_DATA data{};
    data.cbStruct=sizeof(data);
    data.dwUIChoice=WTD_UI_NONE;
    data.fdwRevocationChecks=WTD_REVOKE_WHOLECHAIN;
    data.dwUnionChoice=WTD_CHOICE_FILE;
    data.pFile=&file;
    data.dwStateAction=WTD_STATEACTION_VERIFY;
    data.dwProvFlags=WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT|WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    struct Close {
        WINTRUST_DATA &data; GUID &action;
        ~Close() { data.dwStateAction=WTD_STATEACTION_CLOSE; WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),&action,&data); }
    } close{data,action};
    const auto status=WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),&action,&data);
    if (status!=ERROR_SUCCESS) fail("verify helper signature",status);
    const auto provider=WTHelperProvDataFromStateData(data.hWVTStateData);
    const auto signer=provider?WTHelperGetProvSignerFromChain(provider,0,FALSE,0):nullptr;
    const auto certificate=signer?WTHelperGetProvCertFromChain(signer,0):nullptr;
    if (!certificate || certificate->cbStruct<sizeof(CRYPT_PROVIDER_CERT) || !certificate->pCert
        || !certificate->pCert->pbCertEncoded || !certificate->pCert->cbCertEncoded || certificate->pCert->cbCertEncoded>65536)
        fail("read native signing certificate",ERROR_INVALID_DATA);
    WindowsSha256 actual{};
    DWORD size=static_cast<DWORD>(actual.size());
    if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM,0,nullptr,certificate->pCert->pbCertEncoded,
        certificate->pCert->cbCertEncoded,actual.data(),&size)) fail("hash signing certificate");
    if (size!=actual.size()) fail("invalid signing certificate hash",ERROR_INVALID_DATA);
    if (actual!=expected) fail("unexpected signing publisher",ERROR_ACCESS_DENIED);
}
