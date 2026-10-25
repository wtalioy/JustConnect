#include "infrastructure/networkhelper/windows/publisher.h"
#include <iostream>
#include <system_error>
#include <vector>

static std::wstring environment(const wchar_t *name)
{
    const auto length=GetEnvironmentVariableW(name,nullptr,0);
    if (!length) throw std::runtime_error("signed fixture metadata unavailable");
    std::vector<wchar_t> value(length);
    if (GetEnvironmentVariableW(name,value.data(),length)!=length-1) throw std::runtime_error("signed fixture metadata changed");
    return value.data();
}

int main() try
{
    const auto path=environment(L"JC_TEST_SIGNED_FIXTURE"), encoded=environment(L"JC_TEST_PUBLISHER_SHA256");
    if (encoded.size()!=64) throw std::runtime_error("invalid fixture publisher hash");
    WindowsSha256 hash{};
    const auto digit=[](wchar_t c) { if(c>=L'0' && c<=L'9') return c-L'0'; if(c>=L'a' && c<=L'f') return c-L'a'+10; throw std::runtime_error("invalid hash digit"); };
    for (size_t i=0;i<hash.size();++i) hash[i]=static_cast<unsigned char>((digit(encoded[i*2])<<4)|digit(encoded[i*2+1]));
    const auto handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if (handle==INVALID_HANDLE_VALUE) throw std::runtime_error("cannot pin signed fixture");
    struct Close { HANDLE value; ~Close() { CloseHandle(value); } } close{handle};
    verifyWindowsPublisher(path,handle,hash);
    hash[0]^=1;
    bool refused=false;
    try { verifyWindowsPublisher(path,handle,hash); } catch (const std::system_error &error) { refused=error.code().value()==ERROR_ACCESS_DENIED; }
    if (!refused) throw std::runtime_error("another signing publisher was accepted");
    refused=false;
    try { verifyWindowsPublisher(path,handle,{}); } catch (const std::system_error &error) { refused=error.code().value()==ERROR_NOT_SUPPORTED; }
    if (!refused) throw std::runtime_error("unconfigured signing authority was accepted");
    std::cout << "PASS: native Authenticode leaf hash, publisher mismatch and unconfigured authority refusal\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
