#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/networkhelper/windows/service.h"
#include "infrastructure/networkhelper/windows/control.h"
#include "windowsnetworkcontract.h"
#include <objbase.h>
#include <charconv>
#include <iostream>
#include <system_error>

namespace {
std::uint64_t number(const wchar_t *text)
{
    std::string value;
    for(;*text;++text){if(*text<L'0' || *text>L'9')throw std::runtime_error("invalid control process identity");value+=static_cast<char>(*text);}
    std::uint64_t result=0;
    const auto parsed=std::from_chars(value.data(),value.data()+value.size(),result);
    if(parsed.ec!=std::errc{} || parsed.ptr!=value.data()+value.size() || !result || std::to_string(result)!=value)throw std::runtime_error("invalid control process identity");
    return result;
}
}
int wmain(int argc,wchar_t **argv) try
{
    if(argc==2 && std::wstring(argv[1])==L"--version"){
        using namespace WindowsNetworkContract;
        std::cout<<"{\"protocol\":"<<Protocol<<",\"storage_version\":"<<StorageVersion
            <<",\"revision\":\""<<JC_HELPER_REVISION<<"\",\"source_state\":\""<<JC_HELPER_SOURCE_STATE
            <<"\",\"identity_ready\":"<<(WindowsHelperInstallation::identityReady()?"true":"false")
            <<",\"publisher_sha256\":\""<<PublisherSHA256<<"\",\"driver_sha256\":\""<<DriverSHA256
            <<"\",\"license_sha256\":\""<<LicenseSHA256<<"\"}\n";
        return 0;
    }
    if(argc==2 && std::wstring(argv[1])==L"--service")return runWindowsRecoveryService();
    if(argc==5 && (std::wstring(argv[1])==L"--control" || std::wstring(argv[1])==L"--authorize")){
        const auto pid=number(argv[2]),created=number(argv[3]);
        GUID session{};wchar_t canonical[39]{};
        if(pid>MAXDWORD || FAILED(CLSIDFromString(argv[4],&session)) || session==GUID{} || !StringFromGUID2(session,canonical,39) || std::wstring(argv[4])!=canonical)throw std::runtime_error("invalid control session identity");
        return std::wstring(argv[1])==L"--authorize"?WindowsHelperInstallation::authorizeControl(static_cast<DWORD>(pid),created,session)
            :runWindowsNetworkControl(static_cast<DWORD>(pid),created,session);
    }
    if(argc!=2 || std::wstring(argv[1])!=L"--install")throw std::runtime_error("unknown native helper request");
    auto installation=WindowsHelperInstallation::prepare();
    ensureWindowsRecoveryService(*installation);
    std::wcout<<installation->image()<<L'\n';
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
