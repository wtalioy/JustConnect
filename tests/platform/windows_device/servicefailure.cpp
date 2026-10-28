#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/networkhelper/windows/service.h"
#include "windowsnetworkcontract.h"
#include <iostream>
#include <string>

namespace {
void WINAPI ignoreControl(DWORD) {}
void WINAPI failedStartup(DWORD,wchar_t **)
{
    const auto handle=RegisterServiceCtrlHandlerW(WindowsNetworkContract::Service,ignoreControl);
    SERVICE_STATUS status{};
    status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState=SERVICE_STOPPED;
    status.dwWin32ExitCode=ERROR_GEN_FAILURE;
    if(handle)SetServiceStatus(handle,&status);
}
}
int wmain(int argc,wchar_t **argv) try
{
    if(argc!=2)throw std::runtime_error("service startup fixture requires one request");
    if(std::wstring(argv[1])==L"--service"){
        SERVICE_TABLE_ENTRYW table[]{{const_cast<wchar_t *>(WindowsNetworkContract::Service),failedStartup},{nullptr,nullptr}};
        return StartServiceCtrlDispatcherW(table)?0:1;
    }
    if(std::wstring(argv[1])!=L"--install")throw std::runtime_error("unknown startup fixture request");
    auto installation=WindowsHelperInstallation::prepare();
    ensureWindowsRecoveryService(*installation);
    throw std::runtime_error("broken service startup was accepted");
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
