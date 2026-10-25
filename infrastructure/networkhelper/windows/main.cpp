#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/networkhelper/windows/service.h"
#include <iostream>
#include <system_error>

int wmain(int argc,wchar_t **argv) try
{
    if(argc==2 && std::wstring(argv[1])==L"--service")return runWindowsRecoveryService();
    if(argc!=2 || std::wstring(argv[1])!=L"--install")throw std::runtime_error("unknown native helper request");
    auto installation=WindowsHelperInstallation::prepare();
    ensureWindowsRecoveryService(*installation);
    std::wcout<<installation->image()<<L'\n';
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
