#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/process/windows/identity.h"
#include "windowsnetworkcontract.h"
#include "ordinarytoken.h"
#include <aclapi.h>
#include <sddl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <system_error>

namespace {
void check(bool value,const char *message) { if(!value) throw std::runtime_error(message); }
struct Handle { HANDLE value=nullptr;~Handle() { if(value && value!=INVALID_HANDLE_VALUE) CloseHandle(value); } };
std::filesystem::path self()
{
    wchar_t path[32768]{};
    const auto size=GetModuleFileNameW(nullptr,path,32768);
    check(size && size<32768,"locate installer test image");
    return path;
}
void ordinary()
{
    const auto directory=self().parent_path();
    auto installed=WindowsHelperInstallation::openInstalled();
    check(installed->image()==self().wstring(),"protected installation could not reopen without installer authority");
    for (const auto &name:{WindowsNetworkContract::Executable,WindowsNetworkContract::DriverLibrary,WindowsNetworkContract::DriverLicense}) {
        const DWORD denied[]{FILE_WRITE_DATA,DELETE,WRITE_DAC,WRITE_OWNER};
        for (const auto access:denied) {
            const auto handle=CreateFileW((directory/name).c_str(),access,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
            const auto error=GetLastError();
            if(handle!=INVALID_HANDLE_VALUE) CloseHandle(handle);
            check(handle==INVALID_HANDLE_VALUE && error==ERROR_ACCESS_DENIED,"ordinary account modified a protected payload");
        }
    }
    check(!CreateDirectoryW((directory/L"unclaimed-child").c_str(),nullptr) && GetLastError()==ERROR_ACCESS_DENIED,"ordinary account created an installation payload");
    bool refused=false;
    try { WindowsHelperInstallation::prepare(); } catch(const std::system_error &error) { refused=error.code().value()==ERROR_ACCESS_DENIED; }
    check(refused,"ordinary process entered privileged preparation");
}
void launchOrdinary(const std::wstring &image)
{
    Handle token,process,thread;
    token.value=ordinaryWindowsToken();
    std::wstring command=L"\""+image+L"\" --ordinary";
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags=STARTF_USESTDHANDLES;
    startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);startup.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);startup.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION info{};
    check(CreateProcessAsUserW(token.value,nullptr,command.data(),nullptr,nullptr,TRUE,0,nullptr,nullptr,&startup,&info),"run installed image with ordinary token");
    process.value=info.hProcess;thread.value=info.hThread;
    const bool complete=WaitForSingleObject(process.value,10000)==WAIT_OBJECT_0;
    if(!complete) { TerminateProcess(process.value,1);WaitForSingleObject(process.value,5000); }
    DWORD code=1;
    check(complete && GetExitCodeProcess(process.value,&code) && code==0,"ordinary installed-image boundary failed");
}
void userOwnedEqualityTrap(const std::wstring &path)
{
    std::ifstream input(self(),std::ios::binary);
    const std::vector<char> data((std::istreambuf_iterator<char>(input)),{});
    check(!data.empty() && data.size()==std::filesystem::file_size(self()),"read source bytes for ownership trap");
    check(DeleteFileW(path.c_str()),"remove own installed equality fixture");
    WindowsProcess process(GetCurrentProcessId());
    const auto sid=process.identity().sid;
    PSECURITY_DESCRIPTOR security=nullptr;
    const auto sddl=L"O:"+sid+L"G:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;"+sid+L")";
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&security,nullptr),"create user-owned equality fixture security");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),security,FALSE};
    Handle file;
    file.value=CreateFileW(path.c_str(),GENERIC_WRITE|READ_CONTROL,FILE_SHARE_READ,&attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    LocalFree(security);
    check(file.value!=INVALID_HANDLE_VALUE,"create explicit user-owned equality fixture");
    DWORD written=0;
    check(WriteFile(file.value,data.data(),static_cast<DWORD>(data.size()),&written,nullptr) && written==data.size() && FlushFileBuffers(file.value),"copy exact source bytes to equality fixture");
    PSID owner=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    check(GetSecurityInfo(file.value,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,&owner,nullptr,nullptr,nullptr,&descriptor)==ERROR_SUCCESS,"read equality fixture owner");
    LPWSTR actual=nullptr;
    const bool same=ConvertSidToStringSidW(owner,&actual) && sid==actual;
    if(actual) LocalFree(actual);LocalFree(descriptor);
    check(same,"ownership trap did not start with the actual user owner");
    CloseHandle(file.value);file.value=nullptr;
    bool refused=false;
    try { WindowsHelperInstallation::prepare(); } catch(const std::system_error &error) { refused=error.code().value()==ERROR_ACCESS_DENIED; }
    check(refused,"installer adopted equal bytes owned by an ordinary user");
    std::ifstream remaining(path,std::ios::binary);
    const std::vector<char> found((std::istreambuf_iterator<char>(remaining)),{});
    check(found==data,"refused installation changed the external payload");
}
}

int wmain(int argc,wchar_t **argv) try
{
    wchar_t guarded[8]{};
    check(GetEnvironmentVariableW(L"GITHUB_ACTIONS",guarded,8)==4 && std::wstring(guarded)==L"true","installation checks require disposable runner");
    if(argc==2 && std::wstring(argv[1])==L"--ordinary") { ordinary();return 0; }
    if(argc==2 && std::wstring(argv[1])==L"--unconfigured") {
        check(!WindowsNetworkContract::DriverSHA256[0] || !WindowsNetworkContract::LicenseSHA256[0],"unconfigured check requires missing payload hashes");
        bool refused=false;
        try { WindowsHelperInstallation::prepare(); } catch(const std::system_error &error) { refused=error.code().value()==ERROR_NOT_SUPPORTED; }
        check(refused,"unconfigured build entered machine installation");
        std::cout<<"PASS: unconfigured native installer refused before machine changes\n";return 0;
    }
    check(argc==1,"unexpected installer fixture request");
    auto installation=WindowsHelperInstallation::prepare();
    const auto image=installation->image();
    const auto directory=std::filesystem::path(image).parent_path();
    struct Cleanup {
        WindowsHelperInstallation &installation;const std::filesystem::path &directory;
        ~Cleanup() { installation.close();for(const auto name:{WindowsNetworkContract::Executable,WindowsNetworkContract::DriverLibrary,WindowsNetworkContract::DriverLicense}) DeleteFileW((directory/name).c_str());RemoveDirectoryW(directory.c_str()); }
    } cleanup{*installation,directory};
    auto second=WindowsHelperInstallation::prepare();
    check(second->image()==image && second->driver()==installation->driver(),"identical source changed protected installation identity");
    second->close();
    launchOrdinary(image);
    installation->close();
    userOwnedEqualityTrap(image);
    std::cout<<"PASS: native installation, running-image identity, idempotent reuse, ordinary-user denial and equal-byte owner refusal\n";
    return 0;
} catch(const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
