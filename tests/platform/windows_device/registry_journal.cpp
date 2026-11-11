#include "infrastructure/networkjournal/windows/registry.h"
#include "infrastructure/process/windows/identity.h"
#include "windowsnetworkcontract.h"
#include "ordinarytoken.h"
#include <sddl.h>
#include <objbase.h>
#include <winrt/base.h>
#include <algorithm>
#include <iostream>
#include <memory>
#include <system_error>

namespace {
void check(bool value,const char *message) { if (!value) throw std::runtime_error(message); }
struct Handle { HANDLE value=nullptr; ~Handle() { if (value) CloseHandle(value); } };
bool elevated()
{
    Handle token;
    check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value),"open test token");
    TOKEN_ELEVATION value{};DWORD size=0;
    check(GetTokenInformation(token.value,TokenElevation,&value,sizeof(value),&size),"query test elevation");
    return value.TokenIsElevated;
}
void ordinaryChild()
{
    check(!elevated(),"journal refusal requires an ordinary process");
    bool refused=false;
    try { WindowsRegistryJournal journal; } catch (const std::system_error &error) { refused=error.code().value()==ERROR_ACCESS_DENIED; }
    check(refused,"ordinary account accessed the machine recovery journal");
}
void launchOrdinary()
{
    wchar_t executable[32768]{};
    const auto size=GetModuleFileNameW(nullptr,executable,32768);
    check(size && size<32768,"locate journal test image");
    std::wstring command=L"\""+std::wstring(executable)+L"\" --ordinary";
    Handle token,process,thread;
    token.value=ordinaryWindowsToken();
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags=STARTF_USESTDHANDLES;
    startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION info{};
    check(CreateProcessAsUserW(token.value,nullptr,command.data(),nullptr,nullptr,TRUE,0,nullptr,nullptr,&startup,&info),"start ordinary journal client");
    process.value=info.hProcess;thread.value=info.hThread;
    const auto completed=WaitForSingleObject(process.value,10000)==WAIT_OBJECT_0;
    if (!completed) { TerminateProcess(process.value,1);WaitForSingleObject(process.value,5000); }
    DWORD code=1;
    check(completed && GetExitCodeProcess(process.value,&code) && code==0,"ordinary journal boundary failed");
}
void securityCases()
{
    WindowsProcess own(GetCurrentProcessId());
    const std::pair<std::wstring,bool> cases[]{
        {L"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)",true},
        {L"O:SYG:SYD:P(A;;KA;;;BA)(A;;KA;;;SY)",true},
        {L"O:BAG:SYD:(A;;KA;;;SY)(A;;KA;;;BA)",false},
        {L"O:"+own.identity().sid+L"G:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)",false},
        {L"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;WD)",false},
        {L"O:BAG:SYD:P(A;;KR;;;SY)(A;;KA;;;BA)",false},
        {L"O:BAG:SYD:P(A;IO;KA;;;SY)(A;;KA;;;BA)",false},
        {L"O:BAG:SYD:P(A;;KA;;;BA)(A;;KA;;;BA)",false},
    };
    for (const auto &item:cases) {
        PSECURITY_DESCRIPTOR descriptor=nullptr;
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(item.first.c_str(),SDDL_REVISION_1,&descriptor,nullptr),"parse journal security fixture");
        bool accepted=true;
        try { WindowsRegistryJournal::validateSecurity(descriptor); } catch (const std::system_error &error) { check(error.code().value()==ERROR_ACCESS_DENIED,"unexpected security refusal");accepted=false; }
        LocalFree(descriptor);
        check(accepted==item.second,"journal adopted an untrusted owner or ACL");
    }
}
}

int wmain(int argc,wchar_t **argv) try
{
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    wchar_t guarded[8]{};
    check(GetEnvironmentVariableW(L"GITHUB_ACTIONS",guarded,8)==4 && std::wstring(guarded)==L"true","machine mutation requires disposable runner");
    if (argc==2 && std::wstring(argv[1])==L"--ordinary") { ordinaryChild();return 0; }
    check(argc==1 && elevated(),"native journal requires the elevated runner");
    securityCases();
    GUID owner{};
    check(SUCCEEDED(CoCreateGuid(&owner)),"new journal owner");
    struct Cleanup { GUID owner; ~Cleanup() { try { WindowsRegistryJournal journal;journal.remove(owner); } catch (...) {} } } cleanup{owner};
    auto journal=std::make_unique<WindowsRegistryJournal>();
    const std::string data=R"({"phase":"allocated"})";
    journal->write(owner,data);
    check(journal->read(owner)==data,"atomic checkpoint changed");
    const auto owners=journal->owners();
    check(std::find(owners.begin(),owners.end(),owner)!=owners.end(),"recovery lost its owned checkpoint");
    for (const auto &bad: {std::string(),std::string("{broken"),std::string("{}{}"),std::string("{}junk"),
        std::string("{}\0junk",7),std::string(WindowsNetworkContract::MaxRecordBytes+1,' ')}) {
        bool refused=false;
        try { journal->write(owner,bad); } catch (const std::system_error &error) { refused=error.code().value()==ERROR_INVALID_PARAMETER; }
        check(refused && journal->read(owner)==data,"invalid write damaged the durable checkpoint");
    }
    journal->close();journal->close();
    journal=std::make_unique<WindowsRegistryJournal>();
    check(journal->read(owner)==data,"new owner could not reopen durable recovery state");
    launchOrdinary();
    journal->remove(owner);journal->remove(owner);
    bool missing=false;
    try { journal->read(owner); } catch (const std::system_error &error) { missing=error.code().value()==ERROR_FILE_NOT_FOUND; }
    check(missing,"removed checkpoint remains visible");
    std::cout << "PASS: protected machine journal, invalid-write preservation, durable reopen, ordinary-user denial and owned removal\n";
    return 0;
} catch (const winrt::hresult_error &error) {
    std::cerr << winrt::to_string(error.message()) << '\n';return 1;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';return 1;
}
