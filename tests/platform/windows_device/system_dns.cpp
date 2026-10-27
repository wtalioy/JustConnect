#include "infrastructure/dns/windows/nrpt.h"
#include "ordinarytoken.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <iostream>
#include <system_error>

namespace {
void check(bool value,const char *stage) { if (!value) throw std::runtime_error(stage); }
struct Handle { HANDLE value=nullptr;~Handle(){if(value)CloseHandle(value);} };
struct Addresses { ADDRINFOW *value=nullptr;~Addresses(){if(value)FreeAddrInfoW(value);} };
void query(const wchar_t *name,const wchar_t *expected)
{
    ADDRINFOW hints{};hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    Addresses addresses;
    const auto status=GetAddrInfoW(name,nullptr,&hints,&addresses.value);
    if(status)throw std::system_error(status,std::system_category(),"ordinary GetAddrInfoW");
    bool found=false;
    for(auto item=addresses.value;item;item=item->ai_next){
        const auto address=ntohl(reinterpret_cast<sockaddr_in *>(item->ai_addr)->sin_addr.s_addr);
        IN_ADDR target{};
        check(!expected || InetPtonW(AF_INET,expected,&target)==1,"invalid expected fixture answer");
        check(expected?address==ntohl(target.s_addr):(address>>24)==127,"system resolver returned an unexpected address");
        found=true;
    }
    check(found,"system resolver returned no IPv4 address");
}
void ordinaryQuery(const wchar_t *name,const wchar_t *expected)
{
    wchar_t executable[32768]{};
    const auto size=GetModuleFileNameW(nullptr,executable,32768);
    check(size && size<32768,"locate system DNS fixture");
    auto command=L"\""+std::wstring(executable)+L"\" --query "+name+L" "+expected;
    Handle token,process,thread;token.value=ordinaryWindowsToken();
    STARTUPINFOW startup{sizeof(startup)};PROCESS_INFORMATION info{};
    check(CreateProcessAsUserW(token.value,nullptr,command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&info),"start ordinary system resolver");
    process.value=info.hProcess;thread.value=info.hThread;
    const auto state=WaitForSingleObject(process.value,15000);
    if(state!=WAIT_OBJECT_0){TerminateProcess(process.value,1);WaitForSingleObject(process.value,5000);throw std::runtime_error("ordinary system DNS deadline");}
    DWORD code=1;
    check(GetExitCodeProcess(process.value,&code) && code==0,"ordinary system DNS query failed");
}
}

int wmain(int argc,wchar_t **argv) try
{
    WSADATA sockets{};check(WSAStartup(MAKEWORD(2,2),&sockets)==0,"start fixture sockets");
    struct CleanupSockets {~CleanupSockets(){WSACleanup();}} socketsCleanup;
    if(argc==4 && std::wstring(argv[1])==L"--query"){
        Handle token;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value),"inspect resolver token");
        TOKEN_ELEVATION elevation{};DWORD size=0;
        check(GetTokenInformation(token.value,TokenElevation,&elevation,sizeof(elevation),&size) && !elevation.TokenIsElevated,"system query must run unelevated");
        query(argv[2],argv[3]);query(L"localhost",nullptr);
        return 0;
    }
    wchar_t guarded[8]{};
    check(argc==3 && GetEnvironmentVariableW(L"GITHUB_ACTIONS",guarded,8)==4 && std::wstring(guarded)==L"true","system DNS mutation requires disposable runner");
    IN_ADDR server{};
    check(InetPtonW(AF_INET,argv[1],&server)==1,"invalid fixture DNS address");
    const auto rule=WindowsDnsRule::create({argv[2]},server);
    struct Restore {const WindowsDnsRule &rule;~Restore(){try{rule.restoreSystem();}catch(const std::exception &error){std::cerr<<"DNS cleanup: "<<error.what()<<'\n';}}} restore{rule};
    rule.applySystem();
    ordinaryQuery(argv[2],L"203.0.113.9");
    IN_ADDR listener{};check(InetPtonW(AF_INET,L"127.0.0.1",&listener)==1,"parse fixture listener");
    auto redirect=WindowsNrptRedirect::prepareSystem({L"."+std::wstring(argv[2])},{argv[1]},listener);
    struct RestoreRedirect {const WindowsNrptRedirect &value;~RestoreRedirect(){try{value.restoreSystem();}catch(const std::exception &error){std::cerr<<"redirect cleanup: "<<error.what()<<'\n';}}} redirectCleanup{redirect};
    redirect.applySystem();
    ordinaryQuery(argv[2],L"203.0.113.10");
    redirect.restoreSystem();
    ordinaryQuery(argv[2],L"203.0.113.9");
    rule.restoreSystem();
    std::cout<<"PASS: ordinary cached GetAddrInfoW follows original NRPT, redirected listener and restored endpoint; localhost preserved\n";
    return 0;
} catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
