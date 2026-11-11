#include "infrastructure/tundevice/windows/adapter.h"
#include "infrastructure/tundevice/windows/recovery.h"
#include "idledevice.h"
#include <objbase.h>
#include <ws2tcpip.h>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <stdexcept>

namespace {
void check(bool value,const char *message){if(!value)throw std::runtime_error(message);}
IN_ADDR ip(const wchar_t *text){IN_ADDR result{};check(InetPtonW(AF_INET,text,&result)==1,"parse reuse fixture address");return result;}
void sourcePresent(NET_LUID luid,IN_ADDR source,bool expected)
{
    MIB_UNICASTIPADDRESS_ROW address{};address.InterfaceLuid=luid;
    address.Address.Ipv4.sin_family=AF_INET;address.Address.Ipv4.sin_addr=source;
    const auto status=GetUnicastIpAddressEntry(&address);
    check(expected?status==NO_ERROR:status==ERROR_NOT_FOUND,"reused source address differs");
}
void available(IN_ADDR address)
{
    MIB_UNICASTIPADDRESS_TABLE *addresses=nullptr;
    check(GetUnicastIpAddressTable(AF_INET,&addresses)==NO_ERROR,"read fixture address availability");
    bool used=false;for(ULONG i=0;i<addresses->NumEntries;++i)used|=addresses->Table[i].Address.Ipv4.sin_addr.S_un.S_addr==address.S_un.S_addr;FreeMibTable(addresses);
    MIB_IPFORWARD_TABLE2 *routes=nullptr;
    check(GetIpForwardTable2(AF_INET,&routes)==NO_ERROR,"read fixture route availability");
    for(ULONG i=0;i<routes->NumEntries;++i){const auto &prefix=routes->Table[i].DestinationPrefix;
        if(prefix.PrefixLength<=1)continue;const auto mask=0xffffffffu<<(32-prefix.PrefixLength);
        used|=(ntohl(address.S_un.S_addr)&mask)==ntohl(prefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
    }
    FreeMibTable(routes);check(!used,"documentation fixture address is already in use");
}
}

int wmain(int argc,wchar_t **argv)
{
    if(argc!=2 && argc!=3)return 2;
    if(argc==3 && !_wfreopen(argv[2],L"w",stdout))return 3;
    try{
        const auto first=ip(L"192.0.2.1"),peer=ip(L"192.0.2.2"),second=ip(L"198.51.100.1"),nextPeer=ip(L"198.51.100.2");
        for(const auto address:{first,peer,second,nextPeer})available(address);
        GUID owner{};check(SUCCEEDED(CoCreateGuid(&owner)),"allocate reuse test identity");
        bool allocated=false;
        std::unique_ptr<WindowsTunDevice> device;
        struct Cleanup {GUID &id;bool &allocated;std::unique_ptr<WindowsTunDevice> &device;~Cleanup(){device.reset();if(allocated)try{finishWindowsAdapterClose(id);}catch(...){}}} cleanup{owner,allocated,device};
        using Clock=std::chrono::steady_clock;
        auto before=Clock::now();
        std::cout<<"RUN: create\n"<<std::flush;
        ULONG automaticAddressDelay=0;
        device=WindowsTunDevice::create(argv[1],owner,first,peer,1400,{},[&](const auto &identity){
            allocated=true;
            MIB_IPINTERFACE_ROW initial{};initial.Family=AF_INET;initial.InterfaceLuid=identity.luid;
            check(GetIpInterfaceEntry(&initial)==NO_ERROR,"read initial native automatic-address delay");
            automaticAddressDelay=initial.LinkLocalAddressTimeout;
        });
        const auto createMs=std::chrono::duration<double,std::milli>(Clock::now()-before).count();
        const auto identity=device->identity();
        check(automaticAddressDelay<=10000,"native autoconfiguration delay exceeds the 30-second fixture budget");
        const auto autoconfigurationWindowMs=automaticAddressDelay+2000;
        bool refused=false;try{device->activate(second,nextPeer,1300,{});}catch(const std::system_error &e){refused=e.code().value()==ERROR_INVALID_STATE;}
        check(refused,"an active ring session was silently reused");
        Sleep(autoconfigurationWindowMs);
        std::cout<<"RUN: park\n"<<std::flush;
        device->interrupt();
        device->deactivate();WindowsDeviceCheck::idle(owner);check(windowsAdapterPresent(owner),"parking deleted the owned adapter");
        // Allow Windows' delayed address autoconfiguration to run while this interface stays empty.
        Sleep(autoconfigurationWindowMs);WindowsDeviceCheck::idle(owner);
        unsigned char buffer[20]{};refused=false;
        try{device->read(buffer,sizeof(buffer));}catch(const std::system_error &e){refused=e.code().value()==ERROR_OPERATION_ABORTED;}
        check(refused,"parked adapter retained a readable ring");
        MIB_UNICASTIPADDRESS_ROW external{};InitializeUnicastIpAddressEntry(&external);
        external.InterfaceLuid=identity.luid;external.Address.Ipv4.sin_family=AF_INET;external.Address.Ipv4.sin_addr=first;
        external.OnLinkPrefixLength=32;external.SkipAsSource=TRUE;external.DadState=IpDadStatePreferred;
        check(CreateUnicastIpAddressEntry(&external)==NO_ERROR,"inject an external address on the fixture-owned idle adapter");
        refused=false;try{device->activate(second,nextPeer,1300,{});}catch(const std::system_error &e){refused=e.code().value()==ERROR_INVALID_STATE;}
        check(refused && GetUnicastIpAddressEntry(&external)==NO_ERROR && external.SkipAsSource,"reconnect changed an externally configured idle adapter");
        check(DeleteUnicastIpAddressEntry(&external)==NO_ERROR,"remove only the fixture's external address");WindowsDeviceCheck::idle(owner);
        std::cout<<"RUN: resume\n"<<std::flush;
        before=Clock::now();device->activate(second,nextPeer,1300,{});
        const auto resumeMs=std::chrono::duration<double,std::milli>(Clock::now()-before).count();
        check(device->identity().guid==identity.guid && device->identity().luid.Value==identity.luid.Value && device->identity().index==identity.index,"reconnection created another adapter");
        sourcePresent(identity.luid,first,false);sourcePresent(identity.luid,second,true);
        MIB_IPINTERFACE_ROW settings{};settings.Family=AF_INET;settings.InterfaceLuid=identity.luid;
        check(GetIpInterfaceEntry(&settings)==NO_ERROR && settings.NlMtu==1300,"reused interface kept its previous MTU");
        device->deactivate();WindowsDeviceCheck::idle(owner);
        device->activate(first,peer,1400,{});sourcePresent(identity.luid,second,false);sourcePresent(identity.luid,first,true);
        device->close();finishWindowsAdapterClose(owner);check(!windowsAdapterPresent(owner),"close retained the reusable adapter");allocated=false;
        GUID reserved{};check(SUCCEEDED(CoCreateGuid(&reserved)),"allocate reserved configuration fixture");
        wchar_t text[39]{};check(StringFromGUID2(reserved,text,39)!=0,"format reserved configuration fixture");
        const auto path=std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\")+text;
        HKEY key=nullptr;DWORD disposition=0;
        check(RegCreateKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),0,nullptr,0,KEY_QUERY_VALUE|KEY_SET_VALUE|KEY_WOW64_64KEY,
            nullptr,&key,&disposition)==ERROR_SUCCESS && disposition==REG_CREATED_NEW_KEY,"reserve private fixture configuration");
        struct RemoveConfiguration {HKEY key;const std::wstring &path;~RemoveConfiguration(){RegCloseKey(key);RegDeleteKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),KEY_WOW64_64KEY,0);}} remove{key,path};
        const DWORD enabled=1;
        check(RegSetValueExW(key,L"IPAutoconfigurationEnabled",0,REG_DWORD,reinterpret_cast<const BYTE *>(&enabled),sizeof(enabled))==ERROR_SUCCESS,"write private configuration marker");
        bool touched=false;refused=false;
        try{auto conflicting=WindowsTunDevice::create(argv[1],reserved,first,peer,1400,{},[&](const auto &){touched=true;});}
        catch(const std::system_error &error){refused=error.code().value()==ERROR_ALREADY_EXISTS;}
        DWORD value=0,size=sizeof(value);
        check(refused && !touched && RegGetValueW(key,nullptr,L"IPAutoconfigurationEnabled",RRF_RT_REG_DWORD,nullptr,&value,&size)==ERROR_SUCCESS
            && value==enabled,"creation overwrote an existing IPv4 configuration");
        std::cout<<"PASS: empty parked adapter, fresh rings/address/MTU on reuse, stable identity and final removal; create "<<createMs<<" ms, resume "<<resumeMs<<" ms\n";
        return 0;
    }catch(const std::exception &error){std::cout<<"FAIL: "<<error.what()<<'\n';return 1;}
}
