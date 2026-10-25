#include "infrastructure/networkhelper/windows/control.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "windowsnetworkcontract.h"
#include <objbase.h>
#include <system_error>

namespace {
[[noreturn]] void fail(const char *stage){throw std::system_error(ERROR_INVALID_DATA,std::system_category(),stage);}
std::wstring guid(const GUID &id){wchar_t value[39]{};if(id==GUID{} || !StringFromGUID2(id,value,39))fail("invalid control identity");return value;}
}

std::wstring windowsControlPipeName(const GUID &session)
{return std::wstring(WindowsNetworkContract::ControlPipePrefix)+guid(session);}

std::string receiveWindowsControlMessage(WindowsPacketPipe &pipe,DWORD timeout)
{
    unsigned char length[4]{};
    pipe.read(length,1,timeout);
    pipe.read(length+1,3,WindowsNetworkContract::ControlTimeoutMs);
    const auto size=(std::uint32_t(length[0])<<24)|(std::uint32_t(length[1])<<16)|(std::uint32_t(length[2])<<8)|length[3];
    if(!size || size>WindowsNetworkContract::MaxMessageBytes)fail("invalid control message size");
    std::string message(size,'\0');pipe.read(message.data(),size,WindowsNetworkContract::ControlTimeoutMs);
    return message;
}
void sendWindowsControlMessage(WindowsPacketPipe &pipe,const std::string &message)
{
    if(message.empty() || message.size()>WindowsNetworkContract::MaxMessageBytes)fail("invalid control reply size");
    const auto size=static_cast<std::uint32_t>(message.size());
    unsigned char length[]{static_cast<unsigned char>(size>>24),static_cast<unsigned char>(size>>16),static_cast<unsigned char>(size>>8),static_cast<unsigned char>(size)};
    pipe.write(length,4,WindowsNetworkContract::ControlTimeoutMs);
    pipe.write(message.data(),size,WindowsNetworkContract::ControlTimeoutMs);
}
