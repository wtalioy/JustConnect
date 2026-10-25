#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

class WindowsPacketPipe;
std::wstring windowsControlPipeName(const GUID &session);
std::wstring windowsPacketPipeName(const GUID &session);
std::string receiveWindowsControlMessage(WindowsPacketPipe &pipe,DWORD timeout);
void sendWindowsControlMessage(WindowsPacketPipe &pipe,const std::string &message);
int runWindowsNetworkControl(DWORD caller,std::uint64_t created,const GUID &session);
