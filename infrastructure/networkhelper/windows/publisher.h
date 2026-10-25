#pragma once

#include <windows.h>
#include <array>
#include <string>

using WindowsPublisherHash = std::array<unsigned char,32>;
void verifyWindowsPublisher(const std::wstring &path,HANDLE pinnedFile,const WindowsPublisherHash &expected);
