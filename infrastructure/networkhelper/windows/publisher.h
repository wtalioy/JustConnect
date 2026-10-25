#pragma once

#include <windows.h>
#include <array>
#include <string>

using WindowsSha256 = std::array<unsigned char,32>;
void verifyWindowsPublisher(const std::wstring &path,HANDLE pinnedFile,const WindowsSha256 &expected);
