#include "infrastructure/process/running.h"
#include <windows.h>
#include <tlhelp32.h>

std::optional<bool> isProcessRunning(const QString &name)
{
    const auto snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE)return {};
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);
    auto more=Process32FirstW(snapshot,&entry);
    while(more){
        if(QString::fromWCharArray(entry.szExeFile).compare(name+".exe",Qt::CaseInsensitive)==0){CloseHandle(snapshot);return true;}
        more=Process32NextW(snapshot,&entry);
    }
    const auto error=GetLastError();CloseHandle(snapshot);
    return error==ERROR_NO_MORE_FILES?std::optional<bool>(false):std::nullopt;
}
