#include "infrastructure/process/running.h"
#include <libproc.h>
#include <sys/proc_info.h>
#include <vector>
#include <cerrno>
#include <limits>

std::optional<bool> isProcessRunning(const QString &name)
{
    const auto capacity=proc_listallpids(nullptr,0);
    if(capacity<=0 || capacity>std::numeric_limits<int>::max()/int(sizeof(int)))return {};
    std::vector<int> processes(capacity);
    const auto count=proc_listallpids(processes.data(),capacity*int(sizeof(int)));
    if(count<=0 || count>capacity)return {};
    bool complete=count<capacity;
    for(int index=0;index<count;++index){
        if(processes[index]<=0)continue;
        char image[sizeof(proc_bsdinfo{}.pbi_name)]{};errno=0;
        const auto size=proc_name(processes[index],image,sizeof(image));
        if(size<=0){if(errno!=ESRCH)complete=false;continue;}
        if(QString::fromLocal8Bit(image,size)==name)return true;
    }
    return complete?std::optional<bool>(false):std::nullopt;
}
