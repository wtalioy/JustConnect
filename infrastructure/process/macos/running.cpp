#include "infrastructure/process/running.h"
#include <sys/sysctl.h>
#include <vector>

std::optional<bool> isProcessRunning(const QString &name)
{
    int query[]{CTL_KERN,KERN_PROC,KERN_PROC_ALL};size_t bytes=0;
    constexpr unsigned querySize=sizeof(query)/sizeof(query[0]);
    if(sysctl(query,querySize,nullptr,&bytes,nullptr,0)!=0 || bytes%sizeof(kinfo_proc))return {};
    std::vector<kinfo_proc> processes(bytes/sizeof(kinfo_proc));
    if(processes.empty())return false;
    // Names are public process-table metadata; per-PID detail queries can reject unrelated protected processes.
    if(sysctl(query,querySize,processes.data(),&bytes,nullptr,0)!=0 || bytes>processes.size()*sizeof(kinfo_proc)
        || bytes%sizeof(kinfo_proc))return {};
    for(size_t index=0;index<bytes/sizeof(kinfo_proc);++index)
        if(QString::fromLocal8Bit(processes[index].kp_proc.p_comm)==name)return true;
    return false;
}
