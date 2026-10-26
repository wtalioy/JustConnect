#include "infrastructure/process/running.h"
#include <QDir>
#include <QFile>

std::optional<bool> isProcessRunning(const QString &name)
{
    QDir processes("/proc");
    if(!processes.exists() || !processes.isReadable())return {};
    bool complete=true;
    for(const auto &entry:processes.entryList(QDir::Dirs|QDir::NoDotAndDotDot)){
        bool valid=false;entry.toUInt(&valid);if(!valid)continue;
        QFile comm(processes.filePath(entry+"/comm"));
        if(!comm.open(QIODevice::ReadOnly)){if(comm.exists())complete=false;continue;}
        const auto value=comm.readAll();
        if(comm.error()!=QFileDevice::NoError){complete=false;continue;}
        if(QString::fromLocal8Bit(value).trimmed()==name)return true;
    }
    return complete?std::optional<bool>(false):std::nullopt;
}
