#ifndef APPLICATIONPATHS_H
#define APPLICATIONPATHS_H

#include <QString>

namespace ApplicationPaths
{
QString clientDataFile(const QString &connectionId);
QString logDirectory();
QString logFile();

}

#endif // APPLICATIONPATHS_H
