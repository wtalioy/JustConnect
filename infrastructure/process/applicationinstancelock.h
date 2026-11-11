#ifndef APPLICATIONINSTANCELOCK_H
#define APPLICATIONINSTANCELOCK_H

#include <QLockFile>

class ApplicationInstanceLock
{
public:
    ApplicationInstanceLock();
    QLockFile::LockError error() const;

private:
    QLockFile lock;
};

#endif // APPLICATIONINSTANCELOCK_H
