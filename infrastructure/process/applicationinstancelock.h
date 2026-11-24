#ifndef APPLICATIONINSTANCELOCK_H
#define APPLICATIONINSTANCELOCK_H

#include <QLockFile>

class ApplicationInstanceLock
{
public:
    explicit ApplicationInstanceLock(int waitMs=0);
    QLockFile::LockError error() const;

private:
    QLockFile lock;
};

#endif // APPLICATIONINSTANCELOCK_H
