#pragma once
#include <QElapsedTimer>
#include <QEventLoop>
#include <QTimer>
#include <cstdlib>
#include <iostream>

namespace UiWait {
inline constexpr int OperationTimeoutMs=10000;
inline constexpr int BrowserStartupTimeoutMs=15000;

template<class Predicate> void until(const char *file,int line,Predicate done,int timeoutMs=OperationTimeoutMs) {
    QElapsedTimer elapsed;elapsed.start();
    if(!done()) {
        QEventLoop loop;QTimer poll;
        QObject::connect(&poll,&QTimer::timeout,&loop,[&] {
            if(done() || elapsed.elapsed()>=timeoutMs)loop.quit();
        });
        poll.start(5);loop.exec();
    }
    if(!done()) {
        std::cerr<<file<<':'<<line<<": FAIL: Qt UI operation timed out\n";
        std::exit(1);
    }
}
}
