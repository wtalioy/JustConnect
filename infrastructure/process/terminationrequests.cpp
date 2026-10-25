#include "infrastructure/process/terminationrequests.h"

#include <QDebug>
#ifdef Q_OS_WIN
#include "infrastructure/process/windows/consoletermination.h"
#endif

namespace {
volatile std::sig_atomic_t pendingSignal = 0;
void captureSignal(int number) { pendingSignal = number; }
#ifdef Q_OS_UNIX
constexpr int terminationSignals[]{SIGINT,SIGTERM,SIGHUP};
#endif

}

TerminationRequests::TerminationRequests(QObject *parent) : QObject(parent)
{
#ifdef Q_OS_UNIX
    struct sigaction action{};
    action.sa_handler=captureSignal;
    sigemptyset(&action.sa_mask);
    // Go workers use small stacks; a host signal handler must use the alternate stack.
    action.sa_flags=SA_ONSTACK;
    for (int i=0;i<3;++i) {
        installed[i]=sigaction(terminationSignals[i],&action,&previous[i])==0;
        if (!installed[i]) qWarning() << "Could not register termination signal" << terminationSignals[i];
    }
#else
    previousTerm=std::signal(SIGTERM,captureSignal);
#endif
#ifdef Q_OS_WIN
    WindowsConsoleTermination::install();
#endif
    poll.setInterval(25);
    connect(&poll,&QTimer::timeout,this,[this] {
        bool pending=pendingSignal!=0;
        pendingSignal=0;
#ifdef Q_OS_WIN
        pending=WindowsConsoleTermination::takePending() || pending;
#endif
        if (pending) emit requested();
    });
    poll.start();
}
TerminationRequests::~TerminationRequests()
{
    poll.stop();
#ifdef Q_OS_UNIX
    for (int i=0;i<3;++i) {
        struct sigaction current{};
        if (installed[i] && sigaction(terminationSignals[i],nullptr,&current)==0 && current.sa_handler==captureSignal)
            sigaction(terminationSignals[i],&previous[i],nullptr);
    }
#else
    if (previousTerm!=SIG_ERR) std::signal(SIGTERM,previousTerm);
#endif
#ifdef Q_OS_WIN
    WindowsConsoleTermination::finish();
#endif
}
