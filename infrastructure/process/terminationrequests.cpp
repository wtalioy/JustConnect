#include "infrastructure/process/terminationrequests.h"

#include <QDebug>
#ifdef Q_OS_WIN
#include "infrastructure/process/windows/consoletermination.h"
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
#ifdef Q_OS_WIN
void captureSignal(int) { WindowsConsoleTermination::notify(); }
#else
constexpr int terminationSignals[]{SIGINT,SIGTERM,SIGHUP};
volatile std::sig_atomic_t signalWriteFd = -1;

int signalSocket()
{
    // Process-owned: a signal handler can still be writing when the Qt owner exits.
    static const int readFd = [] {
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
        for (int fd : fds) {
            if (::fcntl(fd, F_SETFL, O_NONBLOCK) == -1 || ::fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
                ::close(fds[0]);
                ::close(fds[1]);
                return -1;
            }
        }
        signalWriteFd = fds[1];
        return fds[0];
    }();
    return readFd;
}

void captureSignal(int)
{
    const int savedError = errno;
    const char byte = 1;
    (void)::write(signalWriteFd, &byte, sizeof byte);
    errno = savedError;
}
#endif
}

TerminationRequests::TerminationRequests(QObject *parent) : QObject(parent)
{
#ifdef Q_OS_WIN
    if (const auto event = WindowsConsoleTermination::install()) {
        notifier.setHandle(event);
        connect(&notifier, &QWinEventNotifier::activated, this, &TerminationRequests::requested);
        notifier.setEnabled(true);
        previousTerm = std::signal(SIGTERM, captureSignal);
    }
#else
    const int readFd = signalSocket();
    if (readFd == -1) {
        qWarning() << "Could not create termination notification socket";
        return;
    }
    notifier.setSocket(readFd);
    connect(&notifier, &QSocketNotifier::activated, this, [this, readFd] {
        char bytes[64];
        if (::read(readFd, bytes, sizeof bytes) > 0) emit requested();
    });
    notifier.setEnabled(true);
    struct sigaction action{};
    action.sa_handler=captureSignal;
    sigemptyset(&action.sa_mask);
    // Go workers use small stacks; a host signal handler must use the alternate stack.
    action.sa_flags=SA_ONSTACK;
    for (int i=0;i<3;++i) {
        installed[i]=sigaction(terminationSignals[i],&action,&previous[i])==0;
        if (!installed[i]) qWarning() << "Could not register termination signal" << terminationSignals[i];
    }
#endif
}
TerminationRequests::~TerminationRequests()
{
    notifier.setEnabled(false);
#ifdef Q_OS_WIN
    if (previousTerm!=SIG_ERR) std::signal(SIGTERM,previousTerm);
    WindowsConsoleTermination::finish();
#else
    for (int i=0;i<3;++i) {
        struct sigaction current{};
        if (installed[i] && sigaction(terminationSignals[i],nullptr,&current)==0 && current.sa_handler==captureSignal)
            sigaction(terminationSignals[i],&previous[i],nullptr);
    }
#endif
}
