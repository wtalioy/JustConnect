#pragma once

#include <QObject>
#include <csignal>
#ifdef Q_OS_WIN
#include <QWinEventNotifier>
#else
#include <QSocketNotifier>
#endif

class TerminationRequests : public QObject
{
    Q_OBJECT
public:
    explicit TerminationRequests(QObject *parent = nullptr);
    ~TerminationRequests() override;
signals:
    void requested();
private:
#ifdef Q_OS_WIN
    QWinEventNotifier notifier;
    using SignalHandler = void (*)(int);
    SignalHandler previousTerm = SIG_ERR;
#else
    QSocketNotifier notifier{QSocketNotifier::Read};
    struct sigaction previous[3]{};
    bool installed[3]{};
#endif
};
