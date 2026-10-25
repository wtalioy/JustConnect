#pragma once

#include <QObject>
#include <QTimer>
#include <csignal>

class TerminationRequests : public QObject
{
    Q_OBJECT
public:
    explicit TerminationRequests(QObject *parent = nullptr);
    ~TerminationRequests() override;
signals:
    void requested();
private:
    QTimer poll;
#ifdef Q_OS_UNIX
    struct sigaction previous[3]{};
    bool installed[3]{};
#else
    using SignalHandler = void (*)(int);
    SignalHandler previousTerm = SIG_DFL;
#endif
};
