#pragma once

#include <QDialog>
#include <QStringList>
#include <QTimer>
#include <memory>

class ApplicationLogFile;
class ApplicationLogger;
class ConnectionDiagnostics;
class NetworkPolicySession;
namespace Ui { class ConnectionDetailsDialog; }

class ConnectionDetailsDialog final : public QDialog {
    Q_OBJECT
public:
    ConnectionDetailsDialog(ConnectionDiagnostics *diagnostics, NetworkPolicySession *policy,
        ApplicationLogger *logger, ApplicationLogFile *logFile, QWidget *parent);
    ~ConnectionDetailsDialog() override;
    void openDetails();
    void openLogFile();
    void resetLog(const QString &connectionName, const QString &configurationPath);
    void setConnectionSummary(const QString &summary);
    void setConnectionStatus(const QString &status);
signals:
    void networkProtectionRequested();
protected:
    void changeEvent(QEvent *event) override;
private:
    void updateDiagnostics();
    void flushLog();
    void clearLog();

    std::unique_ptr<Ui::ConnectionDetailsDialog> ui;
    ConnectionDiagnostics *diagnostics;
    NetworkPolicySession *policy;
    ApplicationLogFile *logFile;
    QTimer logFlushTimer;
    QStringList pendingLogEntries;
};
