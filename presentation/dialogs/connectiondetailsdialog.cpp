#include "connectiondetailsdialog.h"
#include "application/applicationlogger.h"
#include "application/networkpolicysession.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "presentation/coordinators/connectiondiagnostics.h"
#include "presentation/presentationhelpers.h"
#include "ui_connectiondetailsdialog.h"

#include <QApplication>
#include <QDesktopServices>
#include <QEvent>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHeaderView>
#include <QMessageBox>
#include <QSysInfo>
#include <QTabBar>

ConnectionDetailsDialog::ConnectionDetailsDialog(ConnectionDiagnostics *diagnostics, NetworkPolicySession *policy,
    ApplicationLogger *logger, ApplicationLogFile *logFile, QWidget *parent)
    : QDialog(parent), ui(std::make_unique<Ui::ConnectionDetailsDialog>()), diagnostics(diagnostics), policy(policy), logFile(logFile)
{
    ui->setupUi(this);
    setObjectName("detailsDialog");
    resize(640,568);
    ui->logPlainTextEdit->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    ui->diagnosticReport->header()->setSectionResizeMode(0,QHeaderView::ResizeToContents);
    ui->diagnosticReport->header()->setSectionResizeMode(1,QHeaderView::Stretch);
    ui->diagnosticReport->setSelectionMode(QAbstractItemView::NoSelection);
    ui->diagnosticReport->setFocusPolicy(Qt::TabFocus);
    const auto refreshVisible=[this] { if (ui->overviewTab->isVisible()) updateDiagnostics(); };
    connect(diagnostics,&ConnectionDiagnostics::changed,this,refreshVisible);
    connect(ui->detailsTabs,&QTabWidget::currentChanged,this,[this,refreshVisible] {
        refreshVisible();
        if (ui->logPlainTextEdit->isVisible()) flushLog();
    });
    connect(ui->refreshDiagnosticsButton,&QPushButton::clicked,policy,&NetworkPolicySession::refresh);
    PresentationHelpers::setButtonIcon(ui->diagnosticRulesButton,":/resource/rules.svg");
    connect(ui->diagnosticRulesButton,&QPushButton::clicked,this,&ConnectionDetailsDialog::networkProtectionRequested);
    PresentationHelpers::connectCopyButton(ui->copyDiagnosticsButton,[this] {
        return QApplication::applicationVersion() + "\n" + this->diagnostics->report();
    });

    logFlushTimer.setSingleShot(true);
    connect(&logFlushTimer,&QTimer::timeout,this,[this] {
        if (ui->logPlainTextEdit->isVisible()) flushLog();
    });
    connect(logger,&ApplicationLogger::entryAdded,this,[this](const QString &entry) {
        if (entry.contains(u'\n')) pendingLogEntries.append(entry.split(u'\n'));
        else pendingLogEntries.append(entry);
        const auto limit = ui->logPlainTextEdit->maximumBlockCount();
        if (limit > 0 && pendingLogEntries.size() > limit)
            pendingLogEntries.remove(0, pendingLogEntries.size() - limit);
        if (ui->logPlainTextEdit->isVisible() && !logFlushTimer.isActive())
            logFlushTimer.start();
    });
    connect(ui->openLogPushButton,&QPushButton::clicked,this,&ConnectionDetailsDialog::openLogFile);
    connect(ui->clearLogPushButton,&QPushButton::clicked,this,&ConnectionDetailsDialog::clearLog);
    PresentationHelpers::connectCopyButton(ui->copyLogPushButton,[this] {
        flushLog();
        return ui->logPlainTextEdit->toPlainText();
    });
}

ConnectionDetailsDialog::~ConnectionDetailsDialog() = default;

void ConnectionDetailsDialog::openDetails()
{
    if (!isVisible()) {
        ui->detailsTabs->setCurrentIndex(0);
        ui->detailsTabs->tabBar()->setFocus();
    }
    if (ui->overviewTab->isVisibleTo(this)) updateDiagnostics();
    PresentationHelpers::activateWindow(this);
}

void ConnectionDetailsDialog::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if (event->type()!=QEvent::LanguageChange) return;
    ui->retranslateUi(this);
    if (ui->overviewTab->isVisible()) updateDiagnostics();
}

void ConnectionDetailsDialog::setConnectionSummary(const QString &summary)
{
    ui->profileDetailLabel->setText(summary);
}

void ConnectionDetailsDialog::setConnectionStatus(const QString &status)
{
    ui->statusDetailLabel->setText(status);
}

void ConnectionDetailsDialog::updateDiagnostics()
{
    QList<QStringList> rows;
    for (const auto &[label,value]:diagnostics->fields()) rows.append(QStringList{label,value});
    PresentationHelpers::setTreeRows(ui->diagnosticReport,rows);
    ui->refreshDiagnosticsButton->setEnabled(!policy->currentGeneration().isEmpty() && !policy->isBusy());
}

void ConnectionDetailsDialog::openLogFile()
{
    const auto path=logFile->filePath();
    if (QFileInfo::exists(path)) QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    else QMessageBox::warning(this,tr("Log file"),tr("The log file could not be created."));
}

void ConnectionDetailsDialog::flushLog()
{
    logFlushTimer.stop();
    if (pendingLogEntries.isEmpty()) return;
    const auto text=pendingLogEntries.join(u'\n');
    pendingLogEntries.clear();
    ui->logPlainTextEdit->appendPlainText(text);
}

void ConnectionDetailsDialog::clearLog()
{
    logFlushTimer.stop();
    pendingLogEntries.clear();
    ui->logPlainTextEdit->clear();
}

void ConnectionDetailsDialog::resetLog(const QString &connectionName,const QString &configurationPath)
{
    clearLog();
    ui->logPlainTextEdit->appendPlainText(tr("Welcome to %1\nSystem: %2\nConnection: %3\nConfiguration: %4\n")
        .arg(QApplication::applicationDisplayName(),QSysInfo::prettyProductName(),connectionName,configurationPath));
}
