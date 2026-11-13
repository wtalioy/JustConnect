#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QSettings>
#include <QPointer>

#include "application/connectionsession.h"
#include "application/savedconnectionservice.h"
#include "application/systemproxysession.h"
#include "presentation/dialogs/settingwindow/settingwindow.h"
#include "presentation/coordinators/authdialogcoordinator.h"
#include "presentation/main/mainwindowcoordinator.h"

namespace Ui
{
    class MainWindow;
}

class QActionGroup;
class ApplicationLogger;
class ApplicationLogFile;
class ConnectionUiController;
class ConnectionDetailsDialog;
class NetworkPolicyWindow;
class UpdateChecker;

class MainWindow : public QMainWindow
{
Q_OBJECT

public:
    explicit MainWindow(
        ApplicationLogger *logger,
        ApplicationLogFile *logFile,
        QWidget *parent = nullptr,
        MainWindowCoordinator::NetworkFactory networkFactory = nullptr
    );

    ~MainWindow() override;

public slots:

    void cleanUpWhenQuit();
    void gracefullyQuit();
    void endSystemSession();

signals:
    void shutdownSettled(bool success);

protected:
#ifdef Q_OS_MACOS
    void showEvent(QShowEvent *event) override;
#endif
    void closeEvent(QCloseEvent *e) override;
    bool eventFilter(QObject *watched, QEvent *event) override;
    void changeEvent(QEvent *event) override;


private:
    bool exitReady=false;
    bool viewsInitialized=false;
    void upgradeSettings();
    void showApplicationPreferences();
    void showConnectionSettings();

    void resetConnectionLog();

    void resetConnectionUi();

    void updateConnectionState(ConnectionState state);

    QString connectionName() const;
    void updateConnectionSummary();

    void showNotification(
        const QString &title,
        const QString &content,
        QSystemTrayIcon::MessageIcon icon = QSystemTrayIcon::MessageIcon::Information
    );

    void updateVersionInfo();

    void setupTrayIcon();

    void setupConnectionMenu();

    void refreshConnectionMenu();
    void updateClashExport();

    bool switchConnection(const QString &connectionId);

    void createConnection();

    void renameCurrentConnection();

    void deleteCurrentConnection();

    Ui::MainWindow *ui;
    QSystemTrayIcon *trayIcon;
    QMenu *trayConnectionMenu;
    QAction *trayConnectAction;
    QAction *trayShowAction;
    QAction *trayCloseAction;
    QAction *connectionActionsSeparator;
    QActionGroup *switchGroup;
    QActionGroup *traySwitchGroup;
    QAction *addConnectionAction;
    QAction *copyClashScriptAction;
    QAction *renameConnectionAction;
    QAction *deleteConnectionAction;
    ConnectionSession *connectionSession = nullptr;
    SystemProxySession *systemProxySession = nullptr;
    AuthDialogCoordinator *authenticationDialogs = nullptr;
    ConnectionUiController *connectionUiController=nullptr;
    MainWindowCoordinator *coordinator;
    ConnectionDetailsDialog *details;
    UpdateChecker *updateChecker;
    QSettings *settings;
    SavedConnectionService *savedConnections;
    QString currentConnectionId;

    QPointer<SettingWindow> settingWindow;
    QPointer<QDialog> preferencesWindow;
    QPointer<NetworkPolicyWindow> networkPolicyWindow;

};

#endif //MAINWINDOW_H
