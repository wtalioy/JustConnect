#pragma once
#include <QDialog>
#include <QPointer>

class NetworkPolicySession;
class QLabel;
class QPushButton;
class QTreeWidget;
class QInputDialog;

class NetworkPolicyWindow : public QDialog
{
    Q_OBJECT
public:
    explicit NetworkPolicyWindow(NetworkPolicySession *session, QWidget *parent = nullptr);
private:
    void updateModel();
    void updateActions();
    void updatePolicyMessage();
    void chooseCampusAddress();
    void restoreOriginalAddress();
    QPointer<NetworkPolicySession> session;
    QLabel *status;
    QLabel *policyMessage;
    QTreeWidget *targets;
    QTreeWidget *namespaces;
    QPushButton *refresh, *campus, *original;
    QPointer<QInputDialog> editor;
};
