#pragma once
#include <QDialog>
#include <QPointer>

class NetworkPolicySession;
class QLabel;
class QPushButton;
class QTreeWidget;

class NetworkPolicyWindow : public QDialog
{
    Q_OBJECT
public:
    explicit NetworkPolicyWindow(NetworkPolicySession *session, QWidget *parent = nullptr);
private:
    void updateModel();
    QPointer<NetworkPolicySession> session;
    QLabel *status;
    QTreeWidget *targets;
    QTreeWidget *namespaces;
    QPushButton *refresh;
};
