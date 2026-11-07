#pragma once
#include <QDialog>
#include <QJsonObject>
#include <QPointer>
#include <functional>

class NetworkPolicySession;
class QLabel;
class QPushButton;
class QTreeWidget;
class QInputDialog;
class QTabWidget;
class QShowEvent;

class NetworkPolicyWindow : public QDialog
{
    Q_OBJECT
public:
    explicit NetworkPolicyWindow(NetworkPolicySession *session, QWidget *parent = nullptr);
protected:
    void changeEvent(QEvent *event) override;
    void showEvent(QShowEvent *event) override;
private:
    void retranslate();
    QInputDialog *createEditor(std::function<void(QInputDialog *)> translate);
    void setInputError(const char *source,const QString &scope={});
    const char *inputErrorText=nullptr;
    QString inputErrorScope;
    QTabWidget *tabs;
    QLabel *explanation;
    void updateModel();
    void updateActions();
    void updatePolicyMessage();
    void chooseCampusAddress();
    void restoreOriginalAddress();
    void editName(bool campus);
    QPointer<NetworkPolicySession> session;
    QJsonObject displayedModel;
    QLabel *status;
    QLabel *policyMessage;
    QLabel *nameChoices;
    QTreeWidget *targets;
    QTreeWidget *namespaces;
    QPushButton *retry, *campus, *original, *campusName, *originalName;
    QPointer<QInputDialog> editor;
};
