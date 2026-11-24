#ifndef PRESENTATIONHELPERS_H
#define PRESENTATIONHELPERS_H

#include <QString>
#include <QStringList>
#include <QList>
#include <QDialog>
#include <functional>
#include "application/platformoperationresult.h"
#include "application/credentialstore.h"

class QWidget;
class QLineEdit;
class QAction;
class QAbstractButton;
class QBoxLayout;
class QLabel;
class QPushButton;
class QTreeWidget;

namespace PresentationHelpers
{
class PromptDialog : public QDialog {
    Q_OBJECT
public:
    enum class Tone { Information, Question, Warning, Critical, Update };
    PromptDialog(QWidget *parent,const QString &title,const QString &body,Tone tone,
        const QString &primaryText={},bool cancellable=false);
    void setContent(const QString &title,const QString &body,const QString &primaryText={});
    QString text() const;
    Tone tone() const { return promptTone; }
    QPushButton *primaryButton() const { return primary; }
    QPushButton *dismissButton() const { return dismiss; }
private:
    Tone promptTone;
    QLabel *heading;
    QLabel *bodyLabel;
    QPushButton *primary;
    QPushButton *dismiss = nullptr;
    QBoxLayout *buttons;
};

QString credentialOperationMessage(CredentialStatus status);
QString platformOperationMessage(const PlatformOperationResult &result);
void showAboutDialog(QWidget *parent);
void activateWindow(QWidget *window);
bool actionPrompt(QWidget *parent,const QString &title,const QString &body,const QString &primaryText,
    PromptDialog::Tone tone=PromptDialog::Tone::Question);
void showMessage(QWidget *parent,const QString &title,const QString &body,
    PromptDialog::Tone tone=PromptDialog::Tone::Information);
QAction *passwordVisibilityAction(QLineEdit *field);
void setButtonIcon(QAbstractButton *button,const QString &path);
void connectCopyButton(QAbstractButton *button, std::function<QString()> text);
bool setTreeRows(QTreeWidget *tree,const QList<QStringList> &rows);
}

#endif // PRESENTATIONHELPERS_H
