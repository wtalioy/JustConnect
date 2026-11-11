#ifndef PRESENTATIONHELPERS_H
#define PRESENTATIONHELPERS_H

#include <QString>
#include <QStringList>
#include <QList>
#include <QDialogButtonBox>
#include <functional>
#include "application/platformoperationresult.h"
#include "application/credentialstore.h"

class QWidget;
class QLineEdit;
class QAction;
class QAbstractButton;
class QTreeWidget;

namespace PresentationHelpers
{
QString credentialOperationMessage(CredentialStatus status);
QString platformOperationMessage(const PlatformOperationResult &result);
void showAboutDialog(QWidget *parent);
void activateWindow(QWidget *window);
bool actionPrompt(QWidget *parent,const QString &title,const QString &body,
    QDialogButtonBox::StandardButton primary=QDialogButtonBox::Yes,
    QDialogButtonBox::StandardButton dismiss=QDialogButtonBox::No,const QString &primaryText={});
QAction *passwordVisibilityAction(QLineEdit *field);
void setButtonIcon(QAbstractButton *button,const QString &path);
void connectCopyButton(QAbstractButton *button, std::function<QString()> text);
bool setTreeRows(QTreeWidget *tree,const QList<QStringList> &rows);
}

#endif // PRESENTATIONHELPERS_H
