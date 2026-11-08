#ifndef PRESENTATIONHELPERS_H
#define PRESENTATIONHELPERS_H

#include <QString>
#include <QStringList>
#include <QList>
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
void showAboutDialog(QWidget *parent, const QString &coreVersion);
void activateWindow(QWidget *window);
QAction *passwordVisibilityAction(QLineEdit *field);
void setButtonIcon(QAbstractButton *button,const QString &path);
void connectCopyButton(QAbstractButton *button, std::function<QString()> text);
QString profileKindLabel(const QString &kind);
bool setTreeRows(QTreeWidget *tree,const QList<QStringList> &rows);
}

#endif // PRESENTATIONHELPERS_H
