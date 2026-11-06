#ifndef PRESENTATIONHELPERS_H
#define PRESENTATIONHELPERS_H

#include <QString>
#include "application/platformoperationresult.h"
#include "application/credentialstore.h"

class QWidget;
class QLineEdit;
class QAction;
class QAbstractButton;

namespace PresentationHelpers
{
QString credentialOperationMessage(CredentialStatus status);
QString platformOperationMessage(const PlatformOperationResult &result);
void showAboutDialog(QWidget *parent = nullptr);
void activateWindow(QWidget *window);
QAction *passwordVisibilityAction(QLineEdit *field);
void setButtonIcon(QAbstractButton *button,const QString &path);
QString profileKindLabel(const QString &kind);
}

#endif // PRESENTATIONHELPERS_H
