#ifndef PRESENTATIONHELPERS_H
#define PRESENTATIONHELPERS_H

#include <QString>
#include "application/platformoperationresult.h"
#include "application/credentialstore.h"

class QWidget;
class QLineEdit;
class QAction;

namespace PresentationHelpers
{
QString credentialOperationMessage(CredentialStatus status);
QString platformOperationMessage(const PlatformOperationResult &result);
void showAboutDialog(QWidget *parent = nullptr);
void activateWindow(QWidget *window);
QAction *passwordVisibilityAction(QLineEdit *field);
}

#endif // PRESENTATIONHELPERS_H
