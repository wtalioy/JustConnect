#ifndef PRESENTATIONHELPERS_H
#define PRESENTATIONHELPERS_H

#include <QString>
#include "application/platformoperationresult.h"

class QWidget;

namespace PresentationHelpers
{
QString platformOperationMessage(const PlatformOperationResult &result);
void showAboutDialog(QWidget *parent = nullptr);
bool confirmCredentials(const QString &username, const QString &password);
}

#endif // PRESENTATIONHELPERS_H
