#include "presentationhelpers.h"

#include <QApplication>
#include <QMessageBox>
#include <QPixmap>
#include <QWidget>

#include "application/applicationconstants.h"

void PresentationHelpers::activateWindow(QWidget *window)
{
    if (!window) return;
    if (window->isMinimized()) window->setWindowState(window->windowState() & ~Qt::WindowMinimized);
    window->show();window->raise();window->activateWindow();
}

void PresentationHelpers::showAboutDialog(QWidget *parent)
{
    QMessageBox messageBox(parent);
    messageBox.setWindowTitle(QCoreApplication::translate("PresentationHelpers","About"));
    messageBox.setTextFormat(Qt::RichText);
    messageBox.setText(QCoreApplication::translate("PresentationHelpers",
        "%1 %2<br>Campus network client<br>Maintainer: <a href='https://github.com/wtalioy'>wtalioy</a>"
        "<br><a href='https://github.com/%3'>Project website</a>"
        "<br>Core: <a href='https://github.com/Mythologyli/zju-connect'>zju-connect</a>"
        "<br><br>Upstream contributors: <a href='https://github.com/chenx-dust'>Chenx Dust</a>, "
        "<a href='https://github.com/Mythologyli'>Myth</a>, <a href='https://github.com/lyc8503'>lyc8503</a>")
        .arg(QApplication::applicationDisplayName().toHtmlEscaped(),QApplication::applicationVersion().toHtmlEscaped(),ApplicationConstants::RepositoryName));
    messageBox.setIconPixmap(QPixmap(":/resource/icon.svg").scaled(
        100,
        100,
        Qt::KeepAspectRatio,
        Qt::SmoothTransformation
    ));
    messageBox.exec();
}

bool PresentationHelpers::confirmCredentials(
    const QString &username,
    const QString &password
)
{
    if (username.isEmpty() || password.isEmpty())
    {
        return QMessageBox::warning(
            nullptr,
            QCoreApplication::translate("PresentationHelpers","Warning"),
            QCoreApplication::translate("PresentationHelpers","The account or password is empty.\n\nContinue?"),
            QMessageBox::Ok,
            QMessageBox::Cancel
        ) == QMessageBox::Ok;
    }

    const auto containsNonAscii = [](const QString &value)
    {
        for (const QChar character : value)
        {
            if (character.unicode() > 127)
            {
                return true;
            }
        }
        return false;
    };
    if (containsNonAscii(username) || containsNonAscii(password))
    {
        return QMessageBox::warning(
            nullptr,
            QCoreApplication::translate("PresentationHelpers","Warning"),
            QCoreApplication::translate("PresentationHelpers","The account or password contains non-ASCII characters. Check your input method.\n\nContinue?"),
            QMessageBox::Ok,
            QMessageBox::Cancel
        ) == QMessageBox::Ok;
    }
    return true;
}

QString PresentationHelpers::platformOperationMessage(const PlatformOperationResult &result)
{
    using Status = PlatformOperationResult::Status;
    QString text;
    switch (result.status) {
    case Status::Success: text = QCoreApplication::translate("PresentationHelpers","Operation completed"); break;
    case Status::Failed: text = QCoreApplication::translate("PresentationHelpers","Operation failed"); break;
    case Status::Cancelled: text = QCoreApplication::translate("PresentationHelpers","Authorization cancelled"); break;
    case Status::PermissionDenied: text = QCoreApplication::translate("PresentationHelpers","Permission denied"); break;
    case Status::Unsupported: text = QCoreApplication::translate("PresentationHelpers","This operation is not supported by this system or desktop."); break;
    case Status::TimedOut: text = QCoreApplication::translate("PresentationHelpers","Operation timed out"); break;
    }
    if (!result.detail.isEmpty()) text += "\n" + result.detail;
    if (result.mayHaveChanged && !result.succeeded()) text += QCoreApplication::translate("PresentationHelpers","\nSome settings may have changed. Check network recovery.");
    return text;
}

QString PresentationHelpers::credentialOperationMessage(CredentialStatus status)
{
    switch(status) {
    case CredentialStatus::Success: return {};
    case CredentialStatus::NotFound: return QCoreApplication::translate("PresentationHelpers","You can enter credentials when connecting.");
    case CredentialStatus::Locked: return QCoreApplication::translate("PresentationHelpers","Secure storage is locked. Unlock it first.");
    case CredentialStatus::Unavailable: return QCoreApplication::translate("PresentationHelpers","Secure storage is unavailable. You can sign in manually.");
    case CredentialStatus::PermissionDenied: return QCoreApplication::translate("PresentationHelpers","Secure storage permission was denied. Check authorization.");
    case CredentialStatus::Cancelled: return QCoreApplication::translate("PresentationHelpers","The profile or credentials changed. Reopen settings or retry.");
    case CredentialStatus::Limit: return QCoreApplication::translate("PresentationHelpers","These credentials exceed secure storage limits. You can enter them when connecting.");
    case CredentialStatus::InvalidArgument: return QCoreApplication::translate("PresentationHelpers","Legacy credential format or account identity could not be confirmed. Original data is preserved. Create a new profile to sign in manually.");
    case CredentialStatus::Conflict: return QCoreApplication::translate("PresentationHelpers","Legacy data conflicts with secure storage. Original data is preserved. Sign in manually before clearing the old credentials or cache.");
    case CredentialStatus::Failed: return QCoreApplication::translate("PresentationHelpers","The secure storage or profile operation did not complete. Check it and retry.");
    }
    return {};
}
