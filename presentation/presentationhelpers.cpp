#include "presentationhelpers.h"

#include <QApplication>
#include <QMessageBox>
#include <QPixmap>
#include <QWidget>
#include <QAction>
#include <QIcon>
#include <QLineEdit>
#include <QKeySequence>
#include <QAbstractButton>
#include <QIconEngine>
#include <QPainter>

#include "application/applicationconstants.h"
#include "application/defaultsettings.h"

namespace {
class ButtonIcon final : public QIconEngine {
public:
    explicit ButtonIcon(const QString &path) : icon(path) {}
    QIconEngine *clone() const override {return new ButtonIcon(*this);}
    void paint(QPainter *painter,const QRect &rect,QIcon::Mode mode,QIcon::State state) override {
        auto glyph=rect;glyph.setWidth(qRound(rect.width()*18.0/22.0));
        icon.paint(painter,glyph,Qt::AlignCenter,mode,state);
    }
    QPixmap pixmap(const QSize &size,QIcon::Mode mode,QIcon::State state) override {
        QPixmap result(size);result.fill(Qt::transparent);QPainter painter(&result);
        paint(&painter,QRect(QPoint(),size),mode,state);return result;
    }
private:
    QIcon icon;
};
}

void PresentationHelpers::setButtonIcon(QAbstractButton *button,const QString &path)
{
    // Qt's button label adds 4 px; reserve another 4 px while preserving an 18 px vector glyph at every scale.
    button->setIcon(QIcon(new ButtonIcon(path)));button->setIconSize(QSize(22,18));
}

QString PresentationHelpers::profileKindLabel(const QString &kind)
{
    if (kind==DefaultSettings::builtInProfile().value("JustConnect/ProfileKind").toString())
        return QCoreApplication::translate("PresentationHelpers","Fudan");
    if (kind=="Custom") return QCoreApplication::translate("PresentationHelpers","Custom");
    return kind;
}

QAction *PresentationHelpers::passwordVisibilityAction(QLineEdit *field)
{
    auto *action=field->findChild<QAction *>("visibilityAction",Qt::FindDirectChildrenOnly);
    if (!action) {
        action=field->addAction(QIcon(":/resource/eye.svg"),QLineEdit::TrailingPosition);
        action->setObjectName("visibilityAction");action->setCheckable(true);
        action->setShortcut(QKeySequence(QKeyCombination(Qt::ControlModifier|Qt::ShiftModifier,Qt::Key_H)));
        action->setShortcutContext(Qt::WidgetShortcut);
        QObject::connect(action,&QAction::toggled,field,[field](bool visible) {
            field->setEchoMode(visible ? QLineEdit::Normal : QLineEdit::Password);
            passwordVisibilityAction(field);
        });
    }
    const auto label=action->isChecked() ? QCoreApplication::translate("PresentationHelpers","Hide")
        : QCoreApplication::translate("PresentationHelpers","Show");
    action->setIcon(QIcon(action->isChecked()?":/resource/eye-off.svg":":/resource/eye.svg"));
    action->setText(label);
    action->setToolTip(label+" ("+action->shortcut().toString(QKeySequence::NativeText)+")");
    field->setAccessibleDescription(action->toolTip());
    return action;
}

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
    if (result.mayHaveChanged && !result.succeeded()) text += QCoreApplication::translate("PresentationHelpers","\nSome system settings may have changed. Check them before retrying.");
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
