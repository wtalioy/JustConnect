#include "presentationhelpers.h"

#include <QApplication>
#include <QAccessibleAnnouncementEvent>
#include <QAccessibilityHints>
#include <QClipboard>
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
#include <QStyle>
#include <QStyleHints>
#include <QVariantAnimation>
#include <QTreeWidget>
#include <QSignalBlocker>
#include <utility>

#include "application/applicationconstants.h"

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

bool PresentationHelpers::setTreeRows(QTreeWidget *tree,const QList<QStringList> &rows)
{
    bool same=tree->topLevelItemCount()==rows.size();
    for(int i=0;same && i<rows.size();++i)
        for(int column=0;same && column<tree->columnCount();++column)
            same=tree->topLevelItem(i)->text(column)==rows[i].value(column);
    if(same) return false;
    const QSignalBlocker blocker(tree);
    const bool updates=tree->updatesEnabled();tree->setUpdatesEnabled(false);
    while(tree->topLevelItemCount()>rows.size()) delete tree->takeTopLevelItem(rows.size());
    for(int i=0;i<rows.size();++i) {
        auto *row=tree->topLevelItem(i);
        if(!row) row=new QTreeWidgetItem(tree);
        for(int column=0;column<tree->columnCount();++column) {
            const auto text=rows[i].value(column);
            row->setText(column,text);row->setToolTip(column,text);
        }
    }
    tree->setUpdatesEnabled(updates);
    return true;
}

void PresentationHelpers::setButtonIcon(QAbstractButton *button,const QString &path)
{
    // Qt's button label adds 4 px; reserve another 4 px while preserving an 18 px vector glyph at every scale.
    button->setIcon(QIcon(new ButtonIcon(path)));button->setIconSize(QSize(22,18));
}

void PresentationHelpers::connectCopyButton(QAbstractButton *button, std::function<QString()> text)
{
    constexpr int fadeMs = 140;
    constexpr int durationMs = 2 * fadeMs + 1000;
    const auto copy = button->icon();
    const QIcon check(":/resource/check.svg");
    auto *animation = new QVariantAnimation(button);
    animation->setDuration(durationMs);
    animation->setStartValue(0.0);
    animation->setKeyValueAt(double(fadeMs) / durationMs, 1.0);
    animation->setKeyValueAt(double(durationMs - fadeMs) / durationMs, 1.0);
    animation->setEndValue(0.0);

    const auto reduceMotion = [button] {
#if QT_VERSION >= QT_VERSION_CHECK(6, 12, 0)
        if (QApplication::styleHints()->accessibility()->motionPreference() == Qt::MotionPreference::ReducedMotion)
            return true;
#endif
        return button->style()->styleHint(QStyle::SH_Widget_Animation_Duration, nullptr, button) == 0;
    };
    QObject::connect(animation, &QVariantAnimation::valueChanged, button, [=](const QVariant &value) {
        const auto opacity = value.toReal();
        if (opacity == 0.0 || opacity == 1.0 || reduceMotion()) {
            button->setIcon(opacity == 1.0 ? check : copy);
            return;
        }
        const auto size = button->iconSize();
        const auto dpr = button->devicePixelRatioF();
        const auto outgoing = copy.pixmap(size, dpr);
        QPixmap frame(outgoing.size());
        frame.setDevicePixelRatio(dpr);
        frame.fill(Qt::transparent);
        QPainter painter(&frame);
        const auto blend = QEasingCurve(QEasingCurve::InOutQuad).valueForProgress(opacity);
        painter.setOpacity(1.0 - blend);
        painter.drawPixmap(0, 0, outgoing);
        painter.setCompositionMode(QPainter::CompositionMode_Plus);
        painter.setOpacity(blend);
        painter.drawPixmap(0, 0, check.pixmap(size, dpr));
        painter.end();
        button->setIcon(QIcon(frame));
    });
    QObject::connect(button, &QAbstractButton::clicked, button, [=, text = std::move(text)] {
        auto *clipboard = QApplication::clipboard();
        const auto value = text();
        clipboard->setText(value);
        if (value.isEmpty() || clipboard->text() != value) {
            animation->stop();
            animation->setCurrentTime(0);
            return;
        }

        if (animation->state() != QAbstractAnimation::Running) animation->start();
        const int time = animation->currentTime();
        // Repeated copies extend the check, or reverse the return fade without a jump.
        if (reduceMotion()) animation->setCurrentTime(fadeMs);
        else if (time >= fadeMs) animation->setCurrentTime(qMin(fadeMs, durationMs - time));

        QAccessibleAnnouncementEvent announcement(button, QCoreApplication::translate("PresentationHelpers", "Copied to clipboard"));
        QAccessible::updateAccessibility(&announcement);
    });
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

void PresentationHelpers::showAboutDialog(QWidget *parent, const QString &coreVersion)
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
    if (!coreVersion.isEmpty())
        messageBox.setInformativeText(QCoreApplication::translate("PresentationHelpers", "Core version: %1")
            .arg(coreVersion.toHtmlEscaped()));
    messageBox.setIconPixmap(QApplication::windowIcon().pixmap(QSize(80,80),messageBox.devicePixelRatioF()));
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
    case CredentialStatus::Cancelled: return QCoreApplication::translate("PresentationHelpers","The connection settings or credentials changed. Reopen settings or retry.");
    case CredentialStatus::Limit: return QCoreApplication::translate("PresentationHelpers","These credentials exceed secure storage limits. You can enter them when connecting.");
    case CredentialStatus::InvalidArgument: return QCoreApplication::translate("PresentationHelpers","Legacy credential format or account identity could not be confirmed. Original data is preserved. Add a new connection to sign in manually.");
    case CredentialStatus::Conflict: return QCoreApplication::translate("PresentationHelpers","Legacy data conflicts with secure storage. Original data is preserved. Sign in manually before clearing the old credentials or cache.");
    case CredentialStatus::Failed: return QCoreApplication::translate("PresentationHelpers","The secure storage or connection settings operation did not complete. Check it and retry.");
    }
    return {};
}
