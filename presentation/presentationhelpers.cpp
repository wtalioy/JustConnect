#include "presentationhelpers.h"

#include <QApplication>
#include <QAccessibleAnnouncementEvent>
#if QT_VERSION >= QT_VERSION_CHECK(6, 12, 0)
#include <QAccessibilityHints>
#endif
#include <QClipboard>
#include <QDate>
#include <QDialog>
#include <QLabel>
#include <QLocale>
#include <QProgressBar>
#include <QPushButton>
#include <QScreen>
#include <QVBoxLayout>
#include <QHBoxLayout>
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

PresentationHelpers::PromptDialog::PromptDialog(QWidget *parent,const QString &title,const QString &body,
    Tone tone,const QString &primaryText,bool cancellable)
    : QDialog(parent), promptTone(tone), heading(new QLabel(this)), bodyLabel(new QLabel(this)),
      primary(new QPushButton(this)), buttons(new QBoxLayout(QBoxLayout::LeftToRight))
{
    setObjectName("actionPrompt");
    setWindowTitle(QApplication::applicationDisplayName());
    setWindowFlag(Qt::WindowContextHelpButtonHint,false);
    setFixedWidth(qMin(504,screen()->availableGeometry().width()-32));
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(26,24,26,24);
    layout->setSpacing(22);

    auto *row = new QHBoxLayout;
    row->setSpacing(16);
    auto *icon = new QLabel(this);
    icon->setObjectName("promptIcon");
    icon->setFixedSize(44,44);
    const auto artwork = tone==Tone::Update ? ":/resource/app-icon.svg"
        : tone==Tone::Question ? ":/resource/prompt-question.svg"
        : tone==Tone::Warning || tone==Tone::Critical ? ":/resource/prompt-warning.svg"
        : ":/resource/prompt-info.svg";
    icon->setPixmap(QIcon(artwork).pixmap(icon->size(),devicePixelRatioF()));
    row->addWidget(icon,0,Qt::AlignTop);

    auto *copy = new QVBoxLayout;
    copy->setSpacing(6);
    heading->setObjectName("promptHeading");
    bodyLabel->setObjectName("promptBody");
    for (auto *label : {heading,bodyLabel}) {
        label->setTextFormat(Qt::PlainText);
        label->setWordWrap(true);
        label->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);
        copy->addWidget(label);
    }
    row->addLayout(copy,1);
    layout->addLayout(row);

    buttons->setSpacing(8);
    buttons->addStretch();
    const auto addButton = [this](QPushButton *button,bool emphasized) {
        button->setProperty("promptPrimary",emphasized);
        button->setAutoDefault(false);
        buttons->addWidget(button);
    };
    if (cancellable) {
        dismiss = new QPushButton(this);
        addButton(dismiss,false);
        connect(dismiss,&QPushButton::clicked,this,&QDialog::reject);
    }
    addButton(primary,true);
    connect(primary,&QPushButton::clicked,this,&QDialog::accept);
    auto *defaultButton = dismiss && tone!=Tone::Update ? dismiss : primary;
    defaultButton->setDefault(true);
    // Keep the initial focus ring off the buttons until the user navigates to one.
    heading->setFocusPolicy(Qt::ClickFocus);
    if (dismiss) setTabOrder({heading,dismiss,primary});
    heading->setFocus(Qt::OtherFocusReason);
    layout->addLayout(buttons);
    ensurePolished();
    setContent(title,body,primaryText);
}

void PresentationHelpers::PromptDialog::setContent(const QString &title,const QString &body,const QString &primaryText)
{
    setAccessibleName(title);
    heading->setText(title);
    bodyLabel->setText(body);
    primary->setText(primaryText.isEmpty() ? tr("OK") : primaryText);
    if (dismiss) {
        dismiss->setText(tr("Cancel"));
        const auto margins = layout()->contentsMargins();
        const int required = primary->sizeHint().width()+dismiss->sizeHint().width()+buttons->spacing();
        buttons->setDirection(required<=width()-margins.left()-margins.right()
            ? QBoxLayout::LeftToRight : QBoxLayout::TopToBottom);
    }
    layout()->invalidate();
    const auto height=layout()->totalHeightForWidth(width());
    setFixedHeight(height>=0 ? height : layout()->totalSizeHint().height());
}

QString PresentationHelpers::PromptDialog::text() const
{
    return bodyLabel->text();
}

bool PresentationHelpers::actionPrompt(QWidget *parent,const QString &title,const QString &body,
    const QString &primaryText,PromptDialog::Tone tone)
{
    PromptDialog dialog(parent,title,body,tone,primaryText,true);
    return dialog.exec()==QDialog::Accepted;
}

void PresentationHelpers::showMessage(QWidget *parent,const QString &title,const QString &body,PromptDialog::Tone tone)
{
    PromptDialog dialog(parent,title,body,tone);
    dialog.exec();
}

PresentationHelpers::UpdateProgressDialog::UpdateProgressDialog(QWidget *parent)
    : QDialog(parent), heading(new QLabel(tr("Downloading update"),this)),
      status(new QLabel(this)), progress(new QProgressBar(this)), cancel(new QPushButton(tr("Cancel"),this))
{
    setWindowTitle(QApplication::applicationDisplayName());
    setAccessibleName(heading->text());
    setWindowFlag(Qt::WindowContextHelpButtonHint,false);
    setWindowFlag(Qt::WindowCloseButtonHint,false);
    setFixedWidth(qMin(472,screen()->availableGeometry().width()-32));
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(24,22,24,22);
    layout->setSpacing(8);
    heading->setObjectName("promptHeading");
    heading->setFocusPolicy(Qt::ClickFocus);
    heading->setFocus(Qt::OtherFocusReason);
    layout->addWidget(heading);
    auto *description = new QLabel(tr("JustConnect will restart when installation finishes."),this);
    description->setObjectName("promptBody");
    description->setWordWrap(true);
    layout->addWidget(description);

    progress->setObjectName("updateProgress");
    progress->setAccessibleName(heading->text());
    progress->setTextVisible(false);
    progress->setFixedHeight(8);
    status->setObjectName("updateProgressStatus");
    status->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    status->setText(tr("Preparing…"));
    status->setMinimumWidth(status->sizeHint().width());
    auto *row = new QHBoxLayout;
    row->setSpacing(12);
    row->addWidget(progress,1);
    row->addWidget(status);
    layout->addSpacing(8);
    layout->addLayout(row);

    cancel->setProperty("promptPrimary",false);
    cancel->setAutoDefault(false);
    connect(cancel,&QPushButton::clicked,this,&UpdateProgressDialog::reject);
    layout->addWidget(cancel,0,Qt::AlignRight);
    setDownloadProgress(0);
}

void PresentationHelpers::UpdateProgressDialog::setDownloadProgress(int percentage)
{
    progress->setValue(percentage);
    status->setText(progress->text());
}

void PresentationHelpers::UpdateProgressDialog::prepareToInstall()
{
    heading->setText(tr("Installing update"));
    setAccessibleName(heading->text());
    progress->setAccessibleName(heading->text());
    progress->setRange(0,0);
    status->setText(tr("Preparing…"));
    cancel->hide();
    adjustSize();
}

void PresentationHelpers::UpdateProgressDialog::reject()
{
    if (!cancel->isHidden()) QDialog::reject();
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

void PresentationHelpers::showAboutDialog(QWidget *parent)
{
    QDialog dialog(parent);
    dialog.setObjectName("aboutDialog");
    dialog.setWindowTitle(QCoreApplication::translate("PresentationHelpers", "About"));
    dialog.setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    auto *layout = new QVBoxLayout(&dialog);
    layout->setContentsMargins(32, 24, 32, 30);
    layout->setSpacing(4);

    auto *icon = new QLabel(&dialog);
    const QIcon artwork(":/resource/app-icon.svg");
    icon->setPixmap(artwork.pixmap(QSize(80, 80), dialog.devicePixelRatioF()));
    layout->addWidget(icon, 0, Qt::AlignHCenter);

    auto *name = new QLabel(QApplication::applicationDisplayName(), &dialog);
    name->setObjectName("aboutAppName");
    name->setTextFormat(Qt::PlainText);
    layout->addWidget(name, 0, Qt::AlignHCenter);

    layout->addSpacing(12);
    auto *credit = new QLabel(QStringLiteral("Powered by wtalioy"), &dialog);
    credit->setObjectName("aboutCredit");
    layout->addWidget(credit, 0, Qt::AlignHCenter);

    auto *version = new QLabel(QCoreApplication::translate("PresentationHelpers", "Version %1")
        .arg(QApplication::applicationVersion()), &dialog);
    version->setObjectName("aboutVersion");
    version->setTextFormat(Qt::PlainText);
    version->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    layout->addWidget(version, 0, Qt::AlignHCenter);

#ifdef PROJ_RELEASE_DATE
    const auto releaseDate = QDate::fromString(QStringLiteral(PROJ_RELEASE_DATE), Qt::ISODate);
    if (releaseDate.isValid()) {
        layout->addSpacing(10);
        auto *released = new QLabel(QCoreApplication::translate("PresentationHelpers", "Released %1")
            .arg(QLocale::c().toString(releaseDate, QStringLiteral("MMM d, yyyy"))), &dialog);
        released->setObjectName("aboutReleaseDate");
        layout->addWidget(released, 0, Qt::AlignHCenter);
    }
#endif

    dialog.ensurePolished();
    dialog.setFixedSize(layout->totalSizeHint().expandedTo(QSize(300, 0)));
    dialog.exec();
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
