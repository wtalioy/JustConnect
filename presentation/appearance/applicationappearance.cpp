#include "applicationappearance.h"
#include <QApplication>
#include <QEvent>
#include <QFile>
#include <QPalette>
#include <QStyleHints>
#include <QStyle>
#include <QWidget>
#include <QAbstractSpinBox>
#include <QLineEdit>
#include <QStyleOptionFrame>
#include <QPushButton>
#include <QToolButton>

namespace {
void prepareWindow(QWidget *window) {
    if (window->property("nativeBackdropRequested").toBool()
        && (QGuiApplication::platformName()=="windows" || QGuiApplication::platformName()=="cocoa"))
        window->setAttribute(Qt::WA_TranslucentBackground);
}
class WindowAppearance final : public QObject {
public:
    using QObject::QObject;
    bool eventFilter(QObject *object,QEvent *event) override {
        if (event->type()!=QEvent::Create && event->type()!=QEvent::Polish && event->type()!=QEvent::Show) return false;
        auto *window=qobject_cast<QWidget *>(object);
        if(event->type()==QEvent::Polish) {
            auto *push=qobject_cast<QPushButton *>(window);
            auto *tool=qobject_cast<QToolButton *>(window);
            if(((push && push->isFlat()) || (tool && tool->autoRaise()))
                && (window->focusPolicy() & Qt::ClickFocus)) window->setFocusPolicy(Qt::TabFocus);
        }
        if (auto *spin=qobject_cast<QAbstractSpinBox *>(window)) {
            if (event->type()!=QEvent::Create) {
                QStyleOptionFrame option;option.initFrom(spin);
                auto *field=spin->findChild<QLineEdit *>();
                QStyleOptionFrame editor;editor.initFrom(field);
                const auto content=field->style()->subElementRect(QStyle::SE_LineEditContents,&editor,field);
                // Qt places the embedded editor at x=0 when spin buttons are styled; restore the shared content inset.
                field->setTextMargins(spin->style()->subElementRect(QStyle::SE_LineEditContents,&option,spin).left()
                    -field->geometry().left()-content.left(),0,0,0);
            }
        }
        if (!window || !window->isWindow() || (window->windowType()!=Qt::Window && window->windowType()!=Qt::Dialog)) return false;
        if (event->type()==QEvent::Create) {
            // Widget construction precedes native creation; Polish/Show can already be too late for alpha.
            prepareWindow(window);return false;
        }
        const bool enabled=window->property("nativeBackdropRequested").toBool()
            && ApplicationAppearance::enableNativeBackdrop(window);
        if (window->property("nativeBackdrop")!=QVariant(enabled)) {
            window->setProperty("nativeBackdrop",enabled);
            if (event->type()==QEvent::Show) {
                window->style()->unpolish(window);
                window->style()->polish(window);
            }
        }
        return false;
    }
};
}

void ApplicationAppearance::install(QWidget *initialWindow) {
    if (initialWindow) {
        initialWindow->setProperty("nativeBackdropRequested",true);
        prepareWindow(initialWindow);
    }
    if (qApp->property("appearanceInstalled").toBool()) return;
    qApp->setProperty("appearanceInstalled",true);
    qApp->styleHints()->setColorScheme(Qt::ColorScheme::Light);
    qApp->styleHints()->setTabFocusBehavior(Qt::TabFocusAllControls);
    auto palette=qApp->palette();
    palette.setColor(QPalette::Window,QColor("#fafbfc"));
    palette.setColor(QPalette::WindowText,QColor("#182132"));
    palette.setColor(QPalette::Base,Qt::white);
    palette.setColor(QPalette::AlternateBase,QColor("#f6f7fb"));
    palette.setColor(QPalette::Text,QColor("#182132"));
    palette.setColor(QPalette::Button,QColor("#ffffff"));
    palette.setColor(QPalette::ButtonText,QColor("#182132"));
    palette.setColor(QPalette::Highlight,QColor("#c8ced6"));
    palette.setColor(QPalette::HighlightedText,QColor("#182132"));
    qApp->setPalette(palette);
    QFile sheet(":/resource/appearance.qss");
    if (sheet.open(QIODevice::ReadOnly)) qApp->setStyleSheet(QString::fromUtf8(sheet.readAll()));
    qApp->installEventFilter(new WindowAppearance(qApp));
}

#if !defined(Q_OS_WIN) && !defined(Q_OS_MACOS)
bool ApplicationAppearance::enableNativeBackdrop(QWidget *) { return false; }
#endif
