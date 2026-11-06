#include "applicationappearance.h"
#include <QApplication>
#include <QEvent>
#include <QFile>
#include <QPalette>
#include <QStyleHints>
#include <QStyle>
#include <QWidget>

namespace {
void prepareWindow(QWidget *window) {
    if (QGuiApplication::platformName()=="windows" || QGuiApplication::platformName()=="cocoa")
        window->setAttribute(Qt::WA_TranslucentBackground);
}
class WindowAppearance final : public QObject {
public:
    using QObject::QObject;
    bool eventFilter(QObject *object,QEvent *event) override {
        if (event->type()!=QEvent::Create && event->type()!=QEvent::Polish && event->type()!=QEvent::Show) return false;
        auto *window=qobject_cast<QWidget *>(object);
        if (!window || !window->isWindow() || (window->windowType()!=Qt::Window && window->windowType()!=Qt::Dialog)) return false;
        if (event->type()==QEvent::Create) {
            // Widget construction precedes native creation; Polish/Show can already be too late for alpha.
            prepareWindow(window);return false;
        }
        const bool enabled=ApplicationAppearance::enableNativeBackdrop(window);
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
    if (initialWindow) prepareWindow(initialWindow);
    if (qApp->property("appearanceInstalled").toBool()) return;
    qApp->setProperty("appearanceInstalled",true);
    qApp->styleHints()->setColorScheme(Qt::ColorScheme::Light);
    qApp->styleHints()->setTabFocusBehavior(Qt::TabFocusAllControls);
    auto palette=qApp->palette();
    palette.setColor(QPalette::Window,QColor("#f5f7fa"));
    palette.setColor(QPalette::WindowText,QColor("#192638"));
    palette.setColor(QPalette::Base,Qt::white);
    palette.setColor(QPalette::AlternateBase,QColor("#edf2f8"));
    palette.setColor(QPalette::Text,QColor("#192638"));
    palette.setColor(QPalette::Button,QColor("#ffffff"));
    palette.setColor(QPalette::ButtonText,QColor("#192638"));
    palette.setColor(QPalette::Highlight,QColor("#315dd7"));
    palette.setColor(QPalette::HighlightedText,Qt::white);
    qApp->setPalette(palette);
    QFile sheet(":/resource/appearance.qss");
    if (sheet.open(QIODevice::ReadOnly)) qApp->setStyleSheet(QString::fromUtf8(sheet.readAll()));
    qApp->installEventFilter(new WindowAppearance(qApp));
}

#if !defined(Q_OS_WIN) && !defined(Q_OS_MACOS)
bool ApplicationAppearance::enableNativeBackdrop(QWidget *) { return false; }
#endif
