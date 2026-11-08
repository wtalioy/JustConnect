#include "applicationappearance.h"
#include <QApplication>
#include <QEvent>
#include <QFile>
#include <QPalette>
#include <QStyleHints>
#include <QScreen>
#include <QAbstractItemView>
#include <QStyle>
#include <QWidget>
#include <QAbstractSpinBox>
#include <QLineEdit>
#include <QStyleOptionFrame>
#include <QPushButton>
#include <QToolButton>
#include <QComboBox>
#include <QStyledItemDelegate>

namespace {
class WindowAppearance final : public QObject {
public:
    using QObject::QObject;
    bool eventFilter(QObject *object,QEvent *event) override {
        if (event->type()!=QEvent::Polish && event->type()!=QEvent::Show) return false;
        auto *window=qobject_cast<QWidget *>(object);
        if(event->type()==QEvent::Polish) {
            // Use the same inset item rendering instead of platform-specific combo menu delegates.
            if(auto *combo=qobject_cast<QComboBox *>(window)) {
                if(!qobject_cast<QStyledItemDelegate *>(combo->itemDelegate()))
                    combo->setItemDelegate(new QStyledItemDelegate(combo));
            }
            auto *push=qobject_cast<QPushButton *>(window);
            auto *tool=qobject_cast<QToolButton *>(window);
            if(((push && push->isFlat()) || (tool && tool->autoRaise()))
                && (window->focusPolicy() & Qt::ClickFocus)) window->setFocusPolicy(Qt::TabFocus);
        }
        if (event->type() == QEvent::Show && window && window->windowType() == Qt::Popup) {
            auto *combo = qobject_cast<QComboBox *>(window->parentWidget());
            if (combo && combo->view()->window() == window) {
                constexpr int gap = 4;
                const QRect field(combo->mapToGlobal(QPoint()), combo->size());
                const QRect available = combo->screen()->availableGeometry();
                const int below = field.bottom() + 1 + gap;
                const int above = field.top() - gap - window->height();
                const int left = qBound(available.left(), field.left(),
                    qMax(available.left(), available.right() - window->width() + 1));
                if (below + window->height() <= available.bottom() + 1)
                    window->move(left, below);
                else if (above >= available.top())
                    window->move(left, above);
            }
        }
        if (auto *spin=qobject_cast<QAbstractSpinBox *>(window)) {
            QStyleOptionFrame option;option.initFrom(spin);
            auto *field=spin->findChild<QLineEdit *>();
            QStyleOptionFrame editor;editor.initFrom(field);
            const auto content=field->style()->subElementRect(QStyle::SE_LineEditContents,&editor,field);
            // Qt places the embedded editor at x=0 when spin buttons are styled; restore the shared content inset.
            field->setTextMargins(spin->style()->subElementRect(QStyle::SE_LineEditContents,&option,spin).left()
                -field->geometry().left()-content.left(),0,0,0);
        }
        return false;
    }
};
}

void ApplicationAppearance::install() {
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
    palette.setColor(QPalette::Highlight,QColor("#dce0e6"));
    palette.setColor(QPalette::HighlightedText,QColor("#182132"));
    qApp->setPalette(palette);
    QFile sheet(":/resource/appearance.qss");
    if (sheet.open(QIODevice::ReadOnly)) {
        auto style = QString::fromUtf8(sheet.readAll());
#ifdef Q_OS_MACOS
        style += QStringLiteral(R"(
QWidget, QLabel#profileDetailLabel { font-size: 11.5pt; }
QMenu, QLabel#statusHintLabel { font-size: 10.5pt; }
QLabel[secondary="true"], QLabel#statusDetailLabel, QPlainTextEdit#logPlainTextEdit { font-size: 10pt; }
)");
#endif
        qApp->setStyleSheet(style);
    }
    qApp->installEventFilter(new WindowAppearance(qApp));
}
