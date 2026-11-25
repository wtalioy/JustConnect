#pragma once
#include <QAction>
#include <QApplication>
#include <QKeyEvent>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QStyle>
#include <QStyleHints>
#if QT_VERSION >= QT_VERSION_CHECK(6, 12, 0)
#include <QAccessibilityHints>
#endif
#include <QVariantAnimation>

class ConnectionMenu final : public QMenu {
public:
    explicit ConnectionMenu(QWidget *parent) : QMenu(parent) {
        stroke.setDuration(950);
        stroke.setStartValue(0.0);
        stroke.setKeyValueAt(0.15,1.0);
        stroke.setEndValue(1.0);
        connect(&stroke,&QVariantAnimation::valueChanged,this,[this] { update(checkRect()); });
        connect(&stroke,&QVariantAnimation::finished,this,[this] { update(checkRect()); });
        connect(this,&QMenu::aboutToHide,&stroke,&QVariantAnimation::stop);
    }
    void showCheckFor(QAction *action) {
        if (!isVisible()) return;
        stroke.stop();
        update(checkRect());
        checkedAction=action;
        stroke.start();
        bool reducedMotion=style()->styleHint(QStyle::SH_Widget_Animation_Duration,nullptr,this)==0;
#if QT_VERSION >= QT_VERSION_CHECK(6, 12, 0)
        reducedMotion |= qApp->styleHints()->accessibility()->motionPreference()==Qt::MotionPreference::ReducedMotion;
#endif
        if (reducedMotion)
            stroke.setCurrentTime(qRound(stroke.duration()*0.15));
        update(checkRect());
    }
protected:
    void mousePressEvent(QMouseEvent *event) override {
        auto *action=actionAt(event->position().toPoint());
        if (event->button()==Qt::LeftButton && keepsMenuOpen(action)) {
            setActiveAction(action);
            return;
        }
        QMenu::mousePressEvent(event);
    }
    void mouseReleaseEvent(QMouseEvent *event) override {
        auto *action=actionAt(event->position().toPoint());
        if (event->button()==Qt::LeftButton && keepsMenuOpen(action) && activeAction()==action) {
            action->trigger();
            return;
        }
        QMenu::mouseReleaseEvent(event);
    }
    void keyPressEvent(QKeyEvent *event) override {
        auto *action=activeAction();
        if (keepsMenuOpen(action)
            && (event->key()==Qt::Key_Return || event->key()==Qt::Key_Enter || event->key()==Qt::Key_Space)) {
            action->trigger();
            return;
        }
        QMenu::keyPressEvent(event);
    }
    void paintEvent(QPaintEvent *event) override {
        QMenu::paintEvent(event);
        if (stroke.state()!=QAbstractAnimation::Running) return;
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const auto bounds=checkRect();
        painter.translate(bounds.left(),bounds.top());
        painter.scale(bounds.width()/24.0,bounds.height()/24.0);
        painter.setPen(QPen(QColor("#263143"),2,Qt::SolidLine,Qt::RoundCap,Qt::RoundJoin));
        const QPointF start(5,12), corner(9,16), end(19,6);
        const auto progress=stroke.currentValue().toReal();
        constexpr auto turn=2.0/7.0;
        if (progress<=turn) painter.drawLine(start,start+(corner-start)*(progress/turn));
        else painter.drawPolyline(QPolygonF{start,corner,corner+(end-corner)*((progress-turn)/(1-turn))});
    }
private:
    static bool keepsMenuOpen(const QAction *action) {
        return action && action->isEnabled() && action->property("keepConnectionMenuOpen").toBool();
    }
    QRect checkRect() const {
        if (!checkedAction) return {};
        const auto row=actionGeometry(checkedAction);
        // Match the leading indicator in appearance.qss.
        return QStyle::visualRect(layoutDirection(),row,QRect(row.left()+5,row.top()+(row.height()-16)/2,16,16));
    }
    QAction *checkedAction=nullptr;
    QVariantAnimation stroke;
};
