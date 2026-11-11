#pragma once
#include <QPolygonF>
#include <QStyleOptionToolButton>
#include <QStylePainter>
#include <QToolButton>
#include <QtMath>

class ProfileMenuButton final : public QToolButton {
public:
    explicit ProfileMenuButton(QWidget *parent=nullptr) : QToolButton(parent) {
        setPopupMode(InstantPopup);
        setAutoRaise(true);
        setToolButtonStyle(Qt::ToolButtonTextOnly);
        setSizePolicy(QSizePolicy::Maximum,QSizePolicy::Fixed);
    }
    QSize sizeHint() const override {
        ensurePolished();
        return {qMax(MinimumWidth,qCeil(QFontMetricsF(font()).horizontalAdvance(text()))+2*Padding+Gap+Arrow),QToolButton::sizeHint().height()};
    }
    QSize minimumSizeHint() const override {return {MinimumWidth,sizeHint().height()};}
protected:
    void paintEvent(QPaintEvent *) override {
        QStyleOptionToolButton option;initStyleOption(&option);
        option.text.clear();option.icon={};option.arrowType=Qt::NoArrow;
        option.features=QStyleOptionToolButton::None;option.subControls=QStyle::SC_ToolButton;
        QStylePainter painter(this);painter.drawComplexControl(QStyle::CC_ToolButton,option);
        // Keep the caption and chevron together; native menu-indicator padding varies by style.
        const int available=qMax(0,width()-2*Padding-Gap-Arrow);
        const QFontMetricsF metrics(font());
        const auto label=metrics.elidedText(text(),Qt::ElideRight,available);
        const int labelWidth=qCeil(metrics.horizontalAdvance(label));
        const int left=(width()-labelWidth-Gap-Arrow)/2;
        style()->drawItemText(&painter,QRect(left,0,labelWidth,height()),Qt::AlignLeft|Qt::AlignVCenter|Qt::TextSingleLine,
            option.palette,isEnabled(),label,QPalette::ButtonText);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(QPen(option.palette.color(isEnabled()?QPalette::Active:QPalette::Disabled,QPalette::ButtonText),
            1.6,Qt::SolidLine,Qt::RoundCap,Qt::RoundJoin));
        painter.translate(left+labelWidth+Gap,(height()-Arrow)/2.0);
        painter.drawPolyline(QPolygonF{QPointF(2,4.5),QPointF(7,9.5),QPointF(12,4.5)});
    }
private:
    static constexpr int Padding=10,Gap=8,Arrow=14,MinimumWidth=64;
};
