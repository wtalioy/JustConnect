#pragma once
#include <QIcon>
#include <QStyleOptionToolButton>
#include <QStylePainter>
#include <QToolButton>
#include <QtMath>

class ProfileMenuButton final : public QToolButton {
public:
    explicit ProfileMenuButton(QWidget *parent=nullptr) : QToolButton(parent) {
        setPopupMode(InstantPopup);
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
        chevron.paint(&painter,QRect(left+labelWidth+Gap,(height()-Arrow)/2,Arrow,Arrow),
            Qt::AlignCenter,isEnabled()?QIcon::Normal:QIcon::Disabled);
    }
private:
    static constexpr int Padding=10,Gap=8,Arrow=12,MinimumWidth=64;
    const QIcon chevron{":/resource/chevron.svg"};
};
