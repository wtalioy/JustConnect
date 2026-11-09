#pragma once

#include <QCheckBox>
#include <QFontMetricsF>
#include <QStyleOptionButton>
#include <QStylePainter>

class AlignedCheckBox final : public QCheckBox
{
public:
    using QCheckBox::QCheckBox;

protected:
    void paintEvent(QPaintEvent *) override
    {
        QStyleOptionButton option;
        initStyleOption(&option);
        QStylePainter painter(this);

        QStyleOptionButton part=option;
        const auto indicator=style()->subElementRect(QStyle::SE_CheckBoxIndicator,&option,this);
        part.rect=indicator;
        painter.drawPrimitive(QStyle::PE_IndicatorCheckBox,part);

        part.rect=style()->subElementRect(QStyle::SE_CheckBoxContents,&option,this);
        const QFontMetricsF fontMetrics(painter.font(),painter.device());
        const auto ink=fontMetrics.tightBoundingRect(option.text);
        if (!ink.isEmpty()) {
            // Qt centers the line box. Center the visible glyphs on the indicator instead.
            const auto baseline=QRectF(part.rect).center().y()+(fontMetrics.ascent()-fontMetrics.descent())/2;
            const auto inkCenter=baseline+ink.center().y();
            part.rect.translate(0,qRound(QRectF(indicator).center().y()-inkCenter));
        }
        painter.drawControl(QStyle::CE_CheckBoxLabel,part);
        if (option.state & QStyle::State_HasFocus) {
            QStyleOptionFocusRect focus;
            focus.QStyleOption::operator=(option);
            focus.rect=style()->subElementRect(QStyle::SE_CheckBoxFocusRect,&option,this);
            painter.drawPrimitive(QStyle::PE_FrameFocusRect,focus);
        }
    }
};
