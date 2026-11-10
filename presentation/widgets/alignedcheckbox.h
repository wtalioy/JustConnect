#pragma once

#include <QCheckBox>
#include <QGlyphRun>
#include <QStyleOptionButton>
#include <QStylePainter>
#include <QTextLayout>

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
        QTextLayout layout(option.text, painter.font(), painter.device());
        layout.beginLayout();
        auto line = layout.createLine();
        if (line.isValid())
            line.setNumColumns(option.text.size());
        layout.endLayout();
        painter.save();
        if (line.isValid() && line.textLength() == option.text.size()) {
            QRectF ink;
            // Measure the shaped glyphs, including fallback fonts, before pixel rounding.
            for (const auto &run : line.glyphRuns()) {
                const auto glyphs = run.glyphIndexes();
                const auto positions = run.positions();
                const auto font = run.rawFont();
                for (qsizetype i = 0; i < glyphs.size(); ++i) {
                    const auto bounds = font.boundingRect(glyphs[i]);
                    if (!bounds.isEmpty())
                        ink |= bounds.translated(positions[i]);
                }
            }
            if (!ink.isEmpty()) {
                const auto lineTop = QRectF(part.rect).center().y() - (line.ascent() + line.descent()) / 2;
                painter.translate(0, QRectF(indicator).center().y() - lineTop - ink.center().y());
            }
        }
        painter.drawControl(QStyle::CE_CheckBoxLabel,part);
        painter.restore();
        if (option.state & QStyle::State_HasFocus) {
            QStyleOptionFocusRect focus;
            focus.QStyleOption::operator=(option);
            focus.rect=style()->subElementRect(QStyle::SE_CheckBoxFocusRect,&option,this);
            painter.drawPrimitive(QStyle::PE_FrameFocusRect,focus);
        }
    }
};
