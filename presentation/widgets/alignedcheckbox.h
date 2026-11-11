#pragma once

#include <QCheckBox>
#include <QImage>
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
        const auto caption = style()->subElementRect(QStyle::SE_CheckBoxContents, &option, this);
        const auto dpr = devicePixelRatioF();
        const auto toPixels = painter.deviceTransform();
        const auto fromPixels = toPixels.inverted();
        bool aligned = false;
        if (!option.text.isEmpty() && !caption.isEmpty() && !indicator.isEmpty()) {
            QImage label(qCeil(caption.width() * dpr), qCeil(caption.height() * dpr),
                         QImage::Format_ARGB32_Premultiplied);
            label.setDevicePixelRatio(dpr);
            label.setDotsPerMeterX(qRound(logicalDpiX() / 0.0254));
            label.setDotsPerMeterY(qRound(logicalDpiY() / 0.0254));
            label.fill(Qt::transparent);
            QPainter textPainter(&label);
            textPainter.setFont(painter.font());
            part.rect = QRect(QPoint(), caption.size());
            style()->drawControl(QStyle::CE_CheckBoxLabel, &part, &textPainter, this);
            textPainter.end();

            int first = -1, last = -1;
            for (int y = 0; y < label.height(); ++y) {
                const auto *row = reinterpret_cast<const QRgb *>(label.constScanLine(y));
                for (int x = 0; x < label.width(); ++x) {
                    // Ignore the faint antialiasing fringe at the edge of the ink.
                    if (qAlpha(row[x]) >= 173) {
                        if (first < 0) first = y;
                        last = y;
                        break;
                    }
                }
            }
            if (first >= 0) {
                // Match the text's odd or even pixel height so both centers share the same grid.
                const int parity = (last - first + 1) % 2;
                const int side = 2 * qRound((indicator.width() * dpr - parity) / 2) + parity;
                const auto squareCenter = toPixels.map(QRectF(indicator).center());
                const double inkCenter = (first + last + 1) / 2.0;
                const int textTop = qRound(squareCenter.y() - inkCenter);
                const int textLeft = qRound(toPixels.map(QPointF(caption.topLeft())).x());
                painter.drawImage(fromPixels.map(QPointF(textLeft, textTop)), label);
                const double squareTop = textTop + inkCenter - side / 2.0;
                const int squareLeft = qRound(toPixels.map(QPointF(indicator.topLeft())).x());
                painter.save();
                painter.translate(fromPixels.map(QPointF(squareLeft, squareTop)));
                painter.scale(side / (dpr * indicator.width()), side / (dpr * indicator.height()));
                part.rect = QRect(QPoint(), indicator.size());
                painter.drawPrimitive(QStyle::PE_IndicatorCheckBox, part);
                painter.restore();
                aligned = true;
            }
        }
        if (!aligned) {
            part.rect = indicator;
            painter.drawPrimitive(QStyle::PE_IndicatorCheckBox, part);
            part.rect = caption;
            painter.drawControl(QStyle::CE_CheckBoxLabel, part);
        }
        if (option.state & QStyle::State_HasFocus) {
            QStyleOptionFocusRect focus;
            focus.QStyleOption::operator=(option);
            focus.rect=style()->subElementRect(QStyle::SE_CheckBoxFocusRect,&option,this);
            painter.drawPrimitive(QStyle::PE_FrameFocusRect,focus);
        }
    }
};
