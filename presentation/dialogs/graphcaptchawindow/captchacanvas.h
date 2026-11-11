#pragma once

#include <QWidget>

class CaptchaCanvas : public QWidget
{
    Q_OBJECT
public:
    explicit CaptchaCanvas(QWidget *parent = nullptr);

    void setImage(const QPixmap &pm);
    const QPixmap &image() const
    {
        return m_img;
    }

    const QVector<QPointF> &pointsPx() const
    {
        return m_pointsPx;
    }
    void clearAll();

    QSize sizeHint() const override
    {
        return m_img.size();
    }

protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *ev) override;
    void keyPressEvent(QKeyEvent *event) override;
    void focusInEvent(QFocusEvent *event) override;
    void focusOutEvent(QFocusEvent *event) override;

private:
    QRectF imageRect() const;
    void addPoint(const QPointF &point);

    QPixmap m_img;
    QVector<QPointF> m_pointsPx;
    QPoint m_keyboardPoint;
    bool m_keyboardCursor=false;
};
