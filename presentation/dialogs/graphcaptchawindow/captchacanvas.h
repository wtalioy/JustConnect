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

private:
    QRectF imageRect() const;

    QPixmap m_img;
    QVector<QPointF> m_pointsPx;
};
