#include "captchacanvas.h"
#include "corelib/abi/constants.h"

#include <QMouseEvent>
#include <QKeyEvent>
#include <QFocusEvent>
#include <QPainter>
#include <QSizePolicy>

CaptchaCanvas::CaptchaCanvas(QWidget *parent) : QWidget(parent)
{
    setFocusPolicy(Qt::StrongFocus);
    setAttribute(Qt::WA_OpaquePaintEvent, true);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
}

void CaptchaCanvas::setImage(const QPixmap &pm)
{
    m_img = pm;
    m_pointsPx.clear();
    m_keyboardPoint=pm.rect().center();m_keyboardCursor=false;
    updateGeometry();
    update();
}

void CaptchaCanvas::clearAll()
{
    if (m_pointsPx.isEmpty())
        return;
    m_pointsPx.clear();
    update();
}

void CaptchaCanvas::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.fillRect(rect(), palette().window());
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setRenderHint(QPainter::SmoothPixmapTransform, true);
    const QRectF target = imageRect();
    if (!m_img.isNull())
        p.drawPixmap(target, m_img, QRectF(m_img.rect()));

    if (hasFocus() && m_keyboardCursor && isEnabled() && !m_img.isNull()) {
        const QPointF point(target.left()+m_keyboardPoint.x()*target.width()/m_img.width(),
            target.top()+m_keyboardPoint.y()*target.height()/m_img.height());
        for (const auto &pen: {QPen(Qt::white,4),QPen(palette().highlight().color(),2)}) {
            p.setPen(pen);p.drawLine(point-QPointF(7,0),point+QPointF(7,0));
            p.drawLine(point-QPointF(0,7),point+QPointF(0,7));
        }
    }

    if (m_pointsPx.isEmpty()) return;

    QFont font;
    font.setPixelSize(14);
    p.setBrush(Qt::white);
    p.setPen(QPen(Qt::black, 2));
    p.setFont(font);

    for (int i = 0; i < m_pointsPx.size(); ++i)
    {
        const QPointF imagePoint = m_pointsPx[i];
        const QPointF pt(target.left() + imagePoint.x() * target.width() / m_img.width(),
                         target.top() + imagePoint.y() * target.height() / m_img.height());
        p.drawEllipse(pt, 8, 8);
        p.drawText(QRectF(pt - QPointF(6, 6), pt + QPointF(6, 6)), QString::number(i + 1),
                   QTextOption(Qt::AlignCenter));
    }
}

void CaptchaCanvas::mousePressEvent(QMouseEvent *ev)
{
    const QPointF pos = ev->position();
    if (ev->button() == Qt::LeftButton && !m_img.isNull())
    {
        const bool hideCursor = m_keyboardCursor;
        m_keyboardCursor = false;
        const QRectF target = imageRect();
        if (target.contains(pos))
        {
            addPoint(QPointF(qBound(0.0,(pos.x()-target.left())*m_img.width()/target.width(),double(m_img.width()-1)),
                qBound(0.0,(pos.y()-target.top())*m_img.height()/target.height(),double(m_img.height()-1))));
        }
        if (hideCursor) update();
    }
}

void CaptchaCanvas::addPoint(const QPointF &point)
{
    if (m_pointsPx.size()>=JC_MAX_AUTH_POINTS) return;
    m_keyboardPoint=point.toPoint();m_pointsPx.push_back(point);update();
}
void CaptchaCanvas::keyPressEvent(QKeyEvent *event)
{
    if (!isEnabled() || m_img.isNull()) {QWidget::keyPressEvent(event);return;}
    m_keyboardCursor=true;
    const int step=event->modifiers().testFlag(Qt::ShiftModifier)?10:1;
    auto next=m_keyboardPoint;
    switch(event->key()) {
    case Qt::Key_Left: next.rx()-=step;break;
    case Qt::Key_Right: next.rx()+=step;break;
    case Qt::Key_Up: next.ry()-=step;break;
    case Qt::Key_Down: next.ry()+=step;break;
    case Qt::Key_Space: addPoint(m_keyboardPoint);event->accept();return;
    case Qt::Key_Backspace:
        if (!m_pointsPx.isEmpty()) {m_pointsPx.removeLast();update();}
        event->accept();return;
    default: QWidget::keyPressEvent(event);return;
    }
    m_keyboardPoint=QPoint(qBound(0,next.x(),m_img.width()-1),qBound(0,next.y(),m_img.height()-1));
    update();event->accept();
}
void CaptchaCanvas::focusInEvent(QFocusEvent *event) {QWidget::focusInEvent(event);m_keyboardCursor=event->reason()!=Qt::MouseFocusReason;update();}
void CaptchaCanvas::focusOutEvent(QFocusEvent *event) {QWidget::focusOutEvent(event);update();}

QRectF CaptchaCanvas::imageRect() const
{
    if (m_img.isNull() || width() <= 0 || height() <= 0)
        return {};

    QSizeF scaledSize = m_img.size();
    scaledSize.scale(size(), Qt::KeepAspectRatio);
    return QRectF(QPointF((width() - scaledSize.width()) / 2.0,
                          (height() - scaledSize.height()) / 2.0),
                  scaledSize);
}
