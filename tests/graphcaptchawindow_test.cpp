#include <QApplication>
#include "corelib/abi/constants.h"
#include <QDebug>
#include <QDialogButtonBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QLineEdit>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QPixmap>
#include <QPushButton>
#include <QBuffer>

#include "presentation/dialogs/graphcaptchawindow/graphcaptchawindow.h"
#include "presentation/dialogs/graphcaptchawindow/captchacanvas.h"

namespace
{
QByteArray createCaptchaImage(int width=120,int height=40,const char *format="PNG")
{
    QByteArray data;
    QBuffer buffer(&data);
    buffer.open(QIODevice::WriteOnly);
    QPixmap image(width,height);
    image.fill(Qt::white);
    image.save(&buffer,format);
    return data;
}

bool submitsTextCaptcha()
{
    const auto imageData = createCaptchaImage();
    GraphCaptchaWindow window;
    window.setGraph(imageData, true);

    auto *codeEdit = window.findChild<QLineEdit *>("codeEdit");
    auto *buttonBox = window.findChild<QDialogButtonBox *>("buttonBox");
    QJsonObject submitted;
    QObject::connect(&window, &GraphCaptchaWindow::finishCaptcha,
                     [&](const QJsonObject &captcha) { submitted = captcha; });

    if (imageData.isEmpty() || codeEdit == nullptr || buttonBox == nullptr
        || codeEdit->isHidden())
    {
        qCritical() << "text captcha controls were not configured";
        return false;
    }

    codeEdit->setText(" A1b2 ");
    buttonBox->button(QDialogButtonBox::Ok)->click();
    if (submitted["code"] != "A1b2")
    {
        qCritical() << "text captcha submission failed:" << submitted;
        return false;
    }
    return true;
}

bool cancelsWithoutSubmittingPlaceholder()
{
    GraphCaptchaWindow window;
    window.setGraph(createCaptchaImage(), true);

    int submissions = 0;
    int cancellations = 0;
    QObject::connect(&window, &GraphCaptchaWindow::finishCaptcha,
                     [&](const QJsonObject &) { ++submissions; });
    QObject::connect(&window, &QDialog::rejected,
                     [&]() { ++cancellations; });

    window.findChild<QDialogButtonBox *>("buttonBox")
        ->button(QDialogButtonBox::Cancel)->click();
    if (submissions != 0 || cancellations != 1)
    {
        qCritical() << "captcha cancellation emitted an invalid response";
        return false;
    }
    return true;
}

bool preservesCoordinateCaptchaResponse()
{
    GraphCaptchaWindow window;
    window.setGraph(createCaptchaImage(), false);

    auto *canvas = window.findChild<CaptchaCanvas *>();
    canvas->resize(240, 160);
    const QPointF position(120, 80);
    QMouseEvent click(QEvent::MouseButtonPress, position, position, position,
        Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
    QApplication::sendEvent(canvas, &click);
    QJsonObject submitted;
    QObject::connect(&window, &GraphCaptchaWindow::finishCaptcha,
                     [&](const QJsonObject &captcha) { submitted = captcha; });
    window.findChild<QDialogButtonBox *>("buttonBox")
        ->button(QDialogButtonBox::Ok)->click();

    const QJsonObject response = submitted;
    if (response.value("width").toInt() != 120
        || response.value("height").toInt() != 40
        || response["points"].toArray().size() != 1
        || response["points"].toArray().first().toObject()["x"].toInt() != 60
        || response["points"].toArray().first().toObject()["y"].toInt() != 20)
    {
        qCritical() << "coordinate captcha response changed:" << submitted;
        return false;
    }
    return true;
}

bool rejectsUnsupportedOrOversizedImagesBeforeDecode()
{
    for(const auto &data:QList<QByteArray>{createCaptchaImage(2049,2048),createCaptchaImage(16,16,"BMP")}) {
        GraphCaptchaWindow window;
        window.setGraph(data,true);
        if(data.isEmpty() || !window.findChild<CaptchaCanvas *>()->image().isNull()){
            qCritical()<<"oversized or unsupported captcha decoded";return false;
        }
    }
    for(const auto &data:QList<QByteArray>{createCaptchaImage(16,16,"JPEG"),QByteArray::fromBase64("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")}) {
        GraphCaptchaWindow window;window.setGraph(data,true);
        if(window.findChild<CaptchaCanvas *>()->image().isNull())return false;
    }
    return true;
}

bool keyboardSelectionRetainsImageCoordinatesAndLimits()
{
    GraphCaptchaWindow window;window.setGraph(createCaptchaImage(12,8),false);
    auto *canvas=window.findChild<CaptchaCanvas *>();canvas->resize(240,160);
    const auto key=[&](int value,Qt::KeyboardModifiers modifiers=Qt::NoModifier) {
        QKeyEvent event(QEvent::KeyPress,value,modifiers);QApplication::sendEvent(canvas,&event);
    };
    for(int i=0;i<4;++i)key(Qt::Key_Right,Qt::ShiftModifier);
    for(int i=0;i<4;++i)key(Qt::Key_Down,Qt::ShiftModifier);
    key(Qt::Key_Space);
    if(canvas->pointsPx()!=QVector<QPointF>{QPointF(11,7)})return false;
    canvas->resize(480,320);key(Qt::Key_Left);key(Qt::Key_Up);key(Qt::Key_Space);
    if(canvas->pointsPx().last()!=QPointF(10,6))return false;
    key(Qt::Key_Backspace);if(canvas->pointsPx().size()!=1)return false;
    for(int i=0;i<JC_MAX_AUTH_POINTS+2;++i)key(Qt::Key_Space);
    if(canvas->pointsPx().size()!=JC_MAX_AUTH_POINTS)return false;
    window.setGraph(createCaptchaImage(),true);key(Qt::Key_Space);
    return canvas->pointsPx().isEmpty();
}

bool limitsCapturedPoints()
{
    GraphCaptchaWindow window;
    window.setGraph(createCaptchaImage(),false);
    auto *canvas=window.findChild<CaptchaCanvas *>();
    canvas->resize(240,160);
    const QPointF position(120,80);
    for(int i=0;i<JC_MAX_AUTH_POINTS+5;++i) {
        QMouseEvent click(QEvent::MouseButtonPress,position,position,position,Qt::LeftButton,Qt::LeftButton,Qt::NoModifier);
        QApplication::sendEvent(canvas,&click);
    }
    if(canvas->pointsPx().size()!=JC_MAX_AUTH_POINTS)return false;
    window.findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Reset)->click();
    return canvas->pointsPx().isEmpty();
}


}

int main(int argc, char *argv[])
{
    QApplication application(argc, argv);
    return submitsTextCaptcha()
        && cancelsWithoutSubmittingPlaceholder()
        && preservesCoordinateCaptchaResponse()
        && rejectsUnsupportedOrOversizedImagesBeforeDecode()
        && keyboardSelectionRetainsImageCoordinatesAndLimits()
        && limitsCapturedPoints()
        ? 0
        : 1;
}
