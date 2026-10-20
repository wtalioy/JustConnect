#include <QApplication>
#include <QDebug>
#include <QDialogButtonBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPixmap>
#include <QPushButton>
#include <QBuffer>

#include "presentation/dialogs/graphcaptchawindow/graphcaptchawindow.h"
#include "presentation/dialogs/graphcaptchawindow/captchacanvas.h"

namespace
{
QByteArray createCaptchaImage()
{
    QByteArray data;
    QBuffer buffer(&data);
    buffer.open(QIODevice::WriteOnly);
    QPixmap image(120, 40);
    image.fill(Qt::white);
    image.save(&buffer, "PNG");
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


}

int main(int argc, char *argv[])
{
    QApplication application(argc, argv);
    return submitsTextCaptcha()
        && cancelsWithoutSubmittingPlaceholder()
        && preservesCoordinateCaptchaResponse()
        ? 0
        : 1;
}
