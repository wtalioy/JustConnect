#include "graphcaptchawindow.h"

#include "captchacanvas.h"

#include <QBuffer>
#include <QImageReader>
#include "corelib/abi/constants.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>

GraphCaptchaWindow::GraphCaptchaWindow(QWidget *parent) : QDialog(parent), ui(new Ui::GraphCaptchaWindow)
{
    ui->setupUi(this);

    setWindowModality(Qt::WindowModal);
    setAttribute(Qt::WA_DeleteOnClose);

    connect(ui->buttonBox->button(QDialogButtonBox::Reset), &QAbstractButton::clicked, [&]() {
        ui->canvas->clearAll();
    });
}

GraphCaptchaWindow::~GraphCaptchaWindow()
{
    delete ui;
}

void GraphCaptchaWindow::setGraph(const QByteArray &image, bool useTextInput)
{
    textInputMode = useTextInput;
    QPixmap graph;
    if (image.size() <= JC_MAX_AUTH_IMAGE) {
        QBuffer buffer;
        buffer.setData(image);
        buffer.open(QIODevice::ReadOnly);
        QImageReader reader(&buffer);
        const auto format = reader.format();
        if (format == "png" || format == "jpeg" || format == "gif") {
            const QSize size = reader.size();
            if (size.isValid() && size.width() <= JC_MAX_AUTH_DIMENSION
                && size.height() <= JC_MAX_AUTH_DIMENSION
                && qint64(size.width()) * size.height() <= JC_MAX_AUTH_PIXELS)
                graph = QPixmap::fromImage(reader.read());
        }
    }
    ui->canvas->setImage(graph);
    ui->canvas->setEnabled(!textInputMode);
    ui->codeLabel->setVisible(textInputMode);
    ui->codeEdit->setVisible(textInputMode);
    ui->buttonBox->button(QDialogButtonBox::Reset)->setVisible(!textInputMode);
    if (textInputMode)
    {
        ui->codeEdit->clear();
        ui->codeEdit->setFocus();
    }
}

void GraphCaptchaWindow::accept()
{
    if (ui->canvas->image().isNull())
    {
        QMessageBox::warning(this, "图形验证码", "验证码图片加载失败，请重试连接。");
        return;
    }

    if (textInputMode)
    {
        const QString code = ui->codeEdit->text().trimmed();
        if (code.isEmpty())
        {
            QMessageBox::warning(this, "图形验证码", "请输入图片中的字符验证码。");
            ui->codeEdit->setFocus();
            return;
        }
        emit finishCaptcha({{"code", code}});
    }
    else
    {
        if (ui->canvas->pointsPx().isEmpty() || ui->canvas->pointsPx().size() > JC_MAX_AUTH_POINTS) {
            QMessageBox::warning(this, "图形验证码", "请按图片提示点选验证码。");
            return;
        }
        QJsonObject obj;
        QJsonArray points;
        for (const auto &point : ui->canvas->pointsPx())
        {
            points.append(QJsonObject{{"x", int(point.x())}, {"y", int(point.y())}});
        }
        obj.insert("points", points);
        obj.insert("width", ui->canvas->image().width());
        obj.insert("height", ui->canvas->image().height());
        emit finishCaptcha(obj);
    }

    QDialog::accept();
}
