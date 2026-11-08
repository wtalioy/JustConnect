#include "ui_graphcaptchawindow.h"
#include "graphcaptchawindow.h"
#include <QEvent>
#include <QIcon>
#include <QStyle>

#include "captchacanvas.h"

#include <QBuffer>
#include <QImageReader>
#include "corelib/abi/constants.h"
#include <QJsonArray>
#include <QJsonObject>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>

GraphCaptchaWindow::GraphCaptchaWindow(QWidget *parent) : QDialog(parent), ui(new Ui::GraphCaptchaWindow)
{
    ui->setupUi(this);

    setWindowModality(Qt::WindowModal);
    setAttribute(Qt::WA_DeleteOnClose);
    auto *reset=ui->buttonBox->button(QDialogButtonBox::Reset);
    reset->setIcon(QIcon(":/resource/undo.svg"));reset->setIconSize(QSize(18,18));reset->setProperty("iconOnly",true);reset->setAutoDefault(false);reset->setFlat(true);
    reset->style()->unpolish(reset);reset->style()->polish(reset);
    updatePrompt();

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
    updatePrompt();
    ui->codeEdit->setVisible(textInputMode);
    ui->buttonBox->button(QDialogButtonBox::Reset)->setVisible(!textInputMode);
    if (textInputMode)
    {
        ui->codeEdit->clear();
        ui->codeEdit->setFocus();
    } else {
        ui->canvas->setFocus();
    }
}

void GraphCaptchaWindow::accept()
{
    if (ui->canvas->image().isNull())
    {
        QMessageBox::warning(this, tr("Image verification"), tr("The verification image could not be loaded. Retry the connection."));
        return;
    }

    if (textInputMode)
    {
        const QString code = ui->codeEdit->text().trimmed();
        if (code.isEmpty())
        {
            QMessageBox::warning(this, tr("Image verification"), tr("Enter the characters shown in the image."));
            ui->codeEdit->setFocus();
            return;
        }
        emit finishCaptcha({{"code", code}});
    }
    else
    {
        if (ui->canvas->pointsPx().isEmpty() || ui->canvas->pointsPx().size() > JC_MAX_AUTH_POINTS) {
            QMessageBox::warning(this, tr("Image verification"), tr("Select the points requested in the image."));
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

void GraphCaptchaWindow::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if (event->type()==QEvent::LanguageChange) {ui->retranslateUi(this);updatePrompt();}
}

void GraphCaptchaWindow::updatePrompt()
{
    auto *reset=ui->buttonBox->button(QDialogButtonBox::Reset);
    reset->setText({});reset->setToolTip(tr("Clear points"));reset->setAccessibleName(tr("Clear points"));
    ui->codeLabel->setVisible(true);
    ui->codeLabel->setText(textInputMode?tr("Enter the characters in the image."):tr("Select the requested points. Arrow keys move; Space selects."));
}
