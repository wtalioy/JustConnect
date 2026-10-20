#pragma once

#include "ui_graphcaptchawindow.h"
#include <QDialog>
#include <QJsonObject>

class GraphCaptchaWindow : public QDialog
{
    Q_OBJECT

public:
    GraphCaptchaWindow(QWidget *parent = nullptr);

    ~GraphCaptchaWindow() override;

    void setGraph(const QByteArray &image, bool textInputMode);

signals:
    void finishCaptcha(const QJsonObject &response);

public slots:
    void accept() override;

private:
    Ui::GraphCaptchaWindow *ui;
    bool textInputMode = false;
};
