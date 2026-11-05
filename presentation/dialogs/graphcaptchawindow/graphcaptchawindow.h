#pragma once

namespace Ui { class GraphCaptchaWindow; }
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

protected:
    void changeEvent(QEvent *event) override;

private:
    void updatePrompt();
    Ui::GraphCaptchaWindow *ui;
    bool textInputMode = false;
};
