#ifndef SSOLOGINWEBVIEW_H
#define SSOLOGINWEBVIEW_H

#include <QDialog>
#include <QUrl>
#include <QString>

namespace Ui
{
class SsoLoginWebView;
}

class SsoLoginWebView : public QDialog
{
    Q_OBJECT

public:
    explicit SsoLoginWebView(QWidget *parent = nullptr);
    ~SsoLoginWebView() override;

    void setInitialUrl(const QUrl &url);
    void setCallbackUrl(const QUrl &url);

signals:
    void loginCompleted(const QString &url);

private:
    void setupConnections();
    bool isCallbackUrl(const QUrl &url) const;
    bool isAllowedUrl(const QUrl &url) const;

    Ui::SsoLoginWebView *ui;
    QUrl callbackUrl;
    bool loginCompletedEmitted = false;
};

#endif // SSOLOGINWEBVIEW_H
