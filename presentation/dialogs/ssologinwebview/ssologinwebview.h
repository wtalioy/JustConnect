#ifndef SSOLOGINWEBVIEW_H
#define SSOLOGINWEBVIEW_H

#include <QDialog>
#include <QUrl>
#include <QString>
#include "core/connectionprofile.h"

namespace Ui
{
class SsoLoginWebView;
}

class SsoLoginWebView : public QDialog
{
    Q_OBJECT

public:
    explicit SsoLoginWebView(QWidget *parent,const QUrl &callback,const TlsOptions &tls={});
    ~SsoLoginWebView() override;

    void setInitialUrl(const QUrl &url);

signals:
    void loginCompleted(const QString &url);

protected:
    void changeEvent(QEvent *event) override;

private:
    void setupConnections();
    void showNavigationError();
    void updateWarning();
    enum class NavigationFailure { None, Address, Certificate };
    NavigationFailure failure=NavigationFailure::None;
    bool isCallbackUrl(const QUrl &url) const;
    bool isAllowedUrl(const QUrl &url) const;

    Ui::SsoLoginWebView *ui;
    const QUrl callbackUrl;
    const TlsOptions tls;
    bool loginCompletedEmitted = false;
};

#endif // SSOLOGINWEBVIEW_H
