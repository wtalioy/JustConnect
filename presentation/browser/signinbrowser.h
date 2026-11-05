#pragma once

#include "core/connectionprofile.h"
#include <QWidget>
#include <QUrl>
#include <QVariant>
#include <functional>
#include <memory>

// Each window owns an ephemeral native browser and an immutable trust policy.
class SignInBrowser final : public QWidget {
    Q_OBJECT
public:
    using NavigationPolicy=std::function<bool(const QUrl &,bool)>;
    SignInBrowser(QWidget *parent,const QUrl &callbackUrl,const TlsOptions &tls,NavigationPolicy navigation);
    ~SignInBrowser() override;
    void load(const QUrl &url);
    QUrl url() const;
    void back();
    void forward();
    void reload();
    void runJavaScript(const QString &script,std::function<void(const QVariant &)> result);
    void setHtml(const QString &html);

signals:
    void loadStarted();
    void loadFinished(bool success);
    void urlChanged(const QUrl &url);
    void certificateRejected();
    void initializationFailed();
    void addressFocusRequested();

protected:
    void resizeEvent(QResizeEvent *) override;
    void showEvent(QShowEvent *) override;
    void hideEvent(QHideEvent *) override;
    void focusInEvent(QFocusEvent *) override;

private:
    struct Native;
    std::unique_ptr<Native> native;
};
