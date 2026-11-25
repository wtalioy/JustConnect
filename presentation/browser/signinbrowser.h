#pragma once

#include "core/connectionoptions.h"
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

    // The per-platform translation unit defines Native and owns all browser
    // state; it drives this class from native callbacks, which are plain
    // functions rather than members. The type stays incomplete outside that
    // file, so the accessor cannot leak state to other code.
    struct Native;
    static Native *nativeOf(SignInBrowser *self) { return self ? self->native.get() : nullptr; }

signals:
    void loadStarted();
    void loadFinished(bool success);
    void urlChanged(const QUrl &url);
    void certificateRejected();
    void initializationFailed();
    void addressFocusRequested();

protected:
#ifdef Q_OS_LINUX
    bool event(QEvent *) override;
#endif
    void resizeEvent(QResizeEvent *) override;
    void showEvent(QShowEvent *) override;
    void hideEvent(QHideEvent *) override;
    void focusInEvent(QFocusEvent *) override;

private:
    std::unique_ptr<Native> native;
};
