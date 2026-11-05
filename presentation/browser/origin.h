#pragma once
#include <QUrl>

namespace BrowserOrigin {
inline bool same(const QUrl &a,const QUrl &b) {
    const auto port=[](const QUrl &url){return url.port(url.scheme()=="https"?443:80);};
    return a.scheme()==b.scheme() && a.host().compare(b.host(),Qt::CaseInsensitive)==0 && port(a)==port(b);
}
inline bool escapesCertificateScope(const QUrl &url,const QUrl &gateway) {
    return url.host().compare(gateway.host(),Qt::CaseInsensitive)==0 && !same(url,gateway);
}
}
