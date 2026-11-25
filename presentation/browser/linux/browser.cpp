#include "presentation/browser/origin.h"
#include "presentation/browser/signinbrowser.h"

#include <QGuiApplication>
#include <QCoreApplication>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLoggingCategory>
#include <QPointer>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QScopeGuard>
#include <QSslCertificate>
#include <QTemporaryDir>
#include <QTimer>
#include <QtEndian>
#include <cstring>
#include <functional>
#include <memory>
#include <utility>

// Qt defines "signals"/"slots" as macros; GLib/GTK headers have struct members
// with the same name, so drop the Qt keyword macros before the GTK block. All
// Qt headers are already parsed above, and this file declares no Qt classes of
// its own. X11's "None" macro likewise only harms Qt headers, so Xlib comes
// after all of them and nothing Qt-related is included afterwards.
#undef signals
#undef slots

#include <gio/gio.h>
#include <gdk/gdkkeysyms.h>
#include <gdk/gdkx.h>
#include <gtk/gtk.h>
#include <jsc/jsc.h>
#include <webkit2/webkit2.h>
#if defined(GDK_WINDOWING_X11)
#include <X11/Xlib.h>
#endif

#if defined(JC_BROWSER_OPENSSL)
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

namespace {
Q_LOGGING_CATEGORY(browserLog,"justconnect.signin",QtWarningMsg)
}

// Defined before the callbacks: they read and mutate this state directly.
struct SignInBrowser::Native {
    Native(const QUrl &callback, TlsOptions policy) : callback(callback), tls(std::move(policy)) {}
    ~Native() {
        // X destroys child windows together with their parents, so park the
        // view window under the root before anything tears it down: Qt may
        // destroy a hidden dialog's platform window (xcb dummy windows), and
        // GTK's own destroy must stay the only X-side killer. Errors during
        // teardown are trapped instead of aborting the process.
        auto *display = gdk_display_get_default();
        const bool trap = display && GDK_IS_X11_DISPLAY(display);
        if (trap) gdk_x11_display_error_trap_push(display);
#if defined(GDK_WINDOWING_X11)
        if (view && trap) {
            if (GdkWindow *gdkWindow = gtk_widget_get_window(GTK_WIDGET(view))) {
                auto *xdisplay = gdk_x11_display_get_xdisplay(display);
                gdk_window_hide(gdkWindow);
                XReparentWindow(xdisplay, gdk_x11_window_get_xid(gdkWindow),
                    DefaultRootWindow(xdisplay), 0, 0);
                XSync(xdisplay, False);
            }
        }
#endif
        if (view) {
            gtk_widget_destroy(GTK_WIDGET(view));
            view = nullptr;
        }
        if (anchor) {
            gtk_widget_destroy(GTK_WIDGET(anchor));
            anchor = nullptr;
        }
        if (window) {
            gtk_widget_destroy(GTK_WIDGET(window));
            window = nullptr;
        }
        if (trap) gdk_x11_display_error_trap_pop_ignored(display);
        if (filterStore) g_object_unref(filterStore);
        if (context) g_object_unref(context);
    }

    const QUrl callback;
    const TlsOptions tls;
    std::function<bool(const QUrl &, bool)> navigation;
    WebKitWebContext *context = nullptr;
    WebKitWebView *view = nullptr;
    WebKitUserContentFilterStore *filterStore = nullptr;
    GtkWindow *anchor = nullptr; // Unmapped toplevel anchoring the view for X11 realization.
    GtkWindow *window = nullptr; // Separate-window fallback when embedding is unavailable.
    QLabel *hint = nullptr; // Fills the dialog when the page shows in a separate window.
    QTemporaryDir rulesDirectory;
    QUrl current, pending, topLoad;
    QString html;
    bool ready = false, failed = false, htmlPending = false, embedded = false, tlsExceptionRetried = false;
    bool loadCommitted = false;
};

namespace {
#if defined(JC_BROWSER_OPENSSL)
X509 *parseCertificate(const QByteArray &der)
{
    const auto *data = reinterpret_cast<const unsigned char *>(der.constData());
    return d2i_X509(nullptr, &data, long(der.size()));
}

// Verify the presented chain against the configured campus CA anchors and host name.
// Without this build option the custom-CA path fails closed; pages the system already trusts need no anchor.
bool trusted(const QList<QSslCertificate> &chain, const QString &host, const QString &caPem)
{
    if (caPem.isEmpty() || chain.isEmpty() || host.isEmpty()) return false;
    const auto leafDer = chain.first().toDer();
    X509 *leaf = parseCertificate(leafDer);
    if (!leaf) return false;
    const auto freeLeaf = qScopeGuard([&] { X509_free(leaf); });
    X509_STORE *store = X509_STORE_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    const auto release = qScopeGuard([&] {
        X509_STORE_CTX_free(context); sk_X509_pop_free(untrusted, X509_free);
        X509_STORE_free(store); ERR_clear_error();
    });
    if (!store || !untrusted || !context) return false;
    for (const auto &anchor : QSslCertificate::fromData(caPem.toUtf8(), QSsl::Pem)) {
        X509 *parsed = parseCertificate(anchor.toDer());
        if (!parsed) return false;
        X509_STORE_add_cert(store, parsed);
        X509_free(parsed);
    }
    for (const auto &intermediate : chain.mid(1)) {
        X509 *parsed = parseCertificate(intermediate.toDer());
        if (!parsed) return false;
        sk_X509_push(untrusted, parsed);
    }
    X509_STORE_CTX_init(context, store, leaf, untrusted);
    const auto parameter = X509_STORE_CTX_get0_param(context);
    if (X509_VERIFY_PARAM_set_purpose(parameter, X509_PURPOSE_SSL_SERVER) != 1) return false;
    // Campus gateways are reached by address, so an IP host must match the iPAddress SAN
    // instead of OpenSSL's dNSName-only host comparison.
    const QHostAddress address(host);
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        const auto raw = qToBigEndian(address.toIPv4Address());
        if (X509_VERIFY_PARAM_set1_ip(parameter, reinterpret_cast<const unsigned char *>(&raw), sizeof(raw)) != 1) return false;
    } else if (address.protocol() == QAbstractSocket::IPv6Protocol) {
        const auto bytes = address.toIPv6Address();
        if (X509_VERIFY_PARAM_set1_ip(parameter, bytes.c, sizeof(bytes.c)) != 1) return false;
    } else {
        const auto utf8Host = host.toUtf8();
        if (X509_VERIFY_PARAM_set1_host(parameter, utf8Host.constData(), 0) != 1) return false;
    }
    const int verified = X509_verify_cert(context);
    return verified == 1;
}
#else
bool trusted(const QList<QSslCertificate> &, const QString &, const QString &)
{
    return false;
}
#endif

QUrl uriToUrl(const gchar *uri)
{
    return QUrl(QString::fromUtf8(uri ? uri : ""));
}

// Mirror the desktop backends: the result callback receives real QVariant
// values (bool/number/string/list/map). Bare scalars are not valid roots for
// QJsonDocument, so primitives come from the JSC value and only aggregates go
// through the JSON round trip.
QVariant jscToVariant(JSCValue *value)
{
    if (!value || jsc_value_is_null(value) || jsc_value_is_undefined(value)) return {};
    // jsc_value_to_boolean returns gboolean (int), which QVariant would store
    // as an integer, so the boolean conversion is explicit.
    if (jsc_value_is_boolean(value)) return QVariant(jsc_value_to_boolean(value) != FALSE);
    if (jsc_value_is_number(value)) return QVariant(jsc_value_to_double(value));
    if (jsc_value_is_string(value)) return QVariant(QString::fromUtf8(jsc_value_to_string(value)));
    if (char *json = jsc_value_to_json(value, 0)) {
        const auto document = QJsonDocument::fromJson(QByteArray(json));
        g_free(json);
        if (document.isArray()) return document.array().toVariantList();
        if (document.isObject()) return document.object().toVariantMap();
    }
    return {};
}

// GLib keeps the DER bytes in the "certificate" boxed property; 2.84 ships no getter.
GByteArray *certificateDer(GTlsCertificate *certificate)
{
    GValue value = G_VALUE_INIT;
    g_value_init(&value, G_TYPE_BYTE_ARRAY);
    g_object_get_property(G_OBJECT(certificate), "certificate", &value);
    auto *der = static_cast<GByteArray *>(g_value_dup_boxed(&value));
    g_value_unset(&value);
    return der;
}

// The certificate chain presented by the gateway, leaf first.
QList<QSslCertificate> tlsChain(GTlsCertificate *certificate)
{
    QList<QSslCertificate> chain;
    for (GTlsCertificate *node = certificate; node; node = g_tls_certificate_get_issuer(node)) {
        GByteArray *der = certificateDer(node);
        if (!der || !der->len) { if (der) g_byte_array_unref(der); break; }
        chain.append(QSslCertificate(QByteArray(reinterpret_cast<const char *>(der->data), int(der->len)), QSsl::Der));
        g_byte_array_unref(der);
    }
    return chain;
}

void initializeFailed(SignInBrowser *self)
{
    auto *native = SignInBrowser::nativeOf(self);
    if (!native || native->failed) return;
    native->failed = true;
    emit self->initializationFailed();
    emit self->loadFinished(false);
}

void flushPending(SignInBrowser *self)
{
    auto *native = SignInBrowser::nativeOf(self);
    native->ready = true;
    if (native->htmlPending) self->setHtml(native->html);
    else if (!native->pending.isEmpty()) self->load(native->pending);
}
}

namespace {
// Mirror the WebView2 resource filter and the macOS content blockers: without a
// verified gateway certificate, only the callback origin may use the granted
// certificate exception, and nothing on the gateway host escapes its scope.
struct FilterJob {
    QPointer<SignInBrowser> self;
    WebKitUserContentManager *manager = nullptr; // owned by the view
    WebKitUserContentFilterStore *store = nullptr;
};

void onFilterSaved(GObject *source, GAsyncResult *asyncResult, gpointer userData)
{
    const std::unique_ptr<FilterJob> job(static_cast<FilterJob *>(userData));
    // The job owns its own store reference (see compileScopeRules), so this
    // release is safe however teardown interleaves with the async save.
    g_object_unref(job->store);
    const auto self = job->self;
    if (!self) return;
    GError *error = nullptr;
    WebKitUserContentFilter *filter = webkit_user_content_filter_store_save_finish(
        WEBKIT_USER_CONTENT_FILTER_STORE(source), asyncResult, &error);
    // add_filter takes its own reference; this one is ours to drop.
    const auto release = qScopeGuard([&] {
        if (error) g_error_free(error);
        if (filter) webkit_user_content_filter_unref(filter);
    });
    if (!filter) {
        qCDebug(browserLog) << "scope rules rejected" << (error ? error->message : "unknown");
        initializeFailed(self.data());
        return;
    }
    webkit_user_content_manager_add_filter(job->manager, filter);
    flushPending(self.data());
}

void compileScopeRules(SignInBrowser *self)
{
    auto *native = SignInBrowser::nativeOf(self);
    const auto &callback = native->callback;
    const auto hostname = callback.host().contains(':') ? "[" + callback.host() + "]"
        : QString::fromLatin1(QUrl::toAce(callback.host()));
    const auto hostPattern = QRegularExpression::escape(hostname);
    const auto prefix = "^" + callback.scheme() + "://([^/]*@)?" + hostPattern;
    const int defaultPort = callback.scheme() == "https" ? 443 : 80;
    const int port = callback.port(defaultPort);
    // Content filters exclude regex alternation; canonical HTTP URLs include the path slash.
    const auto allowed = prefix + (port == defaultPort ? "(:" + QString::number(port) + ")?"
        : ":" + QString::number(port)) + "/";
    const QJsonArray rules{
        QJsonObject{{"trigger", QJsonObject{{"url-filter", "^https?://([^/]*@)?" + hostPattern + "[:/]"}}},
            {"action", QJsonObject{{"type", "block"}}}},
        QJsonObject{{"trigger", QJsonObject{{"url-filter", allowed}}},
            {"action", QJsonObject{{"type", "ignore-previous-rules"}}}}
    };
    auto *store = webkit_user_content_filter_store_new(
        native->rulesDirectory.path().toUtf8().constData());
    native->filterStore = store;
    const auto json = QJsonDocument(rules).toJson(QJsonDocument::Compact);
    auto *source = g_bytes_new_take(g_memdup2(json.constData(), json.size()), json.size());
    // The job holds its own store reference: the Native's reference covers the
    // dialog lifetime, the callback's covers the async save, independently.
    auto *job = new FilterJob{self, webkit_web_view_get_user_content_manager(native->view),
        static_cast<WebKitUserContentFilterStore *>(g_object_ref(store))};
    webkit_user_content_filter_store_save(store, "signin-certificate-scope", source, nullptr,
        &onFilterSaved, job);
    g_bytes_unref(source);
}

// Final answer for a classified navigation: the host policy decides, and a
// rejected main-frame navigation reports a failed load because WebKit emits no
// completion for ignored decisions.
void applyNavigationPolicy(SignInBrowser *self, WebKitPolicyDecision *decision, const QUrl &target, bool main)
{
    auto *native = SignInBrowser::nativeOf(self);
    const bool allowed = native->navigation && native->navigation(target, main);
    if (allowed) { webkit_policy_decision_use(decision); return; }
    if (main) {
        qCDebug(browserLog) << "navigation rejected" << main;
        const QPointer<SignInBrowser> guard(self);
        QTimer::singleShot(0, self, [guard] { if (guard) emit guard->loadFinished(false); });
    }
    webkit_policy_decision_ignore(decision);
}

// WebKitGTK reports a null frame name for both the main frame and unnamed
// iframes, and initial navigations carry no Sec-Fetch-Dest, so the target can
// stay ambiguous. Ask the live document (the navigation has not committed yet):
// a page without any iframe cannot host a frame load, so the navigation must
// be the main frame; a page that contains frames stays ambiguous and fails
// closed as a frame load, so an ambiguous callback can never complete
// sign-in. The decision stays pending until the census answers, so the
// decision keeps an owned reference: WebKit releases it once the signal
// handler returns.
void probeFrameIdentity(SignInBrowser *self, WebKitPolicyDecision *decision, const QUrl &target)
{
    g_object_ref(decision);
    const auto script = QStringLiteral(
        "(function(){return document.querySelectorAll('iframe').length"
        " ? \"ambiguous\" : \"main\"})()");
    const QPointer<SignInBrowser> guard(self);
    self->runJavaScript(script, [guard, decision, target](const QVariant &result) {
        const auto release = qScopeGuard([decision] { g_object_unref(decision); });
        // Only the census verdict "main" classifies the navigation as the main
        // frame; any other answer (a page with frames, evaluate error, null)
        // fails closed as a frame load.
        const bool main = result.metaType() == QMetaType::fromType<QString>()
            && result.toString() == QLatin1String("main");
        if (!guard) return;
        applyNavigationPolicy(guard.data(), decision, target, main);
    });
}

gboolean onDecidePolicy(WebKitWebView *, WebKitPolicyDecision *decision, WebKitPolicyDecisionType type, gpointer data)
{
    auto *self = static_cast<SignInBrowser *>(data);
    auto *native = SignInBrowser::nativeOf(self);
    switch (type) {
    case WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION: {
        auto *action = webkit_navigation_policy_decision_get_navigation_action(
            WEBKIT_NAVIGATION_POLICY_DECISION(decision));
        const QUrl target(uriToUrl(webkit_uri_request_get_uri(webkit_navigation_action_get_request(action))));
        if (native->htmlPending) {
            // setHtml's internal load bypasses the navigation policy.
            native->htmlPending = false;
            webkit_policy_decision_use(decision);
            return TRUE;
        }
        if (target.scheme() == "about" && (target.path() == "blank" || target.path() == "srcdoc")) {
            // Blank documents carry no data; the desktop backends allow them for
            // non-main frames and WebKitGTK cannot report the frame here.
            webkit_policy_decision_use(decision);
            return TRUE;
        }
        // WebKitGTK reports a null frame name for both the main frame and
        // unnamed iframes. The frame identity comes from the remaining
        // signals: redirect continuations carry Sec-Fetch-Dest, whose value
        // separates the main frame ("document") from subframes ("iframe",
        // so a redirected iframe can never borrow the main-frame identity);
        // named targets are frames; reloads and history moves are the
        // dialog's own main-frame controls; user-driven actions are never
        // frame loads; an explicit load() call targets the main frame; and
        // whatever stays ambiguous goes through the census probe.
        const gchar *frameName = webkit_navigation_action_get_frame_name(action);
        SoupMessageHeaders *headers = webkit_uri_request_get_http_headers(
            webkit_navigation_action_get_request(action));
        const gchar *dest = headers ? soup_message_headers_get_one(headers, "Sec-Fetch-Dest") : nullptr;
        const auto navigationType = webkit_navigation_action_get_navigation_type(action);
        bool main;
        if (frameName) main = false;
        else if (dest) main = QLatin1String(dest) == "document";
        else if (navigationType == WEBKIT_NAVIGATION_TYPE_RELOAD
            || navigationType == WEBKIT_NAVIGATION_TYPE_BACK_FORWARD) main = true;
        else if (webkit_navigation_action_is_user_gesture(action)
            && navigationType != WEBKIT_NAVIGATION_TYPE_OTHER) main = true;
        else if (target == native->topLoad) main = true;
        else {
            probeFrameIdentity(self, decision, target);
            return TRUE;
        }
        applyNavigationPolicy(self, decision, target, main);
        return TRUE;
    }
    case WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION:
        // The dialog owns exactly one view; new windows and targets are dropped.
        webkit_policy_decision_ignore(decision);
        return TRUE;
    case WEBKIT_POLICY_DECISION_TYPE_RESPONSE:
        return FALSE; // Default decision: use the response.
    default:
        return FALSE;
    }
}

void onLoadChanged(WebKitWebView *view, WebKitLoadEvent event, gpointer data)
{
    auto *self = static_cast<SignInBrowser *>(data);
    if (!self) return;
    auto *native = SignInBrowser::nativeOf(self);
    switch (event) {
    case WEBKIT_LOAD_STARTED: {
        // The explicit load() target has been consumed; later navigation
        // decisions classify through their own signals.
        native->topLoad.clear();
        native->loadCommitted = false;
        emit self->loadStarted();
        break;
    }
    case WEBKIT_LOAD_COMMITTED: {
        const QUrl target(uriToUrl(webkit_web_view_get_uri(view)));
        native->current = target;
        native->tlsExceptionRetried = false;
        native->loadCommitted = true;
        emit self->urlChanged(target);
        break;
    }
    case WEBKIT_LOAD_FINISHED:
        // WebKit also finishes ignored and failed provisional navigations.
        if (std::exchange(native->loadCommitted, false)) emit self->loadFinished(true);
        break;
    default:
        break;
    }
}

gboolean onLoadFailed(WebKitWebView *, WebKitLoadEvent, const gchar *failingUri, GError *error, gpointer data)
{
    auto *self = static_cast<SignInBrowser *>(data);
    if (!self) return FALSE;
    SignInBrowser::nativeOf(self)->loadCommitted = false;
    // Policy interruptions and superseded navigations already have a decision.
    if (error && (g_error_matches(error, webkit_network_error_quark(), WEBKIT_NETWORK_ERROR_CANCELLED)
        || error->domain == webkit_policy_error_quark())) return TRUE;
    emit self->loadFinished(false);
    return TRUE;
}

gboolean onLoadFailedWithTlsErrors(WebKitWebView *view, const gchar *failing_uri,
    GTlsCertificate *certificate, GTlsCertificateFlags, gpointer data)
{
    auto *self = static_cast<SignInBrowser *>(data);
    if (!self) return FALSE;
    auto *native = SignInBrowser::nativeOf(self);
    const QUrl target(uriToUrl(failing_uri));
    const auto &tls = native->tls;
    // Mirror the Qt page: an unverified gateway origin accepts its own exception,
    // a verified one only chains that verify against the campus CA anchors.
    const bool okay = !tls.verify ? BrowserOrigin::same(target, native->callback)
        : trusted(tlsChain(certificate), target.host(), tls.caPem);
    // Callback redirects carry authorization tokens in their query; the log
    // keeps the origin so failures stay diagnosable without leaking them.
    qCDebug(browserLog) << "certificate error" << target.scheme() + "://" + target.host()
        + ":" + QString::number(target.port(target.scheme() == "https" ? 443 : 80)) << okay;
    native->loadCommitted = false;
    if (!okay || native->tlsExceptionRetried) {
        emit self->certificateRejected();
        emit self->loadFinished(false);
        return TRUE;
    }
    // The exception is scoped to this host: nothing on other ports or schemes
    // can reuse it, because the scope rules block the request before TLS.
    webkit_web_context_allow_tls_certificate_for_host(native->context, certificate,
        target.host().toUtf8().constData());
    // Reload would reuse the last committed document, not the failed URL.
    native->tlsExceptionRetried = true;
    webkit_web_view_load_uri(view, failing_uri);
    return TRUE;
}

void onWebProcessTerminated(WebKitWebView *, WebKitWebProcessTerminationReason, gpointer data)
{
    auto *self = static_cast<SignInBrowser *>(data);
    auto *native = SignInBrowser::nativeOf(self);
    if (!native || native->failed) return;
    native->failed = true;
    emit self->initializationFailed();
    emit self->loadFinished(false);
}

gboolean onKeyPress(GtkWidget *, GdkEventKey *event, gpointer data)
{
    auto *self = static_cast<SignInBrowser *>(data);
    if (self && (event->state & GDK_CONTROL_MASK) && event->keyval == GDK_KEY_l) {
        emit self->addressFocusRequested();
        return TRUE;
    }
    return FALSE;
}

#if defined(GDK_WINDOWING_X11)
// X11 embedding: a bare WebKitWebView has no GdkWindow until it is anchored in
// a toplevel, and GTK only paints windows it considers on-screen (viewable
// through its own parent chain). The anchor is therefore a mapped
// override-redirect window parked far offscreen: invisible to the compositor,
// but keeping the view viewable so its rendering reaches the X window that is
// reparented into the Qt widget.
void embedX11(SignInBrowser *self)
{
    auto *native = SignInBrowser::nativeOf(self);
    // Qt reports logical widget sizes; GDK3 X11 windows live in physical pixels.
    // Scale by the device pixel ratio so the view fills the Qt window on
    // scaled desktops instead of painting a corner-sized page.
    const auto physical = [self](int logical) {
        return qRound(logical * self->devicePixelRatioF());
    };
    if (!native->anchor) {
        const int w = self->width() > 0 ? physical(self->width()) : 900;
        const int h = self->height() > 0 ? physical(self->height()) : 600;
        native->anchor = GTK_WINDOW(gtk_window_new(GTK_WINDOW_POPUP));
        // The anchor must match the view size: GTK allocates children to the
        // toplevel's content area when it maps, and WebKit renders at its
        // allocated size. A tiny anchor would shrink the page surface even
        // though the reparented X window is full-size.
        gtk_window_set_default_size(native->anchor, w, h);
        gtk_container_add(GTK_CONTAINER(native->anchor), GTK_WIDGET(native->view));
        gtk_widget_realize(GTK_WIDGET(native->anchor));
        gtk_widget_realize(GTK_WIDGET(native->view));
        gtk_window_move(native->anchor, -32000, -32000);
        gtk_widget_show(GTK_WIDGET(native->anchor));
    }
    GdkWindow *gdkWindow = gtk_widget_get_window(GTK_WIDGET(native->view));
    if (!gdkWindow || !GDK_IS_X11_WINDOW(gdkWindow)) return;
    Display *display = gdk_x11_display_get_xdisplay(gdk_window_get_display(gdkWindow));
    const Window child = gdk_x11_window_get_xid(gdkWindow);
    XReparentWindow(display, child, static_cast<Window>(self->winId()), 0, 0);
    XSync(display, False);
    native->embedded = true;
    // GTK's own visibility state gates WebKit's painting pipeline; map the
    // widget through GTK instead of touching the X window behind its back.
    gtk_widget_show(GTK_WIDGET(native->view));
    // A window manager's manage sequence (mutter parks new windows in
    // IconicState for a moment) surfaces in Qt as a spurious
    // minimize/restore cycle right after the dialog appears, which hides and
    // re-shows this widget. On the restore GTK still considers the view
    // visible, so gtk_widget_show() above is a no-op and the view's X window
    // would stay unmapped - a permanently white page. Map the GdkWindow
    // explicitly; it is a no-op when the window is already mapped.
    gdk_window_show(gdkWindow);
    // Make the view the anchor's GTK focus widget: when XWayland hands the X
    // input focus straight to the reparented view window (pointer over the
    // page), GTK routes those keys through the anchor's focus chain and drops
    // them if no widget is focused. WebKit also needs this for its IM context.
    gtk_widget_grab_focus(GTK_WIDGET(native->view));
    // A popup anchor auto-sizes to its requisition and GTK reallocates the
    // view when the anchor maps; without an explicit allocation WebKit lays
    // out at 1x1 while the reparented X window is full-size, leaving the rest
    // of the window never painted.
    GtkAllocation allocation{0, 0, physical(self->width()), physical(self->height())};
    gtk_widget_size_allocate(GTK_WIDGET(native->view), &allocation);
    gdk_window_move_resize(gdkWindow, 0, 0, physical(self->width()), physical(self->height()));
}
#endif
}

SignInBrowser::SignInBrowser(QWidget *parent, const QUrl &callbackUrl, const TlsOptions &tls, NavigationPolicy navigation)
    : QWidget(parent), native(std::make_unique<Native>(callbackUrl, tls))
{
    setFocusPolicy(Qt::StrongFocus); setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    qCDebug(browserLog) << "webkit start";
    native->navigation = navigation;
    // Match GTK's backend to the Qt platform: X11 embedding needs an X11 GDK
    // window, while a Wayland session without XWayland still needs GTK Wayland
    // so the separate-window fallback can open. Must run before gtk_init_check.
    if (QGuiApplication::platformName() == "xcb") gdk_set_allowed_backends("x11");
    if (!gtk_init_check(nullptr, nullptr)) {
        initializeFailed(this);
        return;
    }
    // One off-the-record context per window: no disk storage and no cookie sharing between dialogs.
    native->context = webkit_web_context_new_ephemeral();
    native->view = WEBKIT_WEB_VIEW(webkit_web_view_new_with_context(native->context));
    g_signal_connect(native->view, "decide-policy", G_CALLBACK(&onDecidePolicy), this);
    g_signal_connect(native->view, "load-changed", G_CALLBACK(&onLoadChanged), this);
    g_signal_connect(native->view, "load-failed", G_CALLBACK(&onLoadFailed), this);
    g_signal_connect(native->view, "load-failed-with-tls-errors", G_CALLBACK(&onLoadFailedWithTlsErrors), this);
    g_signal_connect(native->view, "web-process-terminated", G_CALLBACK(&onWebProcessTerminated), this);
    g_signal_connect(native->view, "key-press-event", G_CALLBACK(&onKeyPress), this);
    g_signal_connect(native->view, "button-press-event",
        G_CALLBACK(+[](GtkWidget *, GdkEventButton *, gpointer data) -> gboolean {
            // Clicks land on the view's own X window, so Qt never sees them;
            // pull Qt focus to this widget so its key events can be forwarded
            // to the page. Returning FALSE lets WebKit handle the click too.
            static_cast<SignInBrowser *>(data)->setFocus(Qt::MouseFocusReason);
            return FALSE;
        }), this);
    if (tls.verify) {
        native->ready = true;
        return;
    }
    compileScopeRules(this);
}

SignInBrowser::~SignInBrowser()
{
    blockSignals(true);
}

void SignInBrowser::load(const QUrl &target)
{
    qCDebug(browserLog) << "load requested" << target.isEmpty();
    native->pending = target; native->htmlPending = false;
    native->tlsExceptionRetried = false;
    // An explicit load always targets the main frame; record it so the policy
    // decision recognizes the main-frame load that WebKitGTK cannot label.
    native->topLoad = target;
    if (native->failed) { QTimer::singleShot(0, this, [this] { emit initializationFailed(); emit loadFinished(false); }); return; }
    if (native->ready && native->view && !target.isEmpty())
        webkit_web_view_load_uri(native->view, target.toEncoded().constData());
}

QUrl SignInBrowser::url() const { return native->current; }
void SignInBrowser::back() { if (native->view) webkit_web_view_go_back(native->view); }
void SignInBrowser::forward() { if (native->view) webkit_web_view_go_forward(native->view); }
void SignInBrowser::reload() { if (native->view) webkit_web_view_reload(native->view); }

void SignInBrowser::setHtml(const QString &html)
{
    qCDebug(browserLog) << "html requested" << bool(native->view);
    native->html = html; native->htmlPending = true;
    if (native->failed) { QTimer::singleShot(0, this, [this] { emit initializationFailed(); emit loadFinished(false); }); return; }
    if (native->ready && native->view) webkit_web_view_load_html(native->view, html.toUtf8().constData(), nullptr);
}

void SignInBrowser::runJavaScript(const QString &script, std::function<void(const QVariant &)> result)
{
    if (!native->view) { result({}); return; }
    const auto bytes = script.toUtf8();
    struct Call { std::function<void(const QVariant &)> result; };
    auto *call = new Call{std::move(result)};
    webkit_web_view_evaluate_javascript(native->view, bytes.constData(), bytes.size(),
        nullptr, nullptr, nullptr,
        [](GObject *source, GAsyncResult *asyncResult, gpointer data) {
            const std::unique_ptr<Call> call(static_cast<Call *>(data));
            GError *error = nullptr;
            JSCValue *value = webkit_web_view_evaluate_javascript_finish(WEBKIT_WEB_VIEW(source), asyncResult, &error);
            if (error) qCDebug(browserLog) << "script error" << error->message;
            const QVariant out = value ? jscToVariant(value) : QVariant();
            if (error) g_error_free(error);
            if (value) g_object_unref(value);
            call->result(out);
        }, call);
}

void SignInBrowser::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    if (!native->view) return;
    if (native->hint) native->hint->setGeometry(rect());
#if defined(GDK_WINDOWING_X11)
    if (native->embedded) {
        // Keep the GTK allocation in step so WebKit lays out at the new size;
        // GDK3 X11 needs physical pixels, Qt reports logical ones.
        const auto physical = [this](int logical) {
            return qRound(logical * devicePixelRatioF());
        };
        GtkAllocation allocation{0, 0, physical(width()), physical(height())};
        gtk_widget_size_allocate(GTK_WIDGET(native->view), &allocation);
        if (GdkWindow *gdkWindow = gtk_widget_get_window(GTK_WIDGET(native->view)))
            gdk_window_move_resize(gdkWindow, 0, 0, physical(width()), physical(height()));
        return;
    }
#endif
    if (native->window) gtk_window_resize(native->window, width(), height());
}

void SignInBrowser::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);
    if (!native->view || native->failed) return;
#if defined(GDK_WINDOWING_X11)
    if (!native->embedded && QGuiApplication::platformName() == "xcb") {
        embedX11(this);
        if (native->embedded) {
            // The page is the dialog's primary input target; give it the Qt
            // focus right away so typing works before any click. Without this
            // the initial focus lands on the first tab-order widget (the
            // address bar) and early keystrokes never reach the page.
            this->setFocus(Qt::OtherFocusReason);
            return;
        }
    }
#endif
    // Fallback (native Wayland sessions: Wayland forbids cross-toolkit window
    // embedding): show the browser in its own window and explain the empty
    // dialog area. The X11 anchor is no longer useful once the view moved.
    if (!native->window) {
        native->window = GTK_WINDOW(gtk_window_new(GTK_WINDOW_TOPLEVEL));
        gtk_window_set_title(native->window, "JustConnect");
        gtk_window_set_default_size(native->window, 900, 600);
        if (native->anchor) {
            // The view is still GTK-childed by the anchor; move it out first,
            // since destroying the anchor would destroy the view with it.
            g_object_ref(GTK_WIDGET(native->view));
            gtk_container_remove(GTK_CONTAINER(native->anchor), GTK_WIDGET(native->view));
            gtk_widget_destroy(GTK_WIDGET(native->anchor));
            native->anchor = nullptr;
            gtk_container_add(GTK_CONTAINER(native->window), GTK_WIDGET(native->view));
            g_object_unref(GTK_WIDGET(native->view));
        } else {
            gtk_container_add(GTK_CONTAINER(native->window), GTK_WIDGET(native->view));
        }
    }
    if (!native->hint) {
        native->hint = new QLabel(this);
        native->hint->setWordWrap(true);
        native->hint->setAlignment(Qt::AlignCenter);
        native->hint->setText(QCoreApplication::translate("SignInBrowser",
            "The sign-in page cannot be embedded in this desktop session and opened in a separate window instead. Complete the sign-in there."));
    }
    native->hint->setGeometry(rect());
    native->hint->show();
    native->hint->raise();
    gtk_widget_show_all(GTK_WIDGET(native->window));
}

void SignInBrowser::hideEvent(QHideEvent *event)
{
    QWidget::hideEvent(event);
    if (!native->view) return;
#if defined(GDK_WINDOWING_X11)
    if (native->embedded) {
        if (GdkWindow *gdkWindow = gtk_widget_get_window(GTK_WIDGET(native->view))) {
            auto *display = gdk_window_get_display(gdkWindow);
            auto *xdisplay = gdk_x11_display_get_xdisplay(display);
            // Qt's xcb backend destroys a hidden top-level's platform window,
            // and X kills reparented children with it. Park the view window
            // under the root; showEvent re-embeds it into the new Qt window.
            gdk_window_hide(gdkWindow);
            XReparentWindow(xdisplay, gdk_x11_window_get_xid(gdkWindow),
                DefaultRootWindow(xdisplay), 0, 0);
            XSync(xdisplay, False);
            native->embedded = false;
        }
        return;
    }
#endif
    if (native->window) gtk_widget_hide(GTK_WIDGET(native->window));
}

void SignInBrowser::focusInEvent(QFocusEvent *event)
{
    QWidget::focusInEvent(event);
    if (!native->view) return;
    // No X-side focus is moved in either mode: under XWayland the compositor
    // owns the X input focus and moving it away from the Qt window would stop
    // Qt from receiving keyboard events entirely. Embedded mode forwards the
    // Qt key events instead (see event()), and the fallback window grabs the
    // GTK focus through its own toolkit.
    if (native->window) gtk_widget_grab_focus(GTK_WIDGET(native->view));
}

// X11 embedding: Qt owns the X input focus (under XWayland the compositor
// mediates it, and a GTK window cannot take it without cutting Qt off), so the
// page receives keyboard input by translating Qt key events to GdkEventKey and
// dispatching them to the WebKit view directly. Intercepting in event() also
// keeps Tab/Backtab for the page's own focus navigation instead of Qt's.
bool SignInBrowser::event(QEvent *event)
{
#if defined(GDK_WINDOWING_X11)
    // X11/X.h defines KeyPress/KeyRelease as numeric event-type macros that
    // clobber the Qt enum names; lift them for this scope and restore.
#pragma push_macro("KeyPress")
#pragma push_macro("KeyRelease")
#undef KeyPress
#undef KeyRelease
    if (native->embedded && native->view
        && (event->type() == QEvent::KeyPress || event->type() == QEvent::KeyRelease)) {
        auto *key = static_cast<QKeyEvent *>(event);
        if (GdkWindow *gdkWindow = gtk_widget_get_window(GTK_WIDGET(native->view))) {
            GdkEventKey translated;
            std::memset(&translated, 0, sizeof(translated));
            translated.type = key->type() == QEvent::KeyPress ? GDK_KEY_PRESS : GDK_KEY_RELEASE;
            translated.window = gdkWindow;
            translated.send_event = TRUE;
            translated.time = key->timestamp();
            // xcb reports the X keysym in nativeVirtualKey; fall back to the
            // text's first character (keysyms of Latin-1 match Unicode) for
            // synthetic events that carry no native key data.
            translated.keyval = key->nativeVirtualKey();
            if (!translated.keyval && !key->text().isEmpty())
                translated.keyval = key->text().at(0).unicode();
            translated.hardware_keycode = static_cast<guint16>(key->nativeScanCode());
            int state = 0;
            if (key->modifiers() & Qt::ShiftModifier) state |= GDK_SHIFT_MASK;
            if (key->modifiers() & Qt::ControlModifier) state |= GDK_CONTROL_MASK;
            if (key->modifiers() & Qt::AltModifier) state |= GDK_MOD1_MASK;
            if (key->modifiers() & Qt::MetaModifier) state |= GDK_MOD4_MASK;
            translated.state = static_cast<guint>(state);
            translated.group = 0;
            translated.is_modifier = (key->key() == Qt::Key_Shift || key->key() == Qt::Key_Control
                || key->key() == Qt::Key_Alt || key->key() == Qt::Key_Meta) ? TRUE : FALSE;
            gboolean handled = FALSE;
            g_signal_emit_by_name(native->view,
                key->type() == QEvent::KeyPress ? "key-press-event" : "key-release-event",
                &translated, &handled);
            if (handled == TRUE) return true;
        }
    }
#pragma pop_macro("KeyPress")
#pragma pop_macro("KeyRelease")
#endif
    return QWidget::event(event);
}
