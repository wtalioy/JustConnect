#include "infrastructure/systemproxy/proxychanges.h"
#include <QWinEventNotifier>
#include <windows.h>

struct ProxyChanges::Watch {
    HKEY key = nullptr;
    HANDLE event = nullptr;
    std::unique_ptr<QWinEventNotifier> notifier;
    bool arm() { return RegNotifyChangeKeyValue(key, TRUE, REG_NOTIFY_CHANGE_LAST_SET, event, TRUE) == ERROR_SUCCESS; }
    ~Watch() {
        notifier.reset();
        if (key) RegCloseKey(key);
        if (event) CloseHandle(event);
    }
};
ProxyChanges::ProxyChanges(QObject *parent) : QObject(parent), watch(std::make_unique<Watch>()) {
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_NOTIFY, &watch->key) != ERROR_SUCCESS) return;
    watch->event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!watch->event || !watch->arm()) return;
    watch->notifier = std::make_unique<QWinEventNotifier>(watch->event);
    connect(watch->notifier.get(), &QWinEventNotifier::activated, this, [this] {
        if (!watch->arm()) watch->notifier->setEnabled(false);
        emit changed();
    });
}
ProxyChanges::~ProxyChanges() = default;
