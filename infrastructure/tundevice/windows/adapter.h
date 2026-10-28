#pragma once

#include <wintun.h>
#include <iphlpapi.h>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

struct WindowsTunIdentity {
    std::wstring name;
    GUID guid{};
    NET_LUID luid{};
    NET_IFINDEX index = 0;
};

struct WindowsTunPrefix {
    IN_ADDR address{};
    unsigned char bits = 0;
};

// Adapter/ring ownership stays in the privileged helper. DLL verification belongs to its installer.
class WindowsTunDevice final {
public:
    static std::unique_ptr<WindowsTunDevice> create(const std::wstring &verifiedDll, const GUID &owner,
        IN_ADDR source, IN_ADDR peer, unsigned int mtu, const std::vector<WindowsTunPrefix> &targets,
        const std::function<void(const WindowsTunIdentity &)> &allocated);
    ~WindowsTunDevice();
    WindowsTunDevice(const WindowsTunDevice &) = delete;
    WindowsTunDevice &operator=(const WindowsTunDevice &) = delete;
    const WindowsTunIdentity &identity() const { return owned; }
    static void validate(IN_ADDR source,IN_ADDR peer,unsigned int mtu,const std::vector<WindowsTunPrefix> &targets);
    void reconcile(const std::vector<WindowsTunPrefix> &targets);
    size_t read(unsigned char *packet, size_t capacity);
    void write(const unsigned char *packet, size_t size);
    void close();
private:
    WindowsTunDevice() = default;
    void configure(IN_ADDR source, IN_ADDR peer, const std::vector<WindowsTunPrefix> &targets);
    WindowsTunIdentity owned;
    HMODULE module = nullptr;
    WINTUN_ADAPTER_HANDLE adapter = nullptr;
    WINTUN_SESSION_HANDLE session = nullptr;
    HANDLE ready = nullptr, sendReady = nullptr, stop = nullptr;
    unsigned int mtu = 0;
    IN_ADDR source{},peer{};
    std::vector<WindowsTunPrefix> captures;
    std::atomic<bool> closed{false};
    std::shared_mutex lifetime;
    std::mutex readLock, writeLock;
    std::once_flag closedOnce;
    WINTUN_CLOSE_ADAPTER_FUNC *closeAdapter = nullptr;
    WINTUN_END_SESSION_FUNC *endSession = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC *receive = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC *release = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC *allocate = nullptr;
    WINTUN_SEND_PACKET_FUNC *send = nullptr;
};
