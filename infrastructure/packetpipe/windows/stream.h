#pragma once

#include <windows.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>

class WindowsProcess;

class WindowsPacketPipe final {
public:
    static std::unique_ptr<WindowsPacketPipe> listen(const std::wstring &name,const WindowsProcess &caller);
    ~WindowsPacketPipe();
    WindowsPacketPipe(const WindowsPacketPipe &) = delete;
    WindowsPacketPipe &operator=(const WindowsPacketPipe &) = delete;
    void read(void *data,DWORD size);
    void write(const void *data,DWORD size);
    void close();
private:
    WindowsPacketPipe() = default;
    void connect(const WindowsProcess &caller);
    void transfer(void *data,DWORD size,bool write);
    void complete(OVERLAPPED &operation,DWORD &size,BOOL started,const char *stage,HANDLE caller = nullptr);
    HANDLE pipe = INVALID_HANDLE_VALUE,stop = nullptr,readReady = nullptr,writeReady = nullptr;
    std::mutex readLock,writeLock;
    std::shared_mutex lifetime;
    std::atomic<bool> closed{false};
    std::once_flag closedOnce;
};
