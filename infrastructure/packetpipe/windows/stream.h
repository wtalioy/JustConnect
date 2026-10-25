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
    static std::unique_ptr<WindowsPacketPipe> create(const std::wstring &name,const WindowsProcess &caller);
    static std::unique_ptr<WindowsPacketPipe> listen(const std::wstring &name,const WindowsProcess &caller,DWORD timeout=INFINITE);
    // The launch handle identifies the approved elevated process without querying another account's token.
    static std::unique_ptr<WindowsPacketPipe> connect(const std::wstring &name,HANDLE server,DWORD timeout,HANDLE cancel=nullptr);
    ~WindowsPacketPipe();
    WindowsPacketPipe(const WindowsPacketPipe &) = delete;
    WindowsPacketPipe &operator=(const WindowsPacketPipe &) = delete;
    void read(void *data,DWORD size,DWORD timeout=INFINITE);
    void write(const void *data,DWORD size,DWORD timeout=INFINITE);
    void accept(const WindowsProcess &caller,DWORD timeout);
    HANDLE handle() const{return pipe;}
    void close();
private:
    WindowsPacketPipe() = default;
    void initialize();
    void transfer(void *data,DWORD size,bool write,DWORD timeout);
    void complete(OVERLAPPED &operation,DWORD &size,BOOL started,const char *stage,HANDLE caller = nullptr,DWORD timeout=INFINITE);
    HANDLE pipe = INVALID_HANDLE_VALUE,stop = nullptr,readReady = nullptr,writeReady = nullptr;
    std::mutex readLock,writeLock;
    std::shared_mutex lifetime;
    std::atomic<bool> closed{false};
    std::once_flag closedOnce;
};
