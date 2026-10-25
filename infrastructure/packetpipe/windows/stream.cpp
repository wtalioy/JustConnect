#include "infrastructure/packetpipe/windows/stream.h"
#include "infrastructure/process/windows/identity.h"
#include <sddl.h>
#include <system_error>

namespace {
[[noreturn]] void fail(const char *stage,DWORD error = GetLastError())
{
    throw std::system_error(static_cast<int>(error),std::system_category(),stage);
}
}

std::unique_ptr<WindowsPacketPipe> WindowsPacketPipe::listen(const std::wstring &name,const WindowsProcess &caller)
{
    auto stream=std::unique_ptr<WindowsPacketPipe>(new WindowsPacketPipe);
    const auto sddl=L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;"+caller.identity().sid+L")S:(ML;;NW;;;ME)";
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) fail("create packet pipe security");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
    stream->pipe=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE|FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,&attributes);
    const auto error=GetLastError();
    LocalFree(descriptor);
    if (stream->pipe==INVALID_HANDLE_VALUE) fail("create private packet pipe",error);
    stream->stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    stream->readReady=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    stream->writeReady=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if (!stream->stop || !stream->readReady || !stream->writeReady) fail("create packet I/O events");
    stream->connect(caller);
    return stream;
}

void WindowsPacketPipe::complete(OVERLAPPED &operation,DWORD &size,BOOL started,const char *stage,HANDLE caller)
{
    if (started) return;
    const auto error=GetLastError();
    if (error!=ERROR_IO_PENDING) fail(stage,error);
    const HANDLE waits[]{stop,operation.hEvent,caller};
    const auto state=WaitForMultipleObjects(caller?3:2,waits,FALSE,INFINITE);
    if (state!=WAIT_OBJECT_0+1) {
        const auto saved=state==WAIT_FAILED?GetLastError():ERROR_OPERATION_ABORTED;
        CancelIoEx(pipe,&operation);
        GetOverlappedResult(pipe,&operation,&size,TRUE); // Join before its buffer or OVERLAPPED leaves scope.
        fail(stage,saved);
    }
    if (!GetOverlappedResult(pipe,&operation,&size,FALSE)) fail(stage);
}

void WindowsPacketPipe::connect(const WindowsProcess &caller)
{
    OVERLAPPED operation{};
    operation.hEvent=readReady;
    const auto started=ConnectNamedPipe(pipe,&operation);
    const auto error=GetLastError();
    if (!started && error!=ERROR_PIPE_CONNECTED) {
        DWORD size=0;
        SetLastError(error);
        complete(operation,size,FALSE,"accept packet pipe",caller.handle());
    }
    ULONG pid=0;
    if (!GetNamedPipeClientProcessId(pipe,&pid)) fail("identify packet pipe client");
    if (pid!=caller.identity().pid || !caller.identity().alive()) fail("unexpected packet pipe client",ERROR_ACCESS_DENIED);
}

void WindowsPacketPipe::transfer(void *data,DWORD size,bool writing)
{
    std::lock_guard<std::mutex> serial(writing?writeLock:readLock);
    std::shared_lock<std::shared_mutex> active(lifetime);
    if (closed) fail("packet pipe stopped",ERROR_OPERATION_ABORTED);
    auto *bytes=static_cast<unsigned char *>(data);
    while (size) {
        OVERLAPPED operation{};
        operation.hEvent=writing?writeReady:readReady;
        if (!ResetEvent(operation.hEvent)) fail("reset packet I/O event");
        DWORD count=0;
        const auto started=writing?WriteFile(pipe,bytes,size,&count,&operation):ReadFile(pipe,bytes,size,&count,&operation);
        complete(operation,count,started,writing?"write packet pipe":"read packet pipe");
        if (!count) fail("closed packet pipe",ERROR_BROKEN_PIPE);
        bytes+=count;
        size-=count;
    }
}
void WindowsPacketPipe::read(void *data,DWORD size) { transfer(data,size,false); }
void WindowsPacketPipe::write(const void *data,DWORD size) { transfer(const_cast<void *>(data),size,true); }
void WindowsPacketPipe::close()
{
    std::call_once(closedOnce,[&] {
        closed=true;
        if (stop) SetEvent(stop);
        std::unique_lock<std::shared_mutex> exclusive(lifetime);
        if (pipe!=INVALID_HANDLE_VALUE) CloseHandle(pipe);
        if (stop) CloseHandle(stop);
        if (readReady) CloseHandle(readReady);
        if (writeReady) CloseHandle(writeReady);
    });
}
WindowsPacketPipe::~WindowsPacketPipe() { close(); }
