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

std::unique_ptr<WindowsPacketPipe> WindowsPacketPipe::listen(const std::wstring &name,const WindowsProcess &caller,DWORD timeout)
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
    stream->initialize();
    stream->accept(caller,timeout);
    return stream;
}

void WindowsPacketPipe::initialize()
{
    stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    readReady=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    writeReady=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if (!stop || !readReady || !writeReady) fail("create packet I/O events");
}

std::unique_ptr<WindowsPacketPipe> WindowsPacketPipe::connect(const std::wstring &name,HANDLE server,DWORD timeout,HANDLE cancel)
{
    if (!server || !timeout || timeout==INFINITE || name.rfind(L"\\\\.\\pipe\\",0)!=0)
        fail("invalid local pipe connection",ERROR_INVALID_PARAMETER);
    const auto pid=GetProcessId(server);
    if (!pid || WaitForSingleObject(server,0)!=WAIT_TIMEOUT) fail("approved pipe server unavailable",ERROR_PROCESS_ABORTED);
    auto stream=std::unique_ptr<WindowsPacketPipe>(new WindowsPacketPipe);
    const auto deadline=GetTickCount64()+timeout;
    for (;;) {
        if(cancel && WaitForSingleObject(cancel,0)!=WAIT_TIMEOUT)fail("local pipe connection cancelled",ERROR_OPERATION_ABORTED);
        stream->pipe=CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
        if (stream->pipe!=INVALID_HANDLE_VALUE) break;
        const auto error=GetLastError();
        if (error!=ERROR_PIPE_BUSY && error!=ERROR_FILE_NOT_FOUND) fail("open local pipe",error);
        if (GetTickCount64()>=deadline) fail("local pipe connection deadline",ERROR_TIMEOUT);
        const HANDLE waits[]{server,cancel};
        const auto state=WaitForMultipleObjects(cancel?2:1,waits,FALSE,10);
        if(state!=WAIT_TIMEOUT)fail("local pipe connection stopped",state==WAIT_OBJECT_0+1?ERROR_OPERATION_ABORTED:ERROR_PROCESS_ABORTED);
    }
    ULONG actual=0;
    if (!GetNamedPipeServerProcessId(stream->pipe,&actual)) fail("identify local pipe server");
    if (actual!=pid || WaitForSingleObject(server,0)!=WAIT_TIMEOUT) fail("unexpected local pipe server",ERROR_ACCESS_DENIED);
    stream->initialize();
    return stream;
}

void WindowsPacketPipe::complete(OVERLAPPED &operation,DWORD &size,BOOL started,const char *stage,HANDLE caller,DWORD timeout)
{
    if (started) return;
    const auto error=GetLastError();
    if (error!=ERROR_IO_PENDING) fail(stage,error);
    const HANDLE waits[]{stop,operation.hEvent,caller};
    const auto state=WaitForMultipleObjects(caller?3:2,waits,FALSE,timeout);
    if (state!=WAIT_OBJECT_0+1) {
        const auto saved=state==WAIT_FAILED?GetLastError():(state==WAIT_TIMEOUT?ERROR_TIMEOUT:ERROR_OPERATION_ABORTED);
        CancelIoEx(pipe,&operation);
        GetOverlappedResult(pipe,&operation,&size,TRUE); // Join before its buffer or OVERLAPPED leaves scope.
        fail(stage,saved);
    }
    if (!GetOverlappedResult(pipe,&operation,&size,FALSE)) fail(stage);
}

void WindowsPacketPipe::accept(const WindowsProcess &caller,DWORD timeout)
{
    OVERLAPPED operation{};
    operation.hEvent=readReady;
    const auto started=ConnectNamedPipe(pipe,&operation);
    const auto error=GetLastError();
    if (!started && error!=ERROR_PIPE_CONNECTED) {
        DWORD size=0;
        SetLastError(error);
        complete(operation,size,FALSE,"accept packet pipe",caller.handle(),timeout);
    }
    ULONG pid=0;
    if (!GetNamedPipeClientProcessId(pipe,&pid)) fail("identify packet pipe client");
    if (pid!=caller.identity().pid || !caller.identity().alive()) fail("unexpected packet pipe client",ERROR_ACCESS_DENIED);
}

void WindowsPacketPipe::transfer(void *data,DWORD size,bool writing,DWORD timeout)
{
    std::lock_guard<std::mutex> serial(writing?writeLock:readLock);
    std::shared_lock<std::shared_mutex> active(lifetime);
    if (closed) fail("packet pipe stopped",ERROR_OPERATION_ABORTED);
    auto *bytes=static_cast<unsigned char *>(data);
    const auto startedAt=timeout==INFINITE?0:GetTickCount64();
    while (size) {
        DWORD remaining=INFINITE;
        if(timeout!=INFINITE){
            const auto elapsed=GetTickCount64()-startedAt;
            if(elapsed>=timeout)fail("packet I/O deadline",ERROR_TIMEOUT);
            remaining=static_cast<DWORD>(timeout-elapsed);
        }
        OVERLAPPED operation{};
        operation.hEvent=writing?writeReady:readReady;
        if (!ResetEvent(operation.hEvent)) fail("reset packet I/O event");
        DWORD count=0;
        const auto started=writing?WriteFile(pipe,bytes,size,&count,&operation):ReadFile(pipe,bytes,size,&count,&operation);
        complete(operation,count,started,writing?"write packet pipe":"read packet pipe",nullptr,remaining);
        if (!count) fail("closed packet pipe",ERROR_BROKEN_PIPE);
        bytes+=count;
        size-=count;
    }
}
void WindowsPacketPipe::read(void *data,DWORD size,DWORD timeout) { transfer(data,size,false,timeout); }
void WindowsPacketPipe::write(const void *data,DWORD size,DWORD timeout) { transfer(const_cast<void *>(data),size,true,timeout); }
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
