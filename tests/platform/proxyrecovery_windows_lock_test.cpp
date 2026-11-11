#include "infrastructure/systemproxy/windows/proxyrecoverylock.h"
#include <QCoreApplication>
#include <QDir>
#include <QProcess>
#include <QProcessEnvironment>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QStringList>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {
void check(bool valid,const char *message) {if(!valid)throw std::runtime_error(message);}
QString fault,sid="S-1-5-21-1",name,permissions;
int opened=0,closed=0,allocated=0,freed=0,released=0,created=0;
HANDLE tokenHandle=reinterpret_cast<HANDLE>(quintptr(1)),mutexHandle=reinterpret_cast<HANDLE>(quintptr(2));
BOOL WINAPI openToken(HANDLE process,DWORD access,PHANDLE token) {
    check(process==GetCurrentProcess() && access==TOKEN_QUERY,"Unexpected token scope/access");
    if(fault=="open")return FALSE;
    *token=fault=="missing_token"?nullptr:tokenHandle;opened+=*token!=nullptr;return TRUE;
}
BOOL WINAPI information(HANDLE token,TOKEN_INFORMATION_CLASS type,LPVOID data,DWORD bytes,PDWORD actual) {
    check(token==tokenHandle && type==TokenUser,"Mutex identity did not use the process user SID");
    if(!data) {
        check(bytes==0,"Unexpected identity size probe");
        *actual=fault=="small"?sizeof(TOKEN_USER)-1:fault=="large"?65537:sizeof(TOKEN_USER);
        SetLastError(fault=="probe"?ERROR_ACCESS_DENIED:ERROR_INSUFFICIENT_BUFFER);return fault=="probe_success";
    }
    check(bytes==sizeof(TOKEN_USER),"Unexpected token buffer size");
    if(fault=="read")return FALSE;
    *actual=fault=="actual_large"?bytes+1:fault=="actual_small"?bytes-1:bytes;
    static int identity;static_cast<TOKEN_USER *>(data)->User.Sid=fault=="null_sid"?nullptr:&identity;return TRUE;
}
BOOL WINAPI identity(PSID value,LPWSTR *text) {
    check(value!=nullptr,"Invalid SID reached conversion");
    if(fault=="sid")return FALSE;
    const auto valueText=fault=="empty_sid"?QString():sid;
    *text=static_cast<LPWSTR>(std::malloc((valueText.size()+1)*sizeof(wchar_t)));check(*text,"Allocate private SID fixture");
    valueText.toWCharArray(*text);(*text)[valueText.size()]=0;++allocated;return TRUE;
}
BOOL WINAPI descriptor(LPCWSTR text,DWORD revision,PSECURITY_DESCRIPTOR *value,PULONG bytes) {
    check(revision==SDDL_REVISION_1 && bytes==nullptr,"Unexpected descriptor conversion");
    permissions=QString::fromWCharArray(text);
    check(permissions=="D:P(A;;0x100001;;;"+sid+')',"User mutex DACL grants another principal or unexpected access");
    if(fault=="descriptor")return FALSE;
    *value=fault=="null_descriptor"?nullptr:std::malloc(1);allocated+=*value!=nullptr;return TRUE;
}
HANDLE WINAPI create(LPSECURITY_ATTRIBUTES attributes,LPCWSTR text,DWORD flags,DWORD access) {
    check(attributes && attributes->nLength==sizeof(SECURITY_ATTRIBUTES) && attributes->lpSecurityDescriptor
          && !attributes->bInheritHandle && flags==0 && access==(SYNCHRONIZE|MUTEX_MODIFY_STATE),"Unexpected mutex access or inherited handle");
    name=QString::fromWCharArray(text);
    check(name.startsWith("Global\\JustConnect-proxy-recovery-") && name.size()<MAX_PATH,"Mutex scope is not global or exceeds native name bounds");
    if(fault=="create")return nullptr;
    ++created;return mutexHandle;
}
DWORD WINAPI wait(HANDLE value,DWORD timeout) {
    check(value==mutexHandle && timeout==0,"Recovery mutex blocked or waited on another object");
    return fault=="timeout"?WAIT_TIMEOUT:fault=="wait"?WAIT_FAILED:fault=="abandoned"?WAIT_ABANDONED:WAIT_OBJECT_0;
}
BOOL WINAPI release(HANDLE value) {check(value==mutexHandle,"Released another kernel object");++released;return TRUE;}
BOOL WINAPI close(HANDLE value) {check(value==tokenHandle || value==mutexHandle,"Closed another kernel object");++closed;return TRUE;}
HLOCAL WINAPI free(HLOCAL value) {check(value!=nullptr,"Freed absent identity storage");std::free(value);++freed;return nullptr;}
DWORD nativeWaitResult=WAIT_FAILED;
QString nativeName;
HANDLE WINAPI nativeCreate(LPSECURITY_ATTRIBUTES attributes,LPCWSTR text,DWORD flags,DWORD access) {
    nativeName=QString::fromWCharArray(text);return CreateMutexExW(attributes,text,flags,access);
}
DWORD WINAPI nativeWait(HANDLE handle,DWORD timeout) {nativeWaitResult=WaitForSingleObject(handle,timeout);return nativeWaitResult;}
void fakeTests() {
    WindowsProxyLockApi api{openToken,information,identity,descriptor,create,wait,release,close,free};
    for(const auto &stage:QStringList{"","abandoned","open","missing_token","probe","probe_success","small","large","read",
            "actual_large","actual_small","null_sid","sid","empty_sid","descriptor","null_descriptor","create","timeout","wait"}) {
        fault=stage;opened=closed=allocated=freed=released=created=0;
        {WindowsProxyRecoveryLock lock(api);check(lock.isLocked()==(fault.isEmpty() || fault=="abandoned"),"Failed or abandoned user lock was misclassified");}
        check(closed==opened+created && freed==allocated && released==int(fault.isEmpty() || fault=="abandoned"),
              "User mutex leaked resources or released an unowned mutex");
    }
    fault.clear();QString first;
    {WindowsProxyRecoveryLock lock(api);check(lock.isLocked(),"Acquire first SID fixture");first=name;}
    qputenv("TMP","unrelated-private-temp-root");QCoreApplication::setApplicationName("Unrelated fixture application");
    {WindowsProxyRecoveryLock lock(api);check(lock.isLocked() && name==first,"Data/temp/application metadata changed user ownership scope");}
    sid="S-1-5-21-2";
    {WindowsProxyRecoveryLock lock(api);check(lock.isLocked() && name!=first,"Different users share a recovery mutex");}
    std::cout<<"PASS: Windows user mutex identity, explicit access, bounded queries, failure cleanup and abandonment\n";
}
void nativeTests(const QString &self) {
    check(qEnvironmentVariable("GITHUB_ACTIONS")=="true","Native user mutex tests require a disposable runner");
    QTemporaryDir first,second;check(first.isValid() && second.isValid(),"Create independent native lock roots");
    const auto directory=QDir::currentPath();const auto restoreDirectory=qScopeGuard([&]{QDir::setCurrent(directory);});
    check(QDir::setCurrent(second.path()),"Set native contender working directory");
    for(const auto *key:{"APPDATA","LOCALAPPDATA","TEMP","TMP"})qputenv(key,second.path().toUtf8());
    for(const bool crash:{false,true}) {
        QProcess holder;auto environment=QProcessEnvironment::systemEnvironment();
        const auto cleanup=qScopeGuard([&]{if(holder.state()!=QProcess::NotRunning){holder.kill();holder.waitForFinished(5000);}});
        for(const auto *key:{"APPDATA","LOCALAPPDATA","TEMP","TMP"})environment.insert(key,first.path());
        holder.setProcessEnvironment(environment);holder.setWorkingDirectory(first.path());holder.start(self,{"--hold"},QIODevice::ReadWrite|QIODevice::Text);
        const bool ready=holder.waitForStarted(5000) && holder.waitForReadyRead(5000) && holder.readLine()=="READY\n";
        if(!ready)std::cerr<<holder.readAllStandardError().constData();check(ready,"Start native user mutex owner");
        WindowsProxyLockApi native;native.create=nativeCreate;native.wait=nativeWait;
        WindowsProxyRecoveryLock blocked(native);
        check(!blocked.isLocked() && nativeWaitResult==WAIT_TIMEOUT,"A second process/root acquired the same user's mutex or failed to open it");
        const auto observer=OpenMutexW(SYNCHRONIZE|MUTEX_MODIFY_STATE,FALSE,reinterpret_cast<LPCWSTR>(nativeName.utf16()));
        check(observer!=nullptr,"Keep an independent reference to the actual named mutex");
        const auto closeObserver=qScopeGuard([&]{CloseHandle(observer);});
        if(crash)holder.kill();
        else check(holder.write("\n")==1 && (!holder.bytesToWrite() || holder.waitForBytesWritten(5000)),"Release native mutex owner");
        check(holder.waitForFinished(5000) && (crash?holder.exitCode()!=0
              :holder.exitStatus()==QProcess::NormalExit && holder.exitCode()==0),"Owned mutex fixture did not terminate");
        WindowsProxyRecoveryLock recovered(native);
        check(recovered.isLocked() && nativeWaitResult==(crash?WAIT_ABANDONED:WAIT_OBJECT_0),"Normal/abandoned native mutex could not be acquired");
    }
    std::cout<<"PASS: native global Windows user mutex excludes other roots and recovers after owned process termination\n";
}
}

int main(int argc,char **argv) try {
    QCoreApplication app(argc,argv);const auto args=app.arguments();
    if(args.size()==2 && args[1]=="--hold") {
        check(qEnvironmentVariable("GITHUB_ACTIONS")=="true","Native lock holder requires a disposable runner");
        WindowsProxyRecoveryLock lock;
        if(!lock.isLocked())std::cerr<<"Native user lock failed; last Win32 code "<<GetLastError()<<'\n';
        check(lock.isLocked(),"Acquire native recovery mutex");std::cout<<"READY\n"<<std::flush;std::cin.get();return 0;
    }
    if(args.size()==2 && args[1]=="--native")nativeTests(app.applicationFilePath());
    else {check(args.size()==1,"Unexpected mutex fixture arguments");fakeTests();}
    return 0;
} catch(const std::exception &error) {std::cerr<<error.what()<<'\n';return 1;}
