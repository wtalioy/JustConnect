#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/networkhelper/windows/publisher.h"
#include "windowsnetworkcontract.h"
#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <winternl.h>
#include <array>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <string_view>
#include <system_error>

namespace {
[[noreturn]] void fail(const char *stage,LONG error=GetLastError())
{
    throw std::system_error(static_cast<int>(error),std::system_category(),stage);
}
struct Handle { HANDLE value=nullptr;~Handle() { if (value && value!=INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct Security { PSECURITY_DESCRIPTOR value=nullptr;~Security() { if(value) LocalFree(value); } };
SECURITY_ATTRIBUTES attributes(Security &security)
{
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",SDDL_REVISION_1,&security.value,nullptr)) fail("create protected installation security");
    return {sizeof(SECURITY_ATTRIBUTES),security.value,FALSE};
}
WindowsSha256 decode(std::string_view value)
{
    WindowsSha256 result{};
    if (value.size()!=result.size()*2) fail("unconfigured helper payload authority",ERROR_NOT_SUPPORTED);
    const auto digit=[](char c) { if(c>='0' && c<='9') return c-'0';if(c>='a' && c<='f') return c-'a'+10;if(c>='A' && c<='F') return c-'A'+10;fail("invalid compiled payload hash",ERROR_NOT_SUPPORTED); };
    for(size_t i=0;i<result.size();++i) result[i]=static_cast<unsigned char>((digit(value[i*2])<<4)|digit(value[i*2+1]));
    return result;
}
std::wstring hex(const WindowsSha256 &value)
{
    constexpr wchar_t digits[]=L"0123456789abcdef";
    std::wstring result;
    for (const auto byte:value) { result+=digits[byte>>4];result+=digits[byte&15]; }
    return result;
}
struct File {
    HANDLE value=INVALID_HANDLE_VALUE;
    DWORD size=0;
    explicit File(const std::wstring &path)
    {
        value=CreateFileW(path.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
        if (value==INVALID_HANDLE_VALUE) fail("pin helper source file");
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(value,&info)) { const auto error=GetLastError();CloseHandle(value);fail("read helper source identity",error); }
        if ((info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) || info.nFileSizeHigh || !info.nFileSizeLow || info.nFileSizeLow>(64u<<20)) {
            CloseHandle(value);fail("invalid helper source file",ERROR_INVALID_DATA);
        }
        size=info.nFileSizeLow;
    }
    ~File() { CloseHandle(value); }
    File(const File &)=delete;
    File &operator=(const File &)=delete;
    WindowsSha256 hash() const
    {
        Handle mapping;
        mapping.value=CreateFileMappingW(value,nullptr,PAGE_READONLY,0,0,nullptr);
        if (!mapping.value) fail("map pinned helper payload");
        auto *data=static_cast<unsigned char *>(MapViewOfFile(mapping.value,FILE_MAP_READ,0,0,0));
        if (!data) fail("read pinned helper payload");
        WindowsSha256 result{};
        const auto status=BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,data,size,result.data(),static_cast<ULONG>(result.size()));
        UnmapViewOfFile(data);
        if (status<0) fail("hash pinned helper payload",RtlNtStatusToDosError(status));
        return result;
    }
};
bool trustedOwner(PSID sid)
{
    if (!sid) return false;
    if (IsWellKnownSid(sid,WinLocalSystemSid) || IsWellKnownSid(sid,WinBuiltinAdministratorsSid)) return true;
    static const auto installer=[] {
        DWORD size=0,length=0;SID_NAME_USE use{};
        LookupAccountNameW(nullptr,L"NT SERVICE\\TrustedInstaller",nullptr,&size,nullptr,&length,&use);
        if (GetLastError()!=ERROR_INSUFFICIENT_BUFFER) fail("locate installation owner");
        std::vector<unsigned char> result(size);std::vector<wchar_t> domain(length);
        if (!LookupAccountNameW(nullptr,L"NT SERVICE\\TrustedInstaller",result.data(),&size,domain.data(),&length,&use)) fail("read installation owner SID");
        return result;
    }();
    return EqualSid(sid,const_cast<unsigned char *>(installer.data()))!=FALSE;
}
void immutable(HANDLE handle,bool allowNewChildren)
{
    Security security;PSID owner=nullptr;PACL acl=nullptr;
    const auto status=GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&security.value);
    if (status!=ERROR_SUCCESS) fail("read installation object security",status);
    if (!trustedOwner(owner) || !acl || !IsValidAcl(acl)) fail("untrusted installation owner or DACL",ERROR_ACCESS_DENIED);
    DWORD forbidden=WRITE_DAC|WRITE_OWNER|DELETE|FILE_DELETE_CHILD|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|GENERIC_ALL|GENERIC_WRITE;
    if (!allowNewChildren) forbidden|=FILE_WRITE_DATA|FILE_APPEND_DATA;
    for (DWORD i=0;i<acl->AceCount;++i) {
        void *value=nullptr;
        if (!GetAce(acl,i,&value)) fail("read installation ACE");
        const auto ace=static_cast<ACCESS_ALLOWED_ACE *>(value);
        if ((ace->Header.AceFlags&INHERIT_ONLY_ACE) || ace->Header.AceType==ACCESS_DENIED_ACE_TYPE) continue;
        if (ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE || ((ace->Mask&forbidden) && !trustedOwner(&ace->SidStart)))
            fail("writable installation object",ERROR_ACCESS_DENIED);
    }
}
void runningImage(const File &file)
{
    const auto base=reinterpret_cast<const unsigned char *>(GetModuleHandleW(nullptr));
    const auto dos=reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    const auto nt=reinterpret_cast<const IMAGE_NT_HEADERS *>(base+dos->e_lfanew);
    const auto directory=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!directory.VirtualAddress || !directory.Size || directory.Size%sizeof(IMAGE_DEBUG_DIRECTORY)
        || static_cast<ULONGLONG>(directory.VirtualAddress)+directory.Size>nt->OptionalHeader.SizeOfImage)
        fail("running helper lacks linker identity",ERROR_NOT_SUPPORTED);
    const auto entries=reinterpret_cast<const IMAGE_DEBUG_DIRECTORY *>(base+directory.VirtualAddress);
    // CodeView RSDS signature, linker GUID and age identify this exact linked image; no PDB is loaded.
    constexpr size_t identitySize=4+sizeof(GUID)+sizeof(DWORD);
    for (size_t i=0;i<directory.Size/sizeof(IMAGE_DEBUG_DIRECTORY);++i) {
        const auto &entry=entries[i];
        if (entry.Type!=IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData<identitySize || !entry.AddressOfRawData) continue;
        if (static_cast<ULONGLONG>(entry.AddressOfRawData)+identitySize>nt->OptionalHeader.SizeOfImage
            || static_cast<ULONGLONG>(entry.PointerToRawData)+identitySize>file.size)
            fail("invalid stored helper identity",ERROR_INVALID_DATA);
        const auto actual=base+entry.AddressOfRawData;
        if (std::memcmp(actual,"RSDS",4)!=0) continue;
        LARGE_INTEGER offset{};offset.QuadPart=entry.PointerToRawData;
        std::array<unsigned char,identitySize> stored{};DWORD count=0;
        if (!SetFilePointerEx(file.value,offset,nullptr,FILE_BEGIN) || !ReadFile(file.value,stored.data(),static_cast<DWORD>(stored.size()),&count,nullptr)) fail("read pinned helper linker identity");
        if (count!=stored.size() || std::memcmp(stored.data(),actual,stored.size())!=0) fail("stored helper differs from running image",ERROR_INVALID_DATA);
        return;
    }
    fail("running helper lacks CodeView linker identity",ERROR_NOT_SUPPORTED);
}
void installed(const std::wstring &path,const WindowsSha256 &hash)
{
    File existing(path);immutable(existing.value,false);
    if (existing.hash()!=hash) fail("unknown existing installation payload",ERROR_INVALID_DATA);
}
void install(const File &source,const std::wstring &path,const WindowsSha256 &hash)
{
    try { installed(path,hash);return; } catch (const std::system_error &error) { if (error.code().value()!=ERROR_FILE_NOT_FOUND) throw; }
    GUID id{};wchar_t suffix[39]{};
    if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id,suffix,39)) fail("allocate installation temporary identity",ERROR_INVALID_DATA);
    const auto temporary=path+L"."+suffix+L".tmp";
    Security security;auto access=attributes(security);
    Handle output;
    output.value=CreateFileW(temporary.c_str(),GENERIC_WRITE,0,&access,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr);
    if (output.value==INVALID_HANDLE_VALUE) fail("create protected installation payload");
    struct Remove {
        const std::wstring &path;Handle &output;
        ~Remove() { if(output.value) { CloseHandle(output.value);output.value=nullptr; } DeleteFileW(path.c_str()); }
    } remove{temporary,output};
    LARGE_INTEGER start{};
    if (!SetFilePointerEx(source.value,start,nullptr,FILE_BEGIN)) fail("rewind pinned installation source");
    std::array<unsigned char,65536> buffer{};
    for (;;) {
        DWORD count=0;
        if (!ReadFile(source.value,buffer.data(),static_cast<DWORD>(buffer.size()),&count,nullptr)) fail("read installation source");
        if (!count) break;
        for (DWORD offset=0;offset<count;) {
            DWORD written=0;
            if (!WriteFile(output.value,buffer.data()+offset,count-offset,&written,nullptr)) fail("copy protected installation payload");
            if (!written) fail("short installation write",ERROR_WRITE_FAULT);
            offset+=written;
        }
    }
    if (!FlushFileBuffers(output.value)) fail("flush protected installation payload");
    if (!CloseHandle(output.value)) fail("close protected installation payload");
    output.value=nullptr;
    if (!MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_WRITE_THROUGH)) {
        const auto error=GetLastError();
        if (error!=ERROR_ALREADY_EXISTS && error!=ERROR_FILE_EXISTS) fail("publish protected installation payload",error);
        installed(path,hash);
    }
}
std::wstring currentImage()
{
    wchar_t path[32768]{};
    const auto length=GetModuleFileNameW(nullptr,path,32768);
    if (!length || length>=32768) fail("locate running helper image");
    return path;
}
}

void WindowsHelperInstallation::pinDirectory(const std::wstring &path,bool create,bool allowNewChildren)
{
    if (create) {
        Security security;auto access=attributes(security);
        if (!CreateDirectoryW(path.c_str(),&access) && GetLastError()!=ERROR_ALREADY_EXISTS) fail("create protected installation directory");
    }
    Handle handle;
    handle.value=CreateFileW(path.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if (handle.value==INVALID_HANDLE_VALUE) fail("pin installation directory");
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle.value,&info)) fail("read pinned directory identity");
    if (!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)) fail("unsafe installation directory",ERROR_ACCESS_DENIED);
    immutable(handle.value,allowNewChildren);
    directories.push_back(handle.value);handle.value=nullptr;
}
void WindowsHelperInstallation::pinInstallation(const std::wstring &hash,bool create)
{
    PWSTR folder=nullptr;
    const auto status=SHGetKnownFolderPath(FOLDERID_ProgramFiles,0,nullptr,&folder);
    if (FAILED(status)) fail("locate system installation folder",status);
    std::filesystem::path base;
    try { base=folder; } catch (...) { CoTaskMemFree(folder);throw; }
    CoTaskMemFree(folder);
    if (!base.is_absolute() || base.root_name().wstring().size()!=2 || base.root_name().wstring()[1]!=L':') fail("unsupported system installation volume",ERROR_NOT_SUPPORTED);
    auto path=base.root_path();
    pinDirectory(path.wstring(),false,true);
    for (const auto &part:base.relative_path()) { path/=part;pinDirectory(path.wstring(),false,true); }
    path/=WindowsNetworkContract::InstallDirectory;pinDirectory(path.wstring(),create,false);
    path/=hash;pinDirectory(path.wstring(),create,false);
    executable=(path/WindowsNetworkContract::Executable).wstring();
    library=(path/WindowsNetworkContract::DriverLibrary).wstring();
}
std::unique_ptr<WindowsHelperInstallation> WindowsHelperInstallation::openInstalled()
{
    const auto executable=currentImage();
    File image(executable);immutable(image.value,false);runningImage(image);
    auto result=std::unique_ptr<WindowsHelperInstallation>(new WindowsHelperInstallation);
    result->pinInstallation(hex(image.hash()),false);
    if (_wcsicmp(executable.c_str(),result->image().c_str())!=0) fail("recovery must run from its protected installation",ERROR_ACCESS_DENIED);
    installed(result->library,decode(WindowsNetworkContract::DriverSHA256));
    installed((std::filesystem::path(result->image()).parent_path()/WindowsNetworkContract::DriverLicense).wstring(),decode(WindowsNetworkContract::LicenseSHA256));
    return result;
}
std::unique_ptr<WindowsHelperInstallation> WindowsHelperInstallation::prepare()
{
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value)) fail("read installation elevation");
    TOKEN_ELEVATION elevation{};DWORD size=0;
    if (!GetTokenInformation(token.value,TokenElevation,&elevation,sizeof(elevation),&size)) fail("read installation privilege");
    if (!elevation.TokenIsElevated) fail("installation requires elevation",ERROR_ACCESS_DENIED);
    const auto publisher=decode(WindowsNetworkContract::PublisherSHA256),driverHash=decode(WindowsNetworkContract::DriverSHA256),licenseHash=decode(WindowsNetworkContract::LicenseSHA256);
    const auto executable=currentImage();
    File image(executable);
    verifyWindowsPublisher(executable,image.value,publisher);
    runningImage(image);
    const auto identity=image.hash();
    const auto source=std::filesystem::path(executable).parent_path();
    File driver((source/WindowsNetworkContract::DriverLibrary).wstring()),license((source/WindowsNetworkContract::DriverLicense).wstring());
    if (driver.hash()!=driverHash || license.hash()!=licenseHash) fail("untrusted helper driver or license",ERROR_INVALID_DATA);
    auto result=std::unique_ptr<WindowsHelperInstallation>(new WindowsHelperInstallation);
    result->pinInstallation(hex(identity),true);
    const auto path=std::filesystem::path(result->image()).parent_path();
    install(image,result->executable,identity);install(driver,result->library,driverHash);
    install(license,(path/WindowsNetworkContract::DriverLicense).wstring(),licenseHash);
    return result;
}
void WindowsHelperInstallation::close()
{
    for (auto it=directories.rbegin();it!=directories.rend();++it) CloseHandle(*it);
    directories.clear();
}
WindowsHelperInstallation::~WindowsHelperInstallation() { close(); }
