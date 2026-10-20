#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/platformcommand.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QMap>
#include <QThread>
#include <iostream>
#include <cstdlib>
#ifdef Q_OS_WIN
#include <raserror.h>
#endif

static void check(bool ok, const char *message) { if (!ok) { std::cerr << message << '\n'; std::exit(1); } }
using Status = PlatformOperationResult::Status;
const SystemProxyConfig config{11081,11080,"localhost;*.example.test"};

#ifdef Q_OS_WIN
namespace {
struct WinState { DWORD flags=PROXY_TYPE_DIRECT; QString proxy,bypass,pac; };
QMap<QString,WinState> states;
QStringList rasNames{"fixture connection"};
bool denyQuery=false,denySet=false,ignoreSet=false,denyNotify=false,denyRas=false;
int writes=0,failAt=0;
DWORD queryError=ERROR_ACCESS_DENIED;
BOOL WINAPI query(HINTERNET, DWORD, LPVOID buffer, LPDWORD) {
    if(denyQuery){SetLastError(queryError);return FALSE;}
    auto *list=static_cast<INTERNET_PER_CONN_OPTION_LISTW *>(buffer);
    const auto &state=states[QString::fromWCharArray(list->pszConnection?list->pszConnection:L"")];
    for(DWORD i=0;i<list->dwOptionCount;++i) {
        auto &option=list->pOptions[i];
        if(option.dwOption==INTERNET_PER_CONN_FLAGS_UI){option.Value.dwValue=state.flags;continue;}
        const auto value=option.dwOption==INTERNET_PER_CONN_PROXY_SERVER?state.proxy:option.dwOption==INTERNET_PER_CONN_PROXY_BYPASS?state.bypass:state.pac;
        auto *text=static_cast<wchar_t *>(GlobalAlloc(GMEM_FIXED,(value.size()+1)*sizeof(wchar_t)));
        check(text!=nullptr,"allocate query strings");value.toWCharArray(text);text[value.size()]=0;option.Value.pszValue=text;
    }
    return TRUE;
}
BOOL WINAPI set(HINTERNET, DWORD option, LPVOID buffer, DWORD) {
    if(option!=INTERNET_OPTION_PER_CONNECTION_OPTION){if(denyNotify){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;}
    if(denySet || ++writes==failAt){SetLastError(ERROR_CANCELLED);return FALSE;}
    if(ignoreSet)return TRUE;
    auto *list=static_cast<INTERNET_PER_CONN_OPTION_LISTW *>(buffer);
    auto &state=states[QString::fromWCharArray(list->pszConnection?list->pszConnection:L"")];
    for(DWORD i=0;i<list->dwOptionCount;++i) {
        const auto &value=list->pOptions[i];
        if(value.dwOption==INTERNET_PER_CONN_FLAGS)state.flags=value.Value.dwValue;
        else if(value.dwOption==INTERNET_PER_CONN_PROXY_SERVER)state.proxy=QString::fromWCharArray(value.Value.pszValue);
        else if(value.dwOption==INTERNET_PER_CONN_PROXY_BYPASS)state.bypass=QString::fromWCharArray(value.Value.pszValue);
        else check(false,"manual proxy must not overwrite stored PAC URL");
    }
    return TRUE;
}
DWORD WINAPI entries(LPCWSTR,LPCWSTR,LPRASENTRYNAMEW names,LPDWORD bytes,LPDWORD count) {
    if(denyRas)return ERROR_ACCESS_DENIED;
    *count=DWORD(rasNames.size());if(!*count)return ERROR_SUCCESS;
    if(!names){*bytes=DWORD(sizeof(RASENTRYNAMEW)*rasNames.size());return ERROR_BUFFER_TOO_SMALL;}
    for(int i=0;i<rasNames.size();++i)rasNames[i].toWCharArray(names[i].szEntryName),names[i].szEntryName[rasNames[i].size()]=0;
    return ERROR_SUCCESS;
}
}
static void backendTests() {
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=prior.invalid:3128","old.invalid","https://pac.invalid/original.pac"};
    states[""]=original;states["fixture connection"]={PROXY_TYPE_DIRECT,"socks=old.invalid:1080","ras.invalid",{}};
    PlatformSystemProxyBackend backend(WindowsProxyApi{query,set,entries});
    check(backend.clear().succeeded() && writes==0,"unknown LAN and RAS settings must not be cleared");
    denyQuery=true;
    check(backend.check(config).result.status==Status::PermissionDenied,"query denial propagated");
    check(!backend.apply(config).succeeded() && writes==0,"failed query prevents writes");
    queryError=ERROR_TIMEOUT;check(backend.check(config).result.status==Status::TimedOut,"WinINet timeout classified");
    queryError=ERROR_NOT_SUPPORTED;check(backend.check(config).result.status==Status::Unsupported,"WinINet unsupported classified");
    denyQuery=false;denyRas=true;
    check(backend.check(config).result.status==Status::PermissionDenied,"RAS failure propagated");denyRas=false;
    denySet=true;const auto cancelled=backend.apply(config);
    check(cancelled.status==Status::Cancelled && cancelled.mayHaveChanged,"cancelled WinINet mutation retains unresolved responsibility");
    denySet=false;check(backend.clear().succeeded(),"cancelled application can be recovered");
    writes=0;failAt=2;
    const auto partial=backend.apply(config);
    check(!partial.succeeded() && !partial.mayHaveChanged,"LAN mutation is rolled back after RAS failure");
    check(states[""].flags==original.flags && states[""].proxy==original.proxy && states[""].bypass==original.bypass,"partial apply restores distinct LAN state");
    check(states["fixture connection"].proxy=="socks=old.invalid:1080","unmodified RAS state retained");
    failAt=0;ignoreSet=true;check(!backend.apply(config).succeeded(),"successful API without actual change fails readback");ignoreSet=false;
    check(backend.apply(config).succeeded() && !backend.check(config).conflict,"all endpoints and bypass verified");
    check(states[""].pac==original.pac,"manual mode preserves inactive PAC address");
    check(states[""].proxy=="http=127.0.0.1:11081;https=127.0.0.1:11081;ftp=127.0.0.1:11081;socks=127.0.0.1:11080","WinINet endpoints encoded independently");
    check(!backend.apply(config).succeeded(),"repeated apply cannot overwrite the original snapshot");
    writes=0;failAt=1;check(!backend.clear().succeeded(),"restore failure retained for retry");failAt=0;
    denyNotify=true;check(!backend.clear().succeeded(),"notification failure propagated");denyNotify=false;
    check(backend.clear().succeeded() && states[""].flags==original.flags && states[""].proxy==original.proxy && states[""].bypass==original.bypass,"original PAC/proxy/bypass restored");
    const int restoredWrites=writes;check(backend.clear().succeeded() && writes==restoredWrites,"restored backend cannot clear unknown changes");
    check(backend.apply(config).succeeded(),"apply before external changes");
    states[""].proxy="http=external.invalid:8899";states[""].bypass="external.invalid";states[""].pac="https://pac.invalid/external.pac";
    states["new connection"]={PROXY_TYPE_PROXY,"new.invalid:1234","new.invalid",{}};rasNames<<"new connection";
    check(backend.clear().succeeded(),"restore owned fields around external changes");
    check(states[""].proxy=="http=external.invalid:8899" && states[""].bypass=="external.invalid" && states[""].flags==(PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY),"external fields and dependent mode retained");
    check(states["new connection"].proxy=="new.invalid:1234" && states["fixture connection"].proxy=="socks=old.invalid:1080","new connections untouched and original RAS restored");
}

namespace {
WinState nativeOriginal;
bool nativeSaved=false;
bool nativeRead(WinState &state) {
    INTERNET_PER_CONN_OPTIONW options[4]{};
    const DWORD keys[]{INTERNET_PER_CONN_FLAGS_UI,INTERNET_PER_CONN_PROXY_SERVER,INTERNET_PER_CONN_PROXY_BYPASS,INTERNET_PER_CONN_AUTOCONFIG_URL};
    for(int i=0;i<4;++i)options[i].dwOption=keys[i];
    INTERNET_PER_CONN_OPTION_LISTW list{};list.dwSize=sizeof(list);list.dwOptionCount=4;list.pOptions=options;DWORD bytes=sizeof(list);
    const auto ok=InternetQueryOptionW(nullptr,INTERNET_OPTION_PER_CONNECTION_OPTION,&list,&bytes);
    state.flags=options[0].Value.dwValue;
    QString *values[]{&state.proxy,&state.bypass,&state.pac};
    for(int i=1;i<4;++i){*values[i-1]=QString::fromWCharArray(options[i].Value.pszValue?options[i].Value.pszValue:L"");if(options[i].Value.pszValue)GlobalFree(options[i].Value.pszValue);}
    return ok;
}
bool nativeWrite(const WinState &state) {
    INTERNET_PER_CONN_OPTIONW options[4]{};
    options[0].dwOption=INTERNET_PER_CONN_FLAGS;options[0].Value.dwValue=state.flags;
    const DWORD keys[]{INTERNET_PER_CONN_PROXY_SERVER,INTERNET_PER_CONN_PROXY_BYPASS,INTERNET_PER_CONN_AUTOCONFIG_URL};
    const QString *values[]{&state.proxy,&state.bypass,&state.pac};
    for(int i=0;i<3;++i){options[i+1].dwOption=keys[i];options[i+1].Value.pszValue=const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(values[i]->utf16()));}
    INTERNET_PER_CONN_OPTION_LISTW list{};list.dwSize=sizeof(list);list.dwOptionCount=4;list.pOptions=options;
    return InternetSetOptionW(nullptr,INTERNET_OPTION_PER_CONNECTION_OPTION,&list,sizeof(list));
}
void nativeRestore() {
    if(!nativeSaved)return;
    if(!nativeWrite(nativeOriginal)
        || !InternetSetOptionW(nullptr,INTERNET_OPTION_SETTINGS_CHANGED,nullptr,0)
        || !InternetSetOptionW(nullptr,INTERNET_OPTION_REFRESH,nullptr,0)) {
        std::cerr<<"Failed to restore the disposable runner baseline\n";std::_Exit(1);
    }
}
}
static void nativeRoundtrip() {
    check(qEnvironmentVariable("GITHUB_ACTIONS")=="true","native Windows mutation requires a disposable CI runner");
    check(nativeRead(nativeOriginal),"read native WinINet baseline");nativeSaved=true;std::atexit(nativeRestore);
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=prior.invalid:3128","old.invalid","https://pac.invalid/original.pac"};
    check(nativeWrite(original),"seed disposable WinINet PAC/proxy/bypass");
    rasNames.clear();PlatformSystemProxyBackend backend(WindowsProxyApi{InternetQueryOptionW,InternetSetOptionW,entries});
    check(backend.clear().succeeded(),"native clear without snapshot");
    WinState current;check(nativeRead(current) && current.flags==original.flags,"unknown native PAC remains enabled");
    check(backend.apply(config).succeeded(),"native WinINet apply/readback");
    check(backend.clear().succeeded(),"native WinINet restoration");
    check(nativeRead(current) && current.flags==original.flags && current.proxy==original.proxy && current.bypass==original.bypass && current.pac==original.pac,"native original settings restored exactly");
    check(backend.apply(config).succeeded(),"native reapply");
    current={PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY,"http=external.invalid:8899","external.invalid","https://pac.invalid/new.pac"};
    check(nativeWrite(current) && backend.clear().succeeded(),"native external changes during ownership");
    WinState actual;check(nativeRead(actual) && actual.flags==current.flags && actual.proxy==current.proxy && actual.bypass==current.bypass && actual.pac==current.pac,"native external proxy/PAC/bypass retained");
    std::cout<<"PASS: native WinINet apply, restore and external ownership on disposable CI runner\n";
}

#elif defined(Q_OS_MACOS)
#include "macosproxy_test.h"
#else
struct Fixture {
    QMap<QString, QString> values;
    int mutations = 0, failAt = 0;
    bool failRead = false, failWrite = false, ignoreWrite = false, malformed = false, emptyBypass = false;
    PlatformCommandResult run(const QString &program, const QStringList &args) {
        if (program == "dbus-send") return {};
        const bool write = program.startsWith("kwriteconfig") || args.value(0)=="set";
        const bool kde = program.contains("config");
        const auto key = kde ? args.value(5) : args.value(1)+":"+args.value(2);
        if (write) {
            ++mutations;
            if (failWrite || mutations == failAt) return {{Status::PermissionDenied,"denied"},{}};
            if (!ignoreWrite) {
                auto value = args.last();
                if (!kde && value.startsWith('[')) value.replace('"','\'');
                values[key] = value;
            }
            return {};
        }
        if (failRead) return {{Status::Failed,"query failed"},{}};
        if (emptyBypass && key.endsWith(":ignore-hosts")) return {{}, {}};
        QString fallback;
        if(kde) fallback=key=="ProxyType"?"0":key=="ReversedException"?"false":QString();
        else if(key.endsWith(":port"))fallback="0";
        else if(key.endsWith(":use-same-proxy") || key.endsWith(":use-authentication"))fallback="false";
        else if(key.endsWith(":ignore-hosts"))fallback="@as []";
        else fallback=key.endsWith(":mode")?"'none'":"''";
        return {{}, malformed ? QString("invalid") : values.value(key,fallback)};
    }
};
static void backendTests() {
#ifdef Q_OS_LINUX
    qputenv("XDG_CURRENT_DESKTOP","GNOME");
#endif
    Fixture fixture;
    PlatformSystemProxyBackend backend([&](const QString &p, const QStringList &a) { return fixture.run(p,a); });
    fixture.failRead = true;
    check(!backend.check(config).result.succeeded(),"failed read not a conflict answer");
    check(!backend.apply(config).succeeded() && fixture.mutations==0,"failed read prevents writes");
    fixture.failRead = false; fixture.malformed = true;
    check(!backend.check(config).result.succeeded(),"malformed read rejected");
    fixture.malformed = false; fixture.failWrite = true;
    auto result = backend.apply(config);
    check(result.status==Status::PermissionDenied && !result.mayHaveChanged,"failed first write leaves the original settings intact");
    fixture.failWrite = false; fixture.mutations = 0; fixture.failAt = 3;
    result = backend.apply(config);
    check(!result.succeeded() && !result.mayHaveChanged && !backend.check(config).active,"partial application is rolled back and verified");
    fixture.failAt = 0; fixture.values.clear(); fixture.ignoreWrite = true;
    check(!backend.apply(config).succeeded(),"zero exit without state change rejected");
    fixture.ignoreWrite = false;
    check(backend.apply(config).succeeded(),"endpoints and bypass roundtrip");
    check(!backend.check(config).conflict && backend.check(config).active,"configured proxy verified active");
#ifdef Q_OS_LINUX
    check(backend.clear().succeeded(),"restore before selecting another proxy configuration");
#endif
    fixture.emptyBypass = true;
    auto noBypass = config; noBypass.bypass.clear();
    check(!backend.apply(noBypass).succeeded(), "missing bypass output is not a verified empty bypass list");
    fixture.emptyBypass = false;
    check(backend.apply(noBypass).succeeded(), "valid empty bypass representation accepted");
    check(fixture.run("gsettings",{"get","org.gnome.system.proxy.http","use-authentication"}).output == "false", "GNOME HTTP auth disabled without clearing stored credentials");
    fixture.values["org.gnome.system.proxy:mode"] = "['manual']";
    check(!backend.check(config).result.succeeded(), "wrong GVariant value type is not a proxy mode");
    fixture.values["org.gnome.system.proxy:mode"] = "'manual'";
    check(backend.clear().succeeded() && !backend.check(config).active,"disable readback verified");
#ifdef Q_OS_LINUX
    qputenv("XDG_CURRENT_DESKTOP","KDE"); qputenv("KDE_SESSION_VERSION","6");
    fixture.values.clear();
    check(backend.apply(config).succeeded() && backend.clear().succeeded(),"KDE selected without GNOME writes");
    qputenv("XDG_CURRENT_DESKTOP","unknown");
    check(backend.apply(config).status==Status::Unsupported,"unknown desktop explicit unsupported");
#endif
}
#endif

#ifdef Q_OS_LINUX
static void isolatedKde() {
    QTemporaryDir directory;
    check(directory.isValid(),"isolated KDE configuration directory");
    qputenv("XDG_CURRENT_DESKTOP","KDE");qputenv("KDE_SESSION_VERSION","6");
    qputenv("XDG_CONFIG_HOME",directory.path().toUtf8());
    const auto arguments=[&](const QString &key){return QStringList{"--file",directory.filePath("kioslaverc"),"--group","Proxy Settings","--key",key};};
    const auto get=[&](const QString &key){const auto result=runPlatformCommand("kreadconfig6",arguments(key));check(result.result.succeeded(),"native KConfig read");return result.output;};
    const auto set=[&](const QString &key,const QString &value){auto args=arguments(key);args << "--" << value;check(runPlatformCommand("kwriteconfig6",args).result.succeeded(),"native KConfig write");};
    set("ProxyType","2");set("Proxy Config Script","https://pac.example.invalid/original.pac");
    set("httpProxy","http://prior.example.invalid 3128");set("NoProxyFor","old.example.invalid");set("ReversedException","true");
    PlatformSystemProxyBackend backend;
    check(backend.clear().succeeded() && get("ProxyType")=="2","unknown KDE PAC mode remains untouched");
    check(backend.apply(config).succeeded(),"native KDE apply and readback");
    check(get("httpProxy")=="http://127.0.0.1 11081" && get("socksProxy")=="socks://127.0.0.1 11080","native KDE protocol endpoints");
    check(get("ReversedException")=="false","native KDE bypass must retain ordinary exclusion semantics");
    check(backend.clear().succeeded(),"native KDE restore");
    check(get("ProxyType")=="2" && get("Proxy Config Script")=="https://pac.example.invalid/original.pac","native KDE PAC mode and URL restored");
    check(get("httpProxy")=="http://prior.example.invalid 3128" && get("NoProxyFor")=="old.example.invalid" && get("ReversedException")=="true","native KDE original proxy and bypass semantics restored");
    check(backend.apply(config).succeeded(),"native KDE reapply after restore");
    set("httpProxy","http://external.example.invalid 8899");set("NoProxyFor","external.example.invalid");
    check(backend.clear().succeeded(),"native KDE owned fields restored around external settings");
    check(get("httpProxy")=="http://external.example.invalid 8899" && get("NoProxyFor")=="external.example.invalid" && get("ProxyType")=="1","native KDE external endpoint/bypass and dependent mode preserved");
    check(get("ReversedException")=="false","old reverse flag cannot invert external bypass entries");
    set("httpProxy","--delete");
    check(backend.apply(config).succeeded(),"native KDE capture of an option-like original string");
    check(backend.clear().succeeded() && get("httpProxy")=="--delete","original strings must not be interpreted as writer options");
    const auto credentialed=QString("http://fixture-user:fixture-secret@prior.example.invalid 3128");
    set("httpProxy",credentialed);
    check(backend.apply(config).status==Status::Unsupported,"credentialed KDE endpoints must not be passed through writer argv");
    check(get("httpProxy")==credentialed && get("ProxyType")=="1","unsupported credentialed KDE settings remain unchanged");
    std::cout<<"PASS: native KConfig apply, restoration and external ownership in a private directory/bus\n";
}
#endif

int main(int argc, char **argv) {
    QCoreApplication app(argc,argv);
    const auto args = app.arguments();
#ifdef Q_OS_WIN
    if(args.contains("--native-roundtrip")){nativeRoundtrip();return 0;}
#endif
    if (args.size()==3 && args[1]=="--child") {
        if (args[2]=="hang") QThread::sleep(10);
        if (args[2]=="cancel") { std::cerr << "User canceled. (-128)"; return 1; }
        if (args[2]=="denied") { std::cerr << "Permission denied"; return 3; }
        if (args[2]=="fail") return 7;
        if (args[2]=="crash") {
#ifdef Q_OS_WIN
            // Intentional aborts must not wait for Windows Error Reporting UI.
            _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
            std::abort();
        }
        std::cout << "actual child output"; return 0;
    }
    if (args.contains("--readonly")) {
#ifdef Q_OS_LINUX
        qputenv("XDG_CURRENT_DESKTOP","GNOME"); qputenv("GSETTINGS_BACKEND","memory");
#endif
        PlatformSystemProxyBackend backend;
        auto result = backend.check(config);
        check(result.result.succeeded(),qPrintable("Native read-only probe: "+result.result.detail));
        std::cout << "PASS: actual platform query, no system writes\n"; return 0;
    }
#ifdef Q_OS_LINUX
    if(args.contains("--isolated-kde")){isolatedKde();return 0;}
    if (args.contains("--isolated")) {
        QTemporaryDir directory;
        check(directory.isValid(), "isolated GSettings directory");
        qputenv("XDG_CURRENT_DESKTOP", "GNOME"); qputenv("GSETTINGS_BACKEND", "keyfile");
        qputenv("XDG_CONFIG_HOME", directory.path().toUtf8());
        PlatformSystemProxyBackend backend;
        for (const auto &pair : {qMakePair(QString("authentication-user"),QString("retained-user")), qMakePair(QString("authentication-password"),QString("retained-secret"))})
            check(runPlatformCommand("gsettings", {"set","org.gnome.system.proxy.http",pair.first,"'"+pair.second+"'"}).result.succeeded(), "isolated existing credential fixture");
        check(runPlatformCommand("gsettings", {"set","org.gnome.system.proxy.http","use-authentication","true"}).result.succeeded(), "isolated previous auth flag");
        check(runPlatformCommand("gsettings", {"set","org.gnome.system.proxy","mode","'auto'"}).result.succeeded(), "isolated original PAC mode");
        check(runPlatformCommand("gsettings", {"set","org.gnome.system.proxy","autoconfig-url","'https://pac.example.invalid/original.pac'"}).result.succeeded(), "isolated original PAC URL");
        check(runPlatformCommand("gsettings", {"set","org.gnome.system.proxy.http","host","'prior.example.invalid'"}).result.succeeded(), "isolated original HTTP host");
        check(runPlatformCommand("gsettings", {"set","org.gnome.system.proxy.http","port","3128"}).result.succeeded(), "isolated original HTTP port");
        check(runPlatformCommand("gsettings", {"set","org.gnome.system.proxy","ignore-hosts","['old.example.invalid']"}).result.succeeded(), "isolated original bypass");
        check(backend.clear().succeeded(), "clear without an owned snapshot is a no-op");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy","mode"}).output=="'auto'", "unknown PAC settings must not be disabled");
        const auto applied = backend.apply(config);
        check(applied.succeeded(), qPrintable("isolated actual GSettings write/readback: " + applied.detail));
        check(backend.check(config).active && !backend.check(config).conflict, "isolated actual endpoints");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy.socks","port"}).output == "11080", "actual SOCKS port independently verified");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy.http","use-authentication"}).output == "false", "actual HTTP auth flag independently verified");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy.http","authentication-user"}).output == "'retained-user'", "stored proxy username preserved");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy.http","authentication-password"}).output == "'retained-secret'", "stored proxy secret preserved");
        check(backend.clear().succeeded() && !backend.check(config).active, "isolated actual disable/readback");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy","mode"}).output=="'auto'", "original PAC mode restored");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy","autoconfig-url"}).output=="'https://pac.example.invalid/original.pac'", "PAC URL preserved");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy.http","host"}).output=="'prior.example.invalid'", "original HTTP host restored");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy.http","port"}).output=="3128", "original HTTP port restored");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy.http","use-authentication"}).output=="true", "original HTTP auth flag restored");
        check(runPlatformCommand("gsettings", {"get","org.gnome.system.proxy","ignore-hosts"}).output=="['old.example.invalid']", "original bypass restored");
        auto escapedConfig=config;
        escapedConfig.bypass=QString("inside\ttab;")+QChar(0x200c)+"example.invalid";
        PlatformSystemProxyBackend escaping;
        check(escaping.apply(escapedConfig).succeeded(),"native GVariant escape roundtrip does not strand a partial apply");
        check(escaping.clear().succeeded(),"native escaped bypass restores the original settings");
        for(bool failRestore:{false,true}) {
            int writes=0,failAt=failRestore?0:4;
            PlatformSystemProxyBackend failing([&](const QString &program,const QStringList &arguments){
                if(arguments.value(0)=="set" && ++writes==failAt)return PlatformCommandResult{{Status::PermissionDenied,"injected native write denial"},{}};
                return runPlatformCommand(program,arguments);
            });
            const auto result=failing.apply(config);
            if(failRestore) {
                check(result.succeeded(),"native apply before a restore failure");
                failAt=writes+2;
                const auto incomplete=failing.clear();
                check(!incomplete.succeeded() && incomplete.mayHaveChanged,"failed native restore retains cleanup responsibility");
                check(runPlatformCommand("gsettings",{"get","org.gnome.system.proxy.http","use-authentication"}).output=="false","failed endpoint restore cannot re-enable old proxy credentials");
                failAt=0;check(failing.clear().succeeded(),"native restore can resume after a write denial");
            } else check(!result.succeeded() && !result.mayHaveChanged,"native partial apply is rolled back and verified");
            check(runPlatformCommand("gsettings",{"get","org.gnome.system.proxy.http","host"}).output=="'prior.example.invalid'","native failure preserves the original host");
            check(runPlatformCommand("gsettings",{"get","org.gnome.system.proxy.http","port"}).output=="3128","native failure preserves the original port");
            check(runPlatformCommand("gsettings",{"get","org.gnome.system.proxy.http","use-authentication"}).output=="true","native failure restores the original auth flag");
            check(runPlatformCommand("gsettings",{"get","org.gnome.system.proxy","mode"}).output=="'auto'","native failure restores original PAC mode");
        }
        bool replaceEndpoint=false;
        PlatformSystemProxyBackend changing([&](const QString &program,const QStringList &arguments){
            const auto result=runPlatformCommand(program,arguments);
            if(replaceEndpoint && arguments==QStringList{"set","org.gnome.system.proxy.http","port","3128"}) {
                replaceEndpoint=false;
                check(runPlatformCommand("gsettings",{"set","org.gnome.system.proxy.http","host","'external.example.invalid'"}).result.succeeded(),"external endpoint change during restoration");
            }
            return result;
        });
        check(changing.apply(config).succeeded(),"apply before an external mid-restore change");
        replaceEndpoint=true;
        check(changing.clear().succeeded(),"restore while retaining a new external endpoint");
        check(runPlatformCommand("gsettings",{"get","org.gnome.system.proxy.http","host"}).output=="'external.example.invalid'","external endpoint was retained");
        check(runPlatformCommand("gsettings",{"get","org.gnome.system.proxy.http","use-authentication"}).output=="false","old proxy credentials must not be enabled for a new external endpoint");
        check(runPlatformCommand("gsettings",{"get","org.gnome.system.proxy","mode"}).output=="'manual'","old mode must not override a new endpoint during restoration");
        std::cout << "PASS: actual GSettings writes/readback in disposable keyfile backend; no session settings changed\n";
        return 0;
    }
#endif
    const auto self = app.applicationFilePath();
    check(runPlatformCommand(self,{"--child","ok"}).output=="actual child output","child output captured");
    for (const auto &mode : {QString("fail"),QString("crash")}) {
        const auto result = runPlatformCommand(self,{"--child",mode}).result;
        check(result.status == Status::Failed, qPrintable(mode + ": " + result.detail));
    }
    check(runPlatformCommand(self,{"--child","hang"},50).result.status==Status::TimedOut,"child timeout killed and reaped");
    check(runPlatformCommand(self,{"--child","cancel"}).result.status==Status::Cancelled,"user cancellation classified");
    check(runPlatformCommand(self,{"--child","denied"}).result.status==Status::PermissionDenied,"permission denial classified");
    check(!runPlatformCommand(self+".missing",{}).result.succeeded(),"failed process start rejected");
    backendTests();
    std::cout << "PASS: process statuses, backend failures, partial changes and readback\n";
}
