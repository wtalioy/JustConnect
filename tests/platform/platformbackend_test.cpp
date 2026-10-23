#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/platformcommand.h"
#include "infrastructure/platform/proxyrecovery.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QMap>
#include <QThread>
#include <QProcess>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <iostream>
#include <cstdlib>
#ifdef Q_OS_WIN
#include <raserror.h>
#elif defined(Q_OS_LINUX)
#include "infrastructure/platform/linux/persistentproxy.h"
#include "infrastructure/platform/systemcredentialstore.h"
#include <QDir>
#include <QFileInfo>
#include <QLockFile>
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
int writes=0,failAt=0,queries=0,setCalls=0;
DWORD queryError=ERROR_ACCESS_DENIED;
DWORD ignoreOption=0;
BOOL WINAPI query(HINTERNET, DWORD, LPVOID buffer, LPDWORD) {
    ++queries;
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
    ++setCalls;
    if(denySet || ++writes==failAt){SetLastError(ERROR_CANCELLED);return FALSE;}
    if(ignoreSet)return TRUE;
    auto *list=static_cast<INTERNET_PER_CONN_OPTION_LISTW *>(buffer);
    auto &state=states[QString::fromWCharArray(list->pszConnection?list->pszConnection:L"")];
    for(DWORD i=0;i<list->dwOptionCount;++i) {
        const auto &value=list->pOptions[i];
        if(value.dwOption==ignoreOption)continue;
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
    denySet=true;const auto beforeCancel=setCalls;const auto cancelled=backend.apply(config);
    check(cancelled.status==Status::Cancelled && !cancelled.mayHaveChanged && setCalls==beforeCancel+1
          && states[""].flags==original.flags && states[""].proxy==original.proxy && states[""].bypass==original.bypass && states[""].pac==original.pac
          && states["fixture connection"].proxy=="socks=old.invalid:1080",
          "Verified unchanged settings were rewritten or retained false cleanup responsibility after cancellation");
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
    check(backend.apply(config).succeeded(),"apply notification retry fixture");
    const auto recreated = states[""];
    denyNotify=true;check(!backend.clear().succeeded(),"retain pending notification after confirmed native restoration");
    states[""] = recreated;writes=0;denyNotify=false;
    check(backend.clear().succeeded() && writes==0 && states[""].proxy==recreated.proxy && states[""].flags==recreated.flags,
          "Notification retry reacquired a connection whose restoration was already confirmed");
    states[""] = original;
    check(backend.apply(config).succeeded(),"apply before external changes");
    states[""].proxy="http=external.invalid:8899";states[""].bypass="external.invalid";states[""].pac="https://pac.invalid/external.pac";
    states["new connection"]={PROXY_TYPE_PROXY,"new.invalid:1234","new.invalid",{}};rasNames<<"new connection";
    check(backend.clear().succeeded(),"restore owned fields around external changes");
    check(states[""].proxy=="http=external.invalid:8899" && states[""].bypass=="external.invalid" && states[""].flags==(PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY),"external fields and dependent mode retained");
    check(states["new connection"].proxy=="new.invalid:1234" && states["fixture connection"].proxy=="socks=old.invalid:1080","new connections untouched and original RAS restored");
}

static void recoveryRecordTests() {
    rasNames={QStringLiteral("fixture \u6821\u56ed")};states.clear();
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=user:secret@prior.invalid:3128","old.invalid","https://pac.invalid/original?token=private"};
    states[""]=original;states[rasNames[0]]={PROXY_TYPE_DIRECT,"socks=old.invalid:1080","ras.invalid",{}};
    QJsonObject record;
    {
        PlatformSystemProxyBackend owner(WindowsProxyApi{query,set,entries});
        check(owner.apply(config).succeeded(),"Apply owned proxy before snapshot handoff");
        record=QJsonDocument::fromJson(QJsonDocument(owner.recoverySnapshot()).toJson()).object();
    }
    const auto reject=[&](const QJsonObject &invalid) {
        writes=queries=0;PlatformSystemProxyBackend fresh(WindowsProxyApi{query,set,entries});
        check(!fresh.recover(invalid).succeeded() && writes==0 && queries==0,
              "Invalid recovery record reached a native API or reported restored ownership");
    };
    reject({});
    for (const auto *field:{"schema_version","platform","machine","owner","config","connections"}) {
        auto invalid=record;invalid.remove(field);reject(invalid);
    }
    for (const auto *field:{"platform","machine","owner"}) {
        auto invalid=record;invalid[field]="foreign";reject(invalid);
    }
    auto invalid=record;invalid["schema_version"]=1;reject(invalid);
    invalid=record;invalid["schema_version"]=2;reject(invalid);
    invalid=record;invalid["extra"]=true;reject(invalid);
    auto connections=record["connections"].toArray();connections.append(connections[0]);
    invalid=record;invalid["connections"]=connections;reject(invalid);
    for (const auto &flags:QJsonArray{-1,0.5,4294967296.0,"3",true}) {
        connections=record["connections"].toArray();auto connection=connections[0].toObject();connection["flags"]=flags;connections[0]=connection;
        invalid=record;invalid["connections"]=connections;reject(invalid);
    }
    for(const auto *field:{"released","intent","written","uncertain","pending_restore"}) {
        for(const auto &mask:QJsonArray{-1,0.5,8,"2",true,QJsonValue::Null}) {
            connections=record["connections"].toArray();auto connection=connections[0].toObject();connection[field]=mask;connections[0]=connection;
            invalid=record;invalid["connections"]=connections;reject(invalid);
        }
        connections=record["connections"].toArray();auto connection=connections[0].toObject();connection.remove(field);connections[0]=connection;
        invalid=record;invalid["connections"]=connections;reject(invalid);
    }
    for(const auto &patch:QJsonArray{QJsonObject{{"intent",0},{"written",1}},QJsonObject{{"intent",0},{"written",0},{"uncertain",1}},
            QJsonObject{{"released",1},{"uncertain",1}},QJsonObject{{"released",1},{"pending_restore",1}},
            QJsonObject{{"uncertain",1},{"pending_restore",1}}}) {
        connections=record["connections"].toArray();auto connection=connections[0].toObject();
        const auto values=patch.toObject();for(auto it=values.begin();it!=values.end();++it)connection[it.key()]=it.value();
        connections[0]=connection;invalid=record;invalid["connections"]=connections;reject(invalid);
    }
    for (const auto *field:{"name","server","bypass","pac"}) {
        connections=record["connections"].toArray();auto connection=connections[0].toObject();connection[field]=QString("bad")+QChar(0);connections[0]=connection;
        invalid=record;invalid["connections"]=connections;reject(invalid);
    }
    connections=record["connections"].toArray();auto connection=connections[0].toObject();connection["name"]=QString(RAS_MaxEntryName+1,'x');connections[0]=connection;
    invalid=record;invalid["connections"]=connections;reject(invalid);
    invalid=record;auto badConfig=invalid["config"].toObject();badConfig["http_port"]=0;invalid["config"]=badConfig;reject(invalid);
    invalid=record;invalid["machine"]=QString(65536,'x');reject(invalid);
    PlatformSystemProxyBackend fresh(WindowsProxyApi{query,set,entries});
    check(fresh.recover(record).succeeded() && fresh.recoverySnapshot().isEmpty(),"Fresh backend did not release restored snapshot ownership");
    check(states[""].flags==original.flags && states[""].proxy==original.proxy && states[""].bypass==original.bypass && states[""].pac==original.pac
          && states[rasNames[0]].proxy=="socks=old.invalid:1080","Serialized recovery lost distinct connection values or sensitive PAC/proxy material");
    {
        PlatformSystemProxyBackend owner(WindowsProxyApi{query,set,entries});
        check(owner.apply(config).succeeded(),"Apply before external change and fresh recovery");record=owner.recoverySnapshot();
    }
    states[""].proxy="http=external.invalid:8899";states[""].pac="https://pac.invalid/external";
    PlatformSystemProxyBackend external(WindowsProxyApi{query,set,entries});
    check(external.recover(record).succeeded() && states[""].proxy=="http=external.invalid:8899" && states[""].pac=="https://pac.invalid/external"
          && states[""].flags==(PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY),"Fresh recovery overwrote external endpoints, PAC or their dependent mode");
    check(fresh.apply(config).succeeded(),"Apply before notification-only recovery handoff");
    writes=queries=0;
    check(!fresh.recover(record).succeeded() && writes==0 && queries==0,"Import replaced an active backend ownership snapshot");
    const auto recreated=states[""];denyNotify=true;check(!fresh.clear().succeeded(),"Keep unacknowledged notification state");
    record=fresh.recoverySnapshot();states[""]=recreated;writes=0;
    PlatformSystemProxyBackend notifyOnly(WindowsProxyApi{query,set,entries});
    check(!notifyOnly.recover(record).succeeded() && writes==0 && !notifyOnly.recoverySnapshot().isEmpty(),
          "Fresh notification-only recovery dropped an unacknowledged notification");denyNotify=false;
    check(notifyOnly.clear().succeeded() && writes==0 && states[""].proxy==recreated.proxy,
          "Fresh recovery reacquired an already released external same-value recreation");
    std::cout<<"PASS: bounded machine-bound Windows snapshot handoff, strict rejection, sensitive values and released ownership\n";
}

static void fieldReleaseTests() {
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=prior.invalid:3128","old.invalid","https://pac.invalid/original.pac"};
    const auto recoverInterrupted=[&](const QJsonObject &record) {
        PlatformSystemProxyBackend fresh(WindowsProxyApi{query,set,entries});const auto beforeCalls=setCalls;
        const auto result=fresh.recover(record);const auto pending=fresh.recoverySnapshot()["connections"].toArray();
        check(!result.succeeded() && result.mayHaveChanged && setCalls==beforeCalls && pending.size()==1,
              "Fresh interrupted restoration overwrote ambiguous fields");
        const auto uncertain=pending[0].toObject()["uncertain"].toInteger();check(uncertain!=0,"Interrupted restoration lost uncertainty");
        if(uncertain&1)states[""].flags=original.flags;
        if(uncertain&2)states[""].proxy=original.proxy;
        if(uncertain&4)states[""].bypass=original.bypass;
        check(fresh.clear().succeeded(),"External resolution of ambiguous fields did not release remaining responsibility");
    };
    for(const auto &field:QStringList{"server","bypass","flags"})for(const bool observedOriginal:{false,true})for(const bool handoff:{false,true}) {
        states.clear();rasNames.clear();states[""]=original;
        denyQuery=denySet=ignoreSet=denyNotify=denyRas=false;writes=failAt=setCalls=queries=0;ignoreOption=0;
        PlatformSystemProxyBackend owner(WindowsProxyApi{query,set,entries});
        check(owner.apply(config).succeeded(),"Apply before individual field release");const auto installed=states[""];
        if(field=="server")states[""].proxy=observedOriginal?original.proxy:QString("http=external.invalid:8899");
        else if(field=="bypass")states[""].bypass=observedOriginal?original.bypass:QString("external.invalid");
        else states[""].flags=observedOriginal?original.flags:DWORD(PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_DETECT);
        denySet=true;const auto interrupted=owner.clear();
        check(!interrupted.succeeded() && interrupted.mayHaveChanged,"Keep another field's denied restoration pending");
        const auto record=owner.recoverySnapshot();denySet=false;
        if(field=="server")states[""].proxy=installed.proxy;
        else if(field=="bypass")states[""].bypass=installed.bypass;
        else states[""].flags=installed.flags;
        if(handoff) {
            recoverInterrupted(record);
        } else check(owner.clear().succeeded(),"Live instance did not finish remaining fields");
        check(states[""].proxy==(field=="server"?installed.proxy:original.proxy)
              && states[""].bypass==(field=="bypass"?installed.bypass:original.bypass)
              && states[""].flags==((field=="server" || field=="flags")?installed.flags:original.flags)
              && states[""].pac==original.pac,"Restoration reclaimed an already released field or enabled original mode for an external endpoint");
    }
    for(const auto &field:QStringList{"server","flags"})for(const bool handoff:{false,true}) {
        states.clear();rasNames.clear();states[""]=original;ignoreOption=0;
        PlatformSystemProxyBackend owner(WindowsProxyApi{query,set,entries});
        check(owner.apply(config).succeeded(),"Apply before partially successful restoration");const auto installed=states[""];
        ignoreOption=INTERNET_PER_CONN_PROXY_BYPASS;
        check(!owner.clear().succeeded() && states[""].proxy==original.proxy && states[""].flags==original.flags
              && states[""].bypass==installed.bypass,"Observe confirmed original fields alongside a restoration mismatch");
        const auto record=owner.recoverySnapshot();ignoreOption=0;
        if(field=="server")states[""].proxy=installed.proxy;else states[""].flags=installed.flags;
        if(handoff) {
            recoverInterrupted(record);
        } else check(owner.clear().succeeded(),"Retry did not retain partially confirmed fields");
        check(states[""].proxy==(field=="server"?installed.proxy:original.proxy)
              && states[""].flags==(field=="flags"?installed.flags:original.flags) && states[""].bypass==original.bypass,
              "Readback mismatch discarded another field's confirmed restoration");
    }
    std::cout<<"PASS: Windows per-field release survives failed restoration and fresh-instance handoff\n";
}

#include "windowsproxy_checkpoint_test.h"

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
    QJsonObject record;
    {
        PlatformSystemProxyBackend owner(WindowsProxyApi{InternetQueryOptionW,InternetSetOptionW,entries});
        check(owner.apply(config).succeeded(),"Apply real WinINet snapshot owner");
        record=QJsonDocument::fromJson(QJsonDocument(owner.recoverySnapshot()).toJson()).object();
    }
    PlatformSystemProxyBackend recovered(WindowsProxyApi{InternetQueryOptionW,InternetSetOptionW,entries});
    check(recovered.recover(record).succeeded() && nativeRead(current) && current.flags==original.flags && current.proxy==original.proxy
          && current.bypass==original.bypass && current.pac==original.pac,"Fresh WinINet backend lost native original values");
    std::cout<<"PASS: fresh backend restored the native disposable WinINet snapshot\n";
    check(backend.apply(config).succeeded(),"native reapply");
    current={PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY,"http=external.invalid:8899","external.invalid","https://pac.invalid/new.pac"};
    check(nativeWrite(current) && backend.clear().succeeded(),"native external changes during ownership");
    WinState actual;check(nativeRead(actual) && actual.flags==current.flags && actual.proxy==current.proxy && actual.bypass==current.bypass && actual.pac==current.pac,"native external proxy/PAC/bypass retained");
    std::cout<<"PASS: native WinINet apply, restore and external ownership on disposable CI runner\n";
}
static void nativeRecoveryOwner()
{
    check(qEnvironmentVariable("GITHUB_ACTIONS")=="true","native recovery requires a disposable CI runner");
    ProxyRecoveryBackend backend;
    check(backend.check(config).result.succeeded() && backend.apply(config).succeeded(),"Apply through the packaged native recovery worker");
    std::cout << "READY\n" << std::flush;
    std::cin.get();
}
static void nativeRecovery()
{
    check(qEnvironmentVariable("GITHUB_ACTIONS")=="true","native recovery requires a disposable CI runner");
    check(nativeRead(nativeOriginal),"Read native recovery baseline");nativeSaved=true;std::atexit(nativeRestore);
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=prior.invalid:3128","old.invalid","https://pac.invalid/original.pac"};
    check(nativeWrite(original),"Seed disposable native recovery baseline");
    QProcess holder;holder.start(QCoreApplication::applicationFilePath(),{"--native-recovery-owner"},QIODevice::ReadWrite|QIODevice::Text);
    check(holder.waitForStarted(5000) && holder.waitForReadyRead(10000) && holder.readLine()=="READY\n","Start native recovery host fixture");
    WinState current;
    check(nativeRead(current) && current.proxy.contains("127.0.0.1:11081"),"Independent worker did not apply native WinINet");
    holder.kill();check(holder.waitForFinished(5000),"Kill only the disposable native host fixture");
    QElapsedTimer timer;timer.start();
    for (;;) {
        check(nativeRead(current),"Read actual native recovery outcome");
        if (current.flags==original.flags && current.proxy==original.proxy && current.bypass==original.bypass && current.pac==original.pac) break;
        check(timer.elapsed()<5000,"Independent native recovery exceeded its budget");QThread::msleep(10);
    }
    std::cout << "PASS: native WinINet restored exactly by independent worker after Qt host SIGKILL\n";
}

#elif defined(Q_OS_MACOS)
#include "macosproxy_test.h"
#else
struct Fixture {
    QMap<QString, QString> values;
    int mutations = 0, failAt = 0;
    bool failRead = false, failWrite = false, ignoreWrite = false, malformed = false, emptyBypass = false, failNotify = false;
    PlatformCommandResult run(const QString &program, const QStringList &args) {
        if (program == "dbus-send") return {failNotify ? PlatformOperationResult{Status::Failed,"Injected notification failure"} : PlatformOperationResult{},{}};
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
    check(backend.apply(config).succeeded(),"apply KDE notification retry fixture");
    const auto recreated = fixture.values;
    fixture.failNotify=true;check(!backend.clear().succeeded(),"retain pending KDE notification after restoration");
    fixture.values=recreated;fixture.mutations=0;fixture.failNotify=false;
    check(backend.clear().succeeded() && fixture.mutations==0 && fixture.values==recreated,
          "Notification retry reacquired already restored KDE settings");
    qputenv("XDG_CURRENT_DESKTOP","unknown");
    check(backend.apply(config).status==Status::Unsupported,"unknown desktop explicit unsupported");
#endif
}
#endif

#ifdef Q_OS_LINUX
static void recoveryRecordTests() {
    QTemporaryDir directory;check(directory.isValid(),"Private proxy record context");
    qputenv("XDG_CONFIG_HOME",directory.path().toUtf8());qputenv("GSETTINGS_BACKEND","keyfile");qputenv("KDE_SESSION_VERSION","6");
    for (const bool kde:{false,true}) {
        qputenv("XDG_CURRENT_DESKTOP",kde?"KDE":"GNOME");qputenv("XDG_SESSION_DESKTOP",kde?"plasma":"gnome");
        Fixture fixture;int calls=0;
        const PlatformCommandRunner runner=[&](const QString &p,const QStringList &a) { ++calls;return fixture.run(p,a); };
        if (kde) {
            fixture.values={{"ProxyType","2"},{"httpProxy","http://prior.invalid 3128"},{"NoProxyFor","old.invalid"},
                {"ReversedException","true"},{"Proxy Config Script","https://pac.invalid/?token=private"}};
        } else {
            fixture.values={{"org.gnome.system.proxy:mode","'auto'"},{"org.gnome.system.proxy.http:host","'prior.invalid'"},
                {"org.gnome.system.proxy.http:port","3128"},{"org.gnome.system.proxy.http:use-authentication","true"},
                {"org.gnome.system.proxy:ignore-hosts","['old.invalid', '\\u6821\\u56ed.invalid']"},
                {"org.gnome.system.proxy:autoconfig-url","'https://pac.invalid/?token=private'"}};
        }
        QJsonObject record;
        {
            PlatformSystemProxyBackend owner(runner);check(owner.apply(config).succeeded(),"Apply before Linux snapshot handoff");
            record=QJsonDocument::fromJson(QJsonDocument(owner.recoverySnapshot()).toJson()).object();
        }
        const auto reject=[&](const QJsonObject &invalid) {
            calls=0;PlatformSystemProxyBackend fresh(runner);
            check(!fresh.recover(invalid).succeeded() && calls==0,"Invalid Linux recovery record reached a settings command");
        };
        reject({});
        for (const auto *field:{"schema_version","platform","machine","owner","context","config","before","released","intent","written","uncertain","pending_restore"}) {
            auto invalid=record;invalid.remove(field);reject(invalid);
        }
        auto invalid=record;invalid["platform"]="windows";reject(invalid);
        invalid=record;invalid["schema_version"]=1;reject(invalid);
        invalid=record;invalid["intent"]=QJsonArray{};reject(invalid);
        invalid=record;invalid["pending_restore"]="unknown";reject(invalid);
        invalid=record;invalid["machine"]="foreign";reject(invalid);
        invalid=record;invalid["machine"]=QString(65536,'x');reject(invalid);
        invalid=record;invalid["owner"]="foreign";reject(invalid);
        invalid=record;invalid["extra"]=true;reject(invalid);
        for (const auto *field:{"uid","config_root","desktop","settings_backend","dconf_profile"}) {
            auto context=record["context"].toObject();context[field]="foreign";
            invalid=record;invalid["context"]=context;reject(invalid);
        }
        auto before=record["before"].toObject();before["unknown"]="value";invalid=record;invalid["before"]=before;reject(invalid);
        before=record["before"].toObject();before[kde?"ProxyType":"http/port"]="3";invalid=record;invalid["before"]=before;reject(invalid);
        before=record["before"].toObject();before[kde?"ReversedException":"http/use-authentication"]="false";invalid=record;invalid["before"]=before;reject(invalid);
        before=record["before"].toObject();before[kde?"httpProxy":"http/host"]=QString("bad")+QChar(0);invalid=record;invalid["before"]=before;reject(invalid);
        for (const auto &released:QList<QJsonArray>{{"unknown"},{true},{kde?"httpProxy":"http/host",kde?"httpProxy":"http/host"}}) {
            invalid=record;invalid["released"]=released;reject(invalid);
        }
        PlatformSystemProxyBackend fresh(runner);
        check(fresh.recover(record).succeeded() && fresh.recoverySnapshot().isEmpty(),"Fresh Linux backend did not restore and release its record");
        check(fresh.apply(config).succeeded() && fresh.recoverySnapshot()["before"]==record["before"],"Linux handoff lost original types, Unicode, authentication or PAC material");
        calls=0;check(!fresh.recover(record).succeeded() && calls==0,"Import replaced active Linux ownership");
        if (kde) {
            const auto recreated=fixture.values;fixture.failNotify=true;check(!fresh.clear().succeeded(),"Keep pending KDE notification");
            record=fresh.recoverySnapshot();fixture.values=recreated;fixture.mutations=0;fixture.failNotify=false;
            PlatformSystemProxyBackend notifyOnly(runner);
            check(notifyOnly.recover(record).succeeded() && fixture.mutations==0 && fixture.values==recreated,
                  "Fresh KDE recovery reacquired released same-value settings");
        } else {
            fixture.failAt=fixture.mutations+2;check(!fresh.clear().succeeded(),"Inject partial GNOME restoration");
            record=fresh.recoverySnapshot();check(record["released"].toArray().contains("http/host"),"Confirmed GNOME progress was not exported");
            fixture.values["org.gnome.system.proxy.http:host"]="'127.0.0.1'";fixture.failAt=0;
            PlatformSystemProxyBackend retry(runner);
            check(retry.recover(record).succeeded()
                  && fixture.run("gsettings",{"get","org.gnome.system.proxy.http","host"}).output=="'127.0.0.1'"
                  && fixture.run("gsettings",{"get","org.gnome.system.proxy.http","use-authentication"}).output=="false",
                  "Fresh GNOME recovery reacquired a released endpoint or enabled its old credentials");
        }
    }
    std::cout<<"PASS: context-bound GNOME/KDE snapshot handoff, strict rejection, original types and released ownership\n";
}

static void checkpointTests() {
    QTemporaryDir directory;check(directory.isValid(),"Private checkpoint context");
    qputenv("XDG_CONFIG_HOME",directory.path().toUtf8());qputenv("XDG_CURRENT_DESKTOP","GNOME");
    qputenv("XDG_SESSION_DESKTOP","gnome");qputenv("GSETTINGS_BACKEND","keyfile");
    const auto seed=[] {
        Fixture fixture;
        fixture.values={{"org.gnome.system.proxy.http:host","'prior.invalid'"},{"org.gnome.system.proxy.http:port","3128"},
            {"org.gnome.system.proxy.http:use-authentication","true"},{"org.gnome.system.proxy:mode","'auto'"}};
        return fixture;
    };
    {
        auto fixture=seed();
        PlatformSystemProxyBackend backend([&](const QString &p,const QStringList &a){return fixture.run(p,a);},
            [](const QJsonObject &){return PlatformOperationResult{Status::PermissionDenied,"Denied checkpoint"};});
        const auto result=backend.apply(config);
        check(!result.succeeded() && !result.mayHaveChanged && fixture.mutations==0 && backend.recoverySnapshot().isEmpty(),
              "Initial checkpoint rejection reached a settings mutation or invented ownership");
    }
    {
        auto fixture=seed();QJsonObject stored;bool first=true;
        PlatformSystemProxyBackend backend([&](const QString &p,const QStringList &a){return fixture.run(p,a);},
            [&](const QJsonObject &record){stored=record;if(first){first=false;return PlatformOperationResult{Status::Failed,"Lost publication acknowledgement",true};}return PlatformOperationResult{};});
        check(!backend.apply(config).succeeded() && !stored.isEmpty() && fixture.mutations==0,"Unknown initial publication changed settings or lost its record");
        check(backend.clear().succeeded() && stored.isEmpty() && fixture.mutations==0,"Unstarted application required native rollback or lost record removal");
    }
    {
        auto fixture=seed();QJsonObject stored;bool denyRestore=false;int writes=0;
        const PlatformCommandRunner run=[&](const QString &p,const QStringList &a) {
            if(a.value(0)=="set") {
                auto key=a[1].mid(QString("org.gnome.system.proxy").size());if(key.startsWith('.'))key=key.mid(1)+'/';key+=a[2];
                check(stored["intent"].toArray().contains(key) && !stored["released"].toArray().contains(key),"Native mutation preceded durable ownership intent");
                check(stored["pending_restore"].toString()==key || !stored["written"].toArray().contains(key),"Native restore preceded its checkpoint");++writes;
            }
            return fixture.run(p,a);
        };
        PlatformSystemProxyBackend backend(run,[&](const QJsonObject &record) {
            if(denyRestore && !record["pending_restore"].toString().isEmpty())return PlatformOperationResult{Status::PermissionDenied,"Denied restore checkpoint"};
            stored=record;return PlatformOperationResult{};
        });
        check(backend.apply(config).succeeded() && stored["written"].toArray().size()==writes,"Confirmed applied values were not checkpointed");
        const auto appliedWrites=writes;denyRestore=true;
        const auto result=backend.clear();
        check(!result.succeeded() && result.mayHaveChanged && writes==appliedWrites,"Denied restore checkpoint allowed another native mutation");
        denyRestore=false;check(backend.clear().succeeded() && stored.isEmpty(),"Confirmed checkpoint retry did not finish rollback");
    }
    {
        auto fixture=seed();QJsonObject stored;bool injected=false;
        PlatformSystemProxyBackend backend([&](const QString &p,const QStringList &a){return fixture.run(p,a);},
            [&](const QJsonObject &record) {
                stored=record;
                if(!injected && record["intent"].toArray().contains("http/host")) {
                    injected=true;fixture.values["org.gnome.system.proxy.http:host"]="'127.0.0.1'";
                }
                return PlatformOperationResult{};
            });
        check(!backend.apply(config).succeeded() && injected && fixture.mutations==1
              && fixture.values["org.gnome.system.proxy.http:host"]=="'127.0.0.1'"
              && fixture.values["org.gnome.system.proxy.http:use-authentication"]=="false",
              "Checkpoint-time external endpoint was overwritten or inherited original credentials");
    }
    for (const bool external:{false,true}) {
        auto fixture=seed();QJsonObject stored,intentRecord;QMap<QString,QString> atIntent;int hostWrites=0;
        const PlatformCommandRunner run=[&](const QString &p,const QStringList &a) {
            if(a.value(0)=="set" && a.value(1)=="org.gnome.system.proxy.http" && a.value(2)=="host")++hostWrites;
            return fixture.run(p,a);
        };
        const auto persist=[&](const QJsonObject &record) {
            stored=record;
            if(intentRecord.isEmpty() && record["intent"].toArray().contains("http/host") && !record["written"].toArray().contains("http/host")) {
                intentRecord=record;atIntent=fixture.values;
            }
            return PlatformOperationResult{};
        };
        {PlatformSystemProxyBackend owner(run,persist);check(owner.apply(config).succeeded(),"Capture application write-ahead boundary");}
        check(!intentRecord.isEmpty(),"Application intent was not checkpointed before its native write");
        fixture.values=atIntent;stored=intentRecord;hostWrites=0;
        if(external)fixture.values["org.gnome.system.proxy.http:host"]="'127.0.0.1'";
        PlatformSystemProxyBackend fresh(run,persist);const auto result=fresh.recover(intentRecord);
        check(hostWrites==0 && result.succeeded()!=external,"Fresh application intent guessed an unconfirmed native write");
        if(external) {
            check(result.mayHaveChanged && stored["uncertain"].toArray().contains("http/host")
                  && fixture.values["org.gnome.system.proxy.http:use-authentication"]=="false","Ambiguous application inherited original endpoint credentials");
            fixture.values["org.gnome.system.proxy.http:host"]="'prior.invalid'";
            check(fresh.clear().succeeded() && hostWrites==0 && stored.isEmpty(),"Resolved application intent did not finish recovery");
        } else check(stored.isEmpty(),"Unexecuted intent retained a completed recovery record");
    }
    {
        auto fixture=seed();QJsonObject stored;bool denyRelease=false;int hostWrites=0;
        const PlatformCommandRunner run=[&](const QString &p,const QStringList &a) {
            if(a.value(0)=="set" && a.value(1)=="org.gnome.system.proxy.http" && a.value(2)=="host")++hostWrites;
            return fixture.run(p,a);
        };
        const auto persist=[&](const QJsonObject &record) {
            if(denyRelease && record["released"].toArray().contains("http/host"))return PlatformOperationResult{Status::Failed,"Lost restored-value checkpoint"};
            stored=record;return PlatformOperationResult{};
        };
        {
            PlatformSystemProxyBackend owner(run,persist);check(owner.apply(config).succeeded(),"Apply before interrupted restoration checkpoint");
            denyRelease=true;check(!owner.clear().succeeded(),"Restoration checkpoint failure was acknowledged");
            check(stored["pending_restore"]=="http/host" && fixture.values["org.gnome.system.proxy.http:host"]=="\"prior.invalid\"",
                  "Interrupted restoration did not retain its write-ahead marker");
        }
        fixture.values["org.gnome.system.proxy.http:host"]="'127.0.0.1'";hostWrites=0;denyRelease=false;
        PlatformSystemProxyBackend fresh(run,persist);const auto result=fresh.recover(stored);
        check(!result.succeeded() && result.mayHaveChanged && hostWrites==0 && stored["uncertain"].toArray().contains("http/host")
              && fixture.values["org.gnome.system.proxy.http:use-authentication"]=="false",
              "Fresh recovery reclaimed matching settings after an unconfirmed restore");
        fixture.values["org.gnome.system.proxy.http:host"]="'prior.invalid'";
        check(fresh.clear().succeeded() && hostWrites==0 && stored.isEmpty()
              && fixture.values["org.gnome.system.proxy.http:port"]=="3128"
              && fixture.values["org.gnome.system.proxy.http:use-authentication"]=="true",
              "Resolved uncertainty did not finish owned recovery or exposed original credentials too early");
    }
    {
        class Store final : public CredentialStore {
        public:
            QByteArray bytes;bool present=true;int reads=0;
            CredentialResult read(const QString &) override {++reads;return present?CredentialResult{CredentialStatus::Success,bytes}:CredentialResult{CredentialStatus::NotFound,{}};}
            CredentialResult write(const QString &,const QByteArray &) override {check(false,"Invalid recovery record was overwritten");return {};}
            CredentialResult remove(const QString &) override {check(false,"Invalid recovery record was removed");return {};}
        } store;
        auto fixture=seed();QJsonObject record;
        {PlatformSystemProxyBackend owner([&](const QString &p,const QStringList &a){return fixture.run(p,a);});
         check(owner.apply(config).succeeded(),"Seed a typed recovery record");record=owner.recoverySnapshot();}
        record["machine"]="foreign";
        const auto foreign=QJsonDocument(record).toJson(QJsonDocument::Compact);
        for(const auto &invalid:QList<QByteArray>{QByteArray{},"not-json","{}",foreign}) {
            store.bytes=invalid;store.present=true;int calls=0;
            LinuxPersistentProxyBackend backend(store,QString(64,'a'),[&](const QString &p,const QStringList &a){++calls;return fixture.run(p,a);});
            const auto result=backend.clear();
            check(!result.succeeded() && !result.mayHaveChanged && !backend.apply(config).succeeded() && calls==0 && store.bytes==invalid,
                  "Invalid protected recovery reached native operations, allowed a new application or lost its original bytes");
            const auto reads=store.reads;store.present=false;
            check(!backend.clear().succeeded() && !backend.apply(config).succeeded() && store.reads==reads && calls==0,
                  "External deletion after rejected recovery was mistaken for successful restoration");
        }
    }
    std::cout<<"PASS: proxy write-ahead intents, confirmed values, denied checkpoints, external races and fresh-backend uncertainty\n";
}

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
    QJsonObject record;
    const PlatformCommandRunner native=[](const QString &p,const QStringList &a){return runPlatformCommand(p,a);};
    const PlatformSystemProxyBackend::CheckpointWriter persist=[&](const QJsonObject &value){record=value;return PlatformOperationResult{};};
    {
        PlatformSystemProxyBackend owner(native,persist);check(owner.apply(config).succeeded(),"Apply native KDE snapshot owner");
        check(record==owner.recoverySnapshot() && !record["written"].toArray().isEmpty(),"Native KConfig applied values were not checkpointed");
    }
    const auto savedRecord=record;PlatformSystemProxyBackend recovered(native,persist);
    check(recovered.recover(savedRecord).succeeded() && record.isEmpty() && get("httpProxy")=="http://prior.example.invalid 3128" && get("NoProxyFor")=="old.example.invalid"
          && get("ReversedException")=="true" && get("ProxyType")=="2" && get("Proxy Config Script")=="https://pac.example.invalid/original.pac",
          "Fresh native KConfig backend lost original snapshot values");
    std::cout<<"PASS: fresh backend restored the native private KConfig snapshot\n";
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

static void protectedProxyPhase(const QString &phase,const QString &key) {
    const auto root=QFileInfo(qEnvironmentVariable("XDG_CONFIG_HOME")).dir();
    check(qEnvironmentVariable("GSETTINGS_BACKEND")=="keyfile"
          && root.dirName().startsWith("JustConnect-secret-test-")
          && root.absolutePath().startsWith(QDir::tempPath()+'/'),"Refuse daily proxy and credential settings");
    QLockFile ownership(root.filePath("proxy-test.lock"));ownership.setStaleLockTime(0);
    check(ownership.tryLock(),"Acquire private proxy recovery ownership");
    auto credentials=createSystemCredentialStore();int mutations=0,calls=0;
    LinuxPersistentProxyBackend backend(*credentials,key,[&](const QString &p,const QStringList &a) {
        ++calls;if(a.value(0)=="set")++mutations;return runPlatformCommand(p,a);
    });
    const auto all=[] {
        const auto result=runPlatformCommand("gsettings",{"list-recursively","org.gnome.system.proxy"});
        check(result.result.succeeded(),"Read complete private proxy settings");return result.output.toUtf8();
    };
    if(phase=="unavailable" || phase=="locked") {
        const auto before=all();const auto result=backend.clear();
        check(!result.succeeded() && result.mayHaveChanged && calls==0 && all()==before,
              "Unavailable/locked recovery storage reached native proxy operations or claimed cleanup");
    } else if(phase=="prepare" || phase=="denied") {
        const auto set=[](const QString &schema,const QString &key,const QString &value) {
            check(runPlatformCommand("gsettings",{"set",schema,key,value}).result.succeeded(),"Seed private native proxy values");
        };
        set("org.gnome.system.proxy.http","host","'prior.invalid'");
        set("org.gnome.system.proxy.http","port","3128");
        set("org.gnome.system.proxy.http","use-authentication","true");
        set("org.gnome.system.proxy.http","authentication-user","'fixture user'");
        set("org.gnome.system.proxy.http","authentication-password","'fixture password'");
        set("org.gnome.system.proxy","autoconfig-url","'https://sensitive-proxy-fixture.invalid/token'");
        set("org.gnome.system.proxy","mode","'auto'");
        const auto before=all();
        if(phase=="prepare") {
            bool legacyExcluded=false;
            {
                const auto directory=QDir(qEnvironmentVariable("XDG_DATA_HOME")).filePath("JustConnect");
                check(QDir().mkpath(directory),"Create private legacy recovery directory");
                QLockFile legacy(directory+"/proxy-recovery.lock");legacy.setStaleLockTime(0);
                check(legacy.tryLock(),"Represent a live pre-upgrade recovery owner");
                {
                    ProxyRecoveryBackend candidate;const auto result=candidate.check(config).result;
                    legacyExcluded=result.status==Status::Failed && result.detail.contains("ownership lock");
                }
            }
            check(legacyExcluded && all()==before,"New worker bypassed a live pre-upgrade recovery owner");
            bool excluded=false;
            {
                ProxyRecoveryBackend first;
                check(first.check(config).result.succeeded(),"Start read-only proxy owner");
                const auto data=qgetenv("XDG_DATA_HOME"),temporary=qgetenv("TMPDIR");
                const auto otherTemporary=root.filePath("other-tmp");
                check(QDir().mkpath(otherTemporary),"Create private alternate temporary directory");
                qputenv("XDG_DATA_HOME",root.filePath("other-data").toUtf8());qputenv("TMPDIR",otherTemporary.toUtf8());
                {
                    ProxyRecoveryBackend second;const auto result=second.check(config).result;
                    excluded=result.status==Status::Failed && result.detail.contains("ownership lock");
                }
                qputenv("XDG_DATA_HOME",data);
                if(temporary.isNull())qunsetenv("TMPDIR");else qputenv("TMPDIR",temporary);
            }
            check(excluded && all()==before,"Different data/temp roots admitted concurrent proxy owners");
            std::cout<<"PASS: one user proxy owner across different data and temporary roots\n";
        }
        const auto result=backend.apply(config);
        if(phase=="denied") {
            check(!result.succeeded() && mutations==0 && all()==before && backend.clear().succeeded()
                  && credentials->read(key).status==CredentialStatus::NotFound,"Denied protected checkpoint changed native settings");
        } else {
            check(result.succeeded() && mutations>0 && credentials->read(key).succeeded(),"Native application did not persist protected recovery");
            QFile baseline(root.filePath("proxy-before.txt"));
            check(baseline.open(QIODevice::WriteOnly) && baseline.write(before)==before.size(),"Preserve private native test baseline");
            // Exit without clear: the next process must use only the persisted protected record.
        }
    } else if(phase=="finish") {
        QFile baseline(root.filePath("proxy-before.txt"));check(baseline.open(QIODevice::ReadOnly),"Read original private native baseline");
        const auto original=baseline.readAll();
        check(backend.clear().succeeded() && mutations>0 && all()==original
              && credentials->read(key).status==CredentialStatus::NotFound,"Fresh process lost original values or retained a completed record");
        ownership.unlock();
        ProxyRecoveryBackend worker;
        check(worker.check(config).result.succeeded() && worker.apply(config).succeeded()
              && credentials->read(LinuxPersistentProxyBackend::credentialKey()).succeeded() && all()!=original,
              "Packaged worker did not use protected checkpoints for actual native application");
        check(worker.clear().succeeded() && all()==original
              && credentials->read(LinuxPersistentProxyBackend::credentialKey()).status==CredentialStatus::NotFound,
              "Packaged worker did not restore native settings and remove its protected record");
    } else check(false,"Unknown protected recovery phase");
    std::cout<<"PASS: protected native proxy recovery "<<phase.toStdString()<<'\n';
}
#endif

int main(int argc, char **argv) {
    QCoreApplication app(argc,argv);
    const auto args = app.arguments();
#ifdef Q_OS_WIN
    if(args.contains("--native-roundtrip")){nativeRoundtrip();return 0;}
    if(args.contains("--native-recovery-owner")){nativeRecoveryOwner();return 0;}
    if(args.contains("--native-recovery")){nativeRecovery();return 0;}
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
    if(args.size()==3 && CredentialStore::validKey(args[2])){protectedProxyPhase(args[1],args[2]);return 0;}
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
        const auto originalSettings=runPlatformCommand("gsettings",{"list-recursively","org.gnome.system.proxy"});
        check(originalSettings.result.succeeded(),"Read all private GSettings before snapshot handoff");
        const PlatformCommandRunner native=[](const QString &p,const QStringList &a){return runPlatformCommand(p,a);};
        PlatformSystemProxyBackend denied(native,[](const QJsonObject &){return PlatformOperationResult{Status::PermissionDenied,"Denied checkpoint"};});
        const auto rejected=denied.apply(config);
        check(!rejected.succeeded() && !rejected.mayHaveChanged && runPlatformCommand("gsettings",{"list-recursively","org.gnome.system.proxy"}).output==originalSettings.output,
              "Native GSettings changed after its initial checkpoint was refused");
        QJsonObject record;
        const PlatformSystemProxyBackend::CheckpointWriter persist=[&](const QJsonObject &value){record=value;return PlatformOperationResult{};};
        {
            PlatformSystemProxyBackend owner(native,persist);check(owner.apply(config).succeeded(),"Apply native GSettings snapshot owner");
            check(record==owner.recoverySnapshot() && !record["written"].toArray().isEmpty(),"Native GSettings applied values were not checkpointed");
        }
        const auto savedRecord=record;PlatformSystemProxyBackend recovered(native,persist);
        check(recovered.recover(savedRecord).succeeded() && record.isEmpty(),"Fresh native GSettings snapshot restoration");
        const auto restoredSettings=runPlatformCommand("gsettings",{"list-recursively","org.gnome.system.proxy"});
        check(restoredSettings.result.succeeded() && restoredSettings.output==originalSettings.output,
              "Fresh native GSettings backend lost values or changed retained authentication material");
        std::cout<<"PASS: fresh backend restored the complete native private GSettings snapshot\n";
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
#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    recoveryRecordTests();
#endif
#ifdef Q_OS_WIN
    fieldReleaseTests();
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_WIN)
    checkpointTests();
#endif
    std::cout << "PASS: process statuses, backend failures, partial changes and readback\n";
}
