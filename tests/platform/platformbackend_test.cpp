#include "infrastructure/systemproxy/platformsystemproxybackend.h"
#include "infrastructure/systemproxy/proxyvalidation.h"
#include "infrastructure/process/command.h"
#include "infrastructure/systemproxy/proxyrecovery.h"
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
#if defined(Q_OS_WIN)
#include <raserror.h>
#endif
#if defined(Q_OS_WIN)
#include "infrastructure/systemproxy/persistentproxy.h"
#include "infrastructure/credentialstore/systemcredentialstore.h"
#endif

static void check(bool ok, const char *message) { if (!ok) { std::cerr << message << '\n'; std::exit(1); } }
using Status = PlatformOperationResult::Status;
const SystemProxyConfig config{11081,11080,"localhost;*.example.test"};
#include "proxyworkerfixture.h"
#include "scopedproxy_test.h"

#if defined(Q_OS_WIN)
namespace {
struct WinState { DWORD flags=PROXY_TYPE_DIRECT; QString proxy,bypass,pac; };
QMap<QString,WinState> states;
QStringList rasNames{"fixture connection"};
bool denyQuery=false,denySet=false,ignoreSet=false,denyNotify=false,denyRas=false;
int writes=0,failAt=0,queries=0,setCalls=0;
DWORD queryError=ERROR_ACCESS_DENIED;
DWORD ignoreOption=0;
std::function<void()> beforeProxySet;
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
    if(beforeProxySet)beforeProxySet();
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
    for (const DWORD flags:{DWORD(PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY),DWORD(PROXY_TYPE_PROXY)}) for (const bool handoff:{false,true}) {
        states.clear();rasNames={"inactive"};
        states[""]={flags,"http=127.0.0.1:7897;https=127.0.0.1:7897","keep.invalid",{}};
        states["inactive"]={PROXY_TYPE_DIRECT,"old.invalid:3128","other.invalid",{}};
        auto automatic=config;automatic.upstream={"127.0.0.1:7897"};
        PlatformSystemProxyBackend owner(WindowsProxyApi{query,set,entries});
        const auto observed=owner.inspect();
        check(observed.result.succeeded() && observed.active && !observed.managed && observed.endpoints==automatic.upstream,"Observe original local upstream without changing settings");
        check(owner.apply(automatic).succeeded() && states[""].flags==flags && states[""].bypass=="keep.invalid" && states["inactive"].flags==PROXY_TYPE_DIRECT,
              "Automatic handoff changed mode flags, bypass or an inactive RAS connection");
        check(owner.inspect().managed && owner.inspect().endpoints==automatic.upstream,"Owned frontend obscured its original upstream");
        if (handoff) {
            PlatformSystemProxyBackend fresh(WindowsProxyApi{query,set,entries});
            check(fresh.recover(owner.recoverySnapshot()).succeeded() && states[""].proxy.contains(":7897") && states[""].bypass=="keep.invalid",
                  "Automatic handoff record could not recover its original proxy");
        } else {
            states[""].flags=PROXY_TYPE_DIRECT;
            check(!owner.inspect().active && owner.inspect().endpoints.isEmpty() && owner.clear().succeeded()
                  && states[""].flags==PROXY_TYPE_DIRECT,"Automatic restore re-enabled a user-disabled system proxy");
        }
    }

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
#include "windowsproxy_persistence_test.h"

namespace {
WinState nativeOriginal;
bool nativeSaved=false;
std::unique_ptr<CredentialStore> nativeCredentials;
QString nativeCredentialKey;
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
    if(nativeCredentials && !nativeCredentialKey.isEmpty()) {
        const auto result=nativeCredentials->remove(nativeCredentialKey);
        if(!result.succeeded() && result.status!=CredentialStatus::NotFound) {
            std::cerr<<"Failed to remove the private native proxy test credential\n";std::_Exit(1);
        }
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
    nativeCredentials=createSystemCredentialStore();
    const auto privateKey=QString::fromLatin1(QCryptographicHash::hash("JustConnect-native-proxy-recovery/"+QUuid::createUuid().toRfc4122(),QCryptographicHash::Sha256).toHex());
    check(nativeCredentials->read(privateKey).status==CredentialStatus::NotFound,"Private native proxy recovery credential already exists");
    nativeCredentialKey=privateKey;
    {
        PersistentProxyBackend owner(*nativeCredentials,privateKey,WindowsProxyApi{InternetQueryOptionW,InternetSetOptionW,entries});
        check(owner.apply(config).succeeded() && nativeCredentials->read(privateKey).succeeded(),
              "Native WinINet mutation was not backed by Windows protected storage");
    }
    PersistentProxyBackend protectedRecovery(*nativeCredentials,privateKey,WindowsProxyApi{InternetQueryOptionW,InternetSetOptionW,entries});
    check(protectedRecovery.clear().succeeded() && nativeCredentials->read(privateKey).status==CredentialStatus::NotFound
          && nativeRead(current) && current.flags==original.flags && current.proxy==original.proxy
          && current.bypass==original.bypass && current.pac==original.pac,
          "Fresh Windows protected recovery lost native settings or its confirmed credential removal");
    std::cout<<"PASS: shared persistent backend restored native WinINet from Credential Manager and confirmed removal\n";
    check(backend.apply(config).succeeded(),"native reapply");
    current={PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY,"http=external.invalid:8899","external.invalid","https://pac.invalid/new.pac"};
    check(nativeWrite(current) && backend.clear().succeeded(),"native external changes during ownership");
    WinState actual;check(nativeRead(actual) && actual.flags==current.flags && actual.proxy==current.proxy && actual.bypass==current.bypass && actual.pac==current.pac,"native external proxy/PAC/bypass retained");
    std::cout<<"PASS: native WinINet apply, restore and external ownership on disposable CI runner\n";
}
#include "windowsproxy_worker_test.h"

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
    auto credentials=createSystemCredentialStore();const auto key=PersistentProxyBackend::credentialKey();
    check(credentials->read(key).status==CredentialStatus::NotFound,"Native host recovery record already exists");
    check(nativeRead(nativeOriginal),"Read native recovery baseline");nativeSaved=true;std::atexit(nativeRestore);
    const WinState original{PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL,"http=prior.invalid:3128","old.invalid","https://pac.invalid/original.pac"};
    check(nativeWrite(original),"Seed disposable native recovery baseline");
    QProcess holder;holder.start(QCoreApplication::applicationFilePath(),{"--native-recovery-owner"},QIODevice::ReadWrite|QIODevice::Text);
    check(holder.waitForStarted(5000) && holder.waitForReadyRead(10000) && holder.readLine()=="READY\n","Start native recovery host fixture");
    WinState current;
    check(nativeRead(current) && current.proxy.contains("127.0.0.1:11081"),"Independent worker did not apply native WinINet");
    check(credentials->read(key).succeeded(),"Native host recovery has no protected checkpoint");
    holder.kill();check(holder.waitForFinished(5000),"Kill only the disposable native host fixture");
    QElapsedTimer timer;timer.start();
    for (;;) {
        check(nativeRead(current),"Read actual native recovery outcome");
        if (current.flags==original.flags && current.proxy==original.proxy && current.bypass==original.bypass && current.pac==original.pac) break;
        check(timer.elapsed()<5000,"Independent native recovery exceeded its budget");QThread::msleep(10);
    }
    for(;;) {
        WindowsProxyRecoveryLock released;
        if(released.isLocked()) {
            check(credentials->read(key).status==CredentialStatus::NotFound,"Host recovery released its user lock before record cleanup");break;
        }
        check(timer.elapsed()<5000,"Native recovery did not release user ownership");QThread::msleep(10);
    }
    std::cout << "PASS: native WinINet restored exactly by independent worker after Qt host SIGKILL\n";
}

#else
#include "macosproxy_test.h"
#include "macosproxy_worker_test.h"
#endif



int main(int argc, char **argv) {
    QCoreApplication app(argc,argv);
    const auto args = app.arguments();
#if defined(Q_OS_MACOS)
    if (args.contains("--native-ownership") || args.contains("--native-persistent-recovery")
        || args.contains("--native-scope-probe") || args.contains("--native-foreign-scope-probe")) {
        try {
            if (args.contains("--native-ownership")) nativeMacOwnership();
            else if (args.contains("--native-persistent-recovery")) nativeMacPersistentRecovery();
            else nativeMacLockProbe(args.contains("--native-foreign-scope-probe"));
            return 0;
        } catch(const std::exception &error) {std::cerr<<error.what()<<'\n';return 1;}
    }
#endif
#if defined(Q_OS_WIN)
    if(args.contains("--native-roundtrip")){nativeRoundtrip();return 0;}
    if(args.contains("--native-recovery-owner")){nativeRecoveryOwner();return 0;}
    if(args.contains("--native-recovery")){nativeRecovery();return 0;}
    if(args.contains("--native-persistent-recovery")) {
        try {nativePersistentRecovery();return 0;}
        catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
    }
#endif
    if (args.size()==3 && args[1]=="--child") {
        if (args[2]=="hang") QThread::sleep(10);
        if (args[2]=="cancel") { std::cerr << "User canceled. (-128)"; return 1; }
        if (args[2]=="denied") { std::cerr << "Permission denied"; return 3; }
        if (args[2]=="fail") return 7;
        if (args[2]=="crash") {
#if defined(Q_OS_WIN)
            // Intentional aborts must not wait for Windows Error Reporting UI.
            _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
            std::abort();
        }
        std::cout << "actual child output"; return 0;
    }
    if (args.contains("--readonly")) {
        PlatformSystemProxyBackend backend;
        auto result = backend.check(config);
        check(result.result.succeeded(),qPrintable("Native read-only probe: "+result.result.detail));
        std::cout << "PASS: actual platform query, no system writes\n"; return 0;
    }
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
#if defined(Q_OS_WIN)
    recoveryRecordTests();
#endif
#if defined(Q_OS_WIN)
    fieldReleaseTests();
    persistenceTests();
#endif
#if defined(Q_OS_WIN)
    checkpointTests();
#endif
    std::cout << "PASS: process statuses, backend failures, partial changes and readback\n";
}
