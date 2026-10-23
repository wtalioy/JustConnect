#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/proxyvalidation.h"
#include "application/credentialstore.h"
#include <QStandardPaths>
#include <QVariant>
#include <QSet>
#include <QSysInfo>
#include <QUuid>
#include <algorithm>
#include <unistd.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
bool kde() { return qEnvironmentVariable("XDG_CURRENT_DESKTOP").contains("KDE", Qt::CaseInsensitive)
    || qEnvironmentVariable("XDG_SESSION_DESKTOP").compare("plasma", Qt::CaseInsensitive) == 0; }
bool gnome() {
    const auto desktop = qEnvironmentVariable("XDG_CURRENT_DESKTOP") + ':' + qEnvironmentVariable("XDG_SESSION_DESKTOP");
    return desktop.contains("GNOME", Qt::CaseInsensitive) || desktop.contains("Unity", Qt::CaseInsensitive)
        || desktop.contains("Cinnamon", Qt::CaseInsensitive);
}
// gsettings prints GVariant strings, which may use either quote style.
QStringList strings(const QString &value, bool &ok, bool array) {
    QString input = value.trimmed();
    if (input.startsWith("@as ")) input.remove(0,4);
    ok = false;
    if (input.isEmpty()) return {};
    if (array) {
        if (!input.startsWith('[') || !input.endsWith(']')) return {};
        input = input.mid(1,input.size()-2).trimmed();
    }
    QStringList values; qsizetype i = 0;
    while (i < input.size()) {
        while (i < input.size() && input[i].isSpace()) ++i;
        if (i == input.size()) break;
        const auto quote = input[i++];
        if (quote != '\'' && quote != '"') return {};
        QString item; bool closed = false;
        while (i < input.size()) {
            auto ch = input[i++];
            if (ch == quote) { closed = true; break; }
            if (ch == '\\') {
                if (i == input.size()) return {};
                ch = input[i++];
                if (ch == 'u' || ch == 'U') {
                    const int count=ch=='u'?4:8;
                    if(input.size()-i<count)return {};
                    const auto digits=input.mid(i,count);
                    for(const auto digit:digits)if(!((digit>='0' && digit<='9') || (digit>='a' && digit<='f') || (digit>='A' && digit<='F')))return {};
                    bool valid=false;const char32_t point=digits.toUInt(&valid,16);
                    if(!valid || point==0 || point>0x10ffff || (point>=0xd800 && point<=0xdfff))return {};
                    item+=QString::fromUcs4(&point,1);i+=count;continue;
                }
                const auto control=QStringLiteral("abfnrtv").indexOf(ch);
                if(control>=0)ch=QStringLiteral("\a\b\f\n\r\t\v")[control];
                else if(ch=='\n')continue;
                else if (ch != '\\' && ch != '\'' && ch != '"') return {};
            }
            item += ch;
        }
        if (!closed) return {};
        values.append(item);
        while (i < input.size() && input[i].isSpace()) ++i;
        if (i == input.size()) break;
        if (!array || input[i++] != ',') return {};
    }
    ok = array || values.size() == 1;
    return values;
}

Result available() {
    if (!kde() && !gnome()) return {Status::Unsupported, "Desktop system proxy is unsupported"};
    if (kde() && qEnvironmentVariable("KDE_SESSION_VERSION") != "5" && qEnvironmentVariable("KDE_SESSION_VERSION") != "6")
        return {Status::Unsupported, "KDE session version is unsupported"};
    return {};
}
}

namespace {
const QStringList protocols{"http", "https", "ftp", "socks"};
struct Target {
    QString reader, writer, file;
    bool isKde() const { return !file.isEmpty(); }
    QStringList arguments(const QString &key, bool write) const {
        if (isKde()) {
            QStringList args{"--file",file,"--group","Proxy Settings","--key",key};
            if (!write && key=="ProxyType") args << "--default" << "0";
            if (!write && key=="ReversedException") args << "--default" << "false";
            return args;
        }
        const auto parts=key.split('/');
        return {write?"set":"get", "org.gnome.system.proxy"+(parts.size()==2?"."+parts[0]:QString()),parts.last()};
    }
    QString modeKey() const { return isKde()?"ProxyType":"mode"; }
    QString bypassKey() const { return isKde()?"NoProxyFor":"ignore-hosts"; }
    QString pacKey() const { return isKde()?"Proxy Config Script":"autoconfig-url"; }
    QStringList endpointKeys(const QString &protocol) const {
        if (isKde()) return {protocol+"Proxy"};
        QStringList keys{protocol+"/host",protocol+"/port"};
        if(protocol=="http")keys << "http/use-authentication";
        return keys;
    }
    QStringList keys() const {
        QStringList result;
        for(const auto &protocol:protocols) result.append(endpointKeys(protocol));
        result << bypassKey();
        result << (isKde()?"ReversedException":"use-same-proxy");
        result << modeKey() << pacKey();
        return result;
    }
};
Target currentTarget() {
    if(!kde())return {"gsettings","gsettings",{}};
    const auto version=qEnvironmentVariable("KDE_SESSION_VERSION");
    return {"kreadconfig"+version,"kwriteconfig"+version,QStandardPaths::writableLocation(QStandardPaths::ConfigLocation)+"/kioslaverc"};
}
QJsonObject currentContext() {
    return {{"uid",qint64(geteuid())},{"config_root",QStandardPaths::writableLocation(QStandardPaths::ConfigLocation)},
        {"desktop",kde()?"kde"+qEnvironmentVariable("KDE_SESSION_VERSION"):QString("gnome")},
        {"settings_backend",qEnvironmentVariable("GSETTINGS_BACKEND")},{"dconf_profile",qEnvironmentVariable("DCONF_PROFILE")}};
}
Result readValue(const PlatformCommandRunner &run,const Target &target,const QString &key,QVariant &value) {
    const auto command=run(target.reader,target.arguments(key,false));
    if(!command.result.succeeded())return command.result;
    if(target.isKde()) {
        value=command.output;
        if(key=="ProxyType") {bool ok=false;const auto mode=command.output.toUInt(&ok);if(!ok || mode>4)return {Status::Failed,"Invalid KDE proxy mode"};value=int(mode);}
        if(key=="ReversedException") {
            const auto raw=command.output.toLower();
            if(!QStringList{"true","false","yes","no","on","off","1","0"}.contains(raw))return {Status::Failed,"Invalid KDE bypass direction"};
            value=QStringList{"true","yes","on","1"}.contains(raw);
        }
        return {};
    }
    const auto raw=command.output;
    bool ok=false;
    if(key.endsWith("/port")) {const int port=raw.toInt(&ok);if(ok && port>=0 && port<=65535){value=port;return {};}}
    else if(key=="use-same-proxy" || key=="http/use-authentication") {if(raw=="true" || raw=="false"){value=raw=="true";return {};}}
    else {
        const bool array=key==target.bypassKey();const auto values=strings(raw,ok,array);
        if(ok && (array || values.size()==1)) {
            if(array)value=values;
            else {value=values[0];if(key=="mode" && !QStringList{"none","manual","auto"}.contains(values[0]))return {Status::Failed,"Invalid GNOME proxy mode"};}
            return {};
        }
    }
    return {Status::Failed,"Invalid proxy setting readback"};
}
Result readState(const PlatformCommandRunner &run,const Target &target,QVariantMap &values) {
    for(const auto &key:target.keys()) {
        QVariant value;auto result=readValue(run,target,key,value);
        if(!result.succeeded())return result;
        values.insert(key,value);
    }
    return {};
}
QString argumentValue(const QVariant &value) {
    if(value.metaType().id()==QMetaType::QStringList)return ProxyValidation::listValue(value.toStringList());
    if(value.metaType().id()==QMetaType::QString) {
        const auto array=ProxyValidation::listValue({value.toString()});return array.mid(1,array.size()-2);
    }
    return value.toString();
}
Result writeValue(const PlatformCommandRunner &run,const Target &target,const QString &key,const QVariant &value) {
    auto args=target.arguments(key,true);
    if(target.isKde())args << "--";
    args.append(target.isKde()?value.toString():argumentValue(value));
    auto result=run(target.writer,args).result;
    if(result.succeeded()) {
        QVariant actual;result=readValue(run,target,key,actual);
        if(result.succeeded() && actual!=value)result={Status::Failed,"Proxy setting readback mismatch"};
    }
    result.mayHaveChanged=true;
    return result;
}
Result notify(const PlatformCommandRunner &run,const Target &target) {
    if(!target.isKde())return {};
    return run("dbus-send",{"--session","--type=signal","/KIO/Scheduler","org.kde.KIO.Scheduler.reparseSlaveConfiguration","string:"}).result;
}
QVariantMap requested(const Target &target,const QVariantMap &before,const SystemProxyConfig &config) {
    auto values=before;
    for(const auto &protocol:protocols) {
        const int port=protocol=="socks"?config.socksPort:config.httpPort;
        if(target.isKde())values[protocol+"Proxy"]=(protocol=="socks"?"socks://127.0.0.1 ":"http://127.0.0.1 ")+QString::number(port);
        else {values[protocol+"/host"]="127.0.0.1";values[protocol+"/port"]=port;}
    }
    if(target.isKde()){values[target.modeKey()]=1;values["ReversedException"]=false;values[target.bypassKey()]=ProxyValidation::bypass(config.bypass).join(',');}
    else {values[target.modeKey()]="manual";values[target.bypassKey()]=ProxyValidation::bypass(config.bypass);values["use-same-proxy"]=false;values["http/use-authentication"]=false;}
    return values;
}
}

struct PlatformSystemProxyBackend::Snapshot {
    Target target;
    QVariantMap before, installed;
    QSet<QString> released;
    QSet<QString> intent, written, uncertain;
    QSet<QString> pendingRestore;
    bool dirty = false, resumed = false;
    SystemProxyConfig config;
    QJsonObject context;
    QUuid owner = QUuid::createUuid();
};

QJsonObject PlatformSystemProxyBackend::recoverySnapshot() const {
    if (!snapshot) return {};
    const auto array=[](const QSet<QString> &set) {
        auto values=set.values();std::sort(values.begin(),values.end());return QJsonArray::fromStringList(values);
    };
    return {{"schema_version",3},{"platform","linux"},
        {"machine",QString::fromLatin1(QSysInfo::machineUniqueId().toHex())},
        {"owner",snapshot->owner.toString(QUuid::WithoutBraces)},{"context",snapshot->context},
        {"config",QJsonObject{{"http_port",snapshot->config.httpPort},{"socks_port",snapshot->config.socksPort},{"bypass",snapshot->config.bypass}}},
        {"before",QJsonObject::fromVariantMap(snapshot->before)},{"released",array(snapshot->released)},
        {"intent",array(snapshot->intent)},{"written",array(snapshot->written)},
        {"uncertain",array(snapshot->uncertain)},{"pending_restore",array(snapshot->pendingRestore)}};
}

PlatformOperationResult PlatformSystemProxyBackend::checkpoint(bool remove) {
    auto result=checkpointWriter ? checkpointWriter(remove?QJsonObject{}:recoverySnapshot()) : Result{};
    if (!result.succeeded() && snapshot && snapshot->dirty) result.mayHaveChanged=true;
    return result;
}

PlatformOperationResult PlatformSystemProxyBackend::recover(const QJsonObject &record) {
    if (snapshot) return {Status::Failed,"Existing system proxy ownership must be restored first",true};
    const auto invalid=[] { return Result{Status::Failed,"Invalid or foreign Linux proxy recovery record"}; };
    const auto bytes=QJsonDocument(record).toJson(QJsonDocument::Compact);
    const auto machine=QString::fromLatin1(QSysInfo::machineUniqueId().toHex());
    const auto ownerText=record["owner"].toString();const QUuid owner(ownerText);
    const bool legacy=record["schema_version"]==2;
    if (bytes.size()>CredentialStore::MaxBytes || QJsonDocument::fromJson(bytes).object()!=record || record.size()!=12
        || (!legacy && record["schema_version"]!=3) || record["platform"]!="linux" || machine.isEmpty() || record["machine"]!=machine
        || owner.isNull() || owner.toString(QUuid::WithoutBraces)!=ownerText || record["context"]!=currentContext()
        || !record["config"].isObject() || !record["before"].isObject() || !record["released"].isArray()
        || !record["intent"].isArray() || !record["written"].isArray() || !record["uncertain"].isArray()
        || (legacy?!record["pending_restore"].isString():!record["pending_restore"].isArray())) return invalid();
    const auto config=record["config"].toObject();
    const auto http=config["http_port"].toInteger(-1),socks=config["socks_port"].toInteger(-1);
    if (config.size()!=3 || http<1 || http>65535 || socks<1 || socks>65535 || !config["bypass"].isString()) return invalid();
    auto pending=std::make_shared<Snapshot>();pending->owner=owner;pending->context=record["context"].toObject();
    pending->config={int(http),int(socks),config["bypass"].toString()};
    if (!ProxyValidation::config(pending->config).succeeded()) return invalid();
    if (auto support=available();!support.succeeded()) return support;
    pending->target=currentTarget();const auto &target=pending->target;
    const auto before=record["before"].toObject();const auto keys=target.keys();
    if (before.size()!=keys.size()) return invalid();
    for (const auto &key:keys) {
        const auto value=before[key];
        if ((target.isKde() && key=="ProxyType") || (!target.isKde() && key.endsWith("/port"))) {
            const auto number=value.toInteger(-1);
            if (number<0 || number>(target.isKde()?4:65535)) return invalid();
            pending->before[key]=int(number);
        } else if (key=="ReversedException" || key=="use-same-proxy" || key=="http/use-authentication") {
            if (!value.isBool()) return invalid();
            pending->before[key]=value.toBool();
        } else if (!target.isKde() && key==target.bypassKey()) {
            if (!value.isArray()) return invalid();
            QStringList list;
            for (const auto &entry:value.toArray()) {
                if (!entry.isString() || entry.toString().contains(QChar(0))) return invalid();
                list.append(entry.toString());
            }
            pending->before[key]=list;
        } else {
            if (!value.isString() || value.toString().contains(QChar(0))) return invalid();
            if (!target.isKde() && key=="mode" && !QStringList{"none","manual","auto"}.contains(value.toString())) return invalid();
            if (target.isKde() && key.endsWith("Proxy") && value.toString().contains('@')) return invalid();
            pending->before[key]=value.toString();
        }
    }
    pending->installed=requested(target,pending->before,pending->config);
    for (const auto &field:QStringList{"released","intent","written","uncertain","pending_restore"}) {
        auto &set=field=="released"?pending->released:field=="intent"?pending->intent:field=="written"?pending->written
            :field=="uncertain"?pending->uncertain:pending->pendingRestore;
        const auto entries=legacy && field=="pending_restore"
            ? (record[field].toString().isEmpty()?QJsonArray{}:QJsonArray{record[field]}) : record[field].toArray();
        for (const auto &entry:entries) {
            const auto key=entry.toString();
            if (!entry.isString() || !keys.contains(key) || key==target.pacKey() || set.contains(key)
                || (field!="released" && pending->before[key]==pending->installed[key])) return invalid();
            set.insert(key);
        }
    }
    if (pending->released.intersects(pending->uncertain) || !(pending->written-pending->intent).isEmpty()
        || !(pending->uncertain-pending->intent).isEmpty()) return invalid();
    if (!(pending->pendingRestore-pending->intent).isEmpty() || pending->pendingRestore.intersects(pending->released)
        || pending->pendingRestore.intersects(pending->uncertain)) return invalid();
    pending->dirty=!pending->intent.isEmpty();
    pending->resumed=true;snapshot=pending;
    return clear();
}

SystemProxyCheck PlatformSystemProxyBackend::check(const SystemProxyConfig &config) {
    if(auto valid=ProxyValidation::config(config);!valid.succeeded())return {valid};
    if(auto support=available();!support.succeeded())return {support};
    const auto target=currentTarget();QVariantMap values;
    if(auto result=readState(runner,target,values);!result.succeeded())return {result};
    const auto mode=values[target.modeKey()].toString();
    if(mode!=(target.isKde()?"1":"manual"))return {{},mode!=(target.isKde()?"0":"none")};
    const auto expected=requested(target,values,config);
    bool conflict=false;
    for(const auto &protocol:protocols)for(const auto &key:target.endpointKeys(protocol))conflict|=values[key]!=expected[key];
    conflict|=values[target.isKde()?"ReversedException":"use-same-proxy"].toBool();
    return {{},conflict,true};
}

PlatformOperationResult PlatformSystemProxyBackend::apply(const SystemProxyConfig &config) {
    if(auto valid=ProxyValidation::config(config);!valid.succeeded())return valid;
    if(snapshot)return {Status::Failed,"Restore the current proxy settings before applying another configuration",true};
    if(auto support=available();!support.succeeded())return support;
    auto pending=std::make_shared<Snapshot>();pending->target=currentTarget();
    pending->config=config;pending->context=currentContext();
    if(auto result=readState(runner,pending->target,pending->before);!result.succeeded())return result;
    // shortcut: KConfig CLI values use argv; credentialed URLs require a native KConfig writer.
    if(pending->target.isKde())for(const auto &protocol:protocols)
        if(pending->before[protocol+"Proxy"].toString().contains('@'))return {Status::Unsupported,"Credentialed KDE proxy URLs cannot be changed safely by the command-line backend"};
    pending->installed=requested(pending->target,pending->before,config);snapshot=pending;
    if (auto result=checkpoint();!result.succeeded()) {
        if (!result.mayHaveChanged) snapshot.reset();
        return result;
    }
    auto order=pending->target.keys();order.removeAll(pending->target.pacKey());
    // Disable authentication before changing the HTTP endpoint; restore it only after the original endpoint.
    if(!pending->target.isKde()){order.removeAll("http/use-authentication");order.prepend("http/use-authentication");}
    const auto fail=[this](Result result){const auto restored=clear();result.mayHaveChanged=!restored.succeeded();return result;};
    for(const auto &key:order)if(pending->before[key]!=pending->installed[key]) {
        pending->intent.insert(key);
        const auto abandon=[&](Result result) {
            pending->intent.remove(key);pending->released.insert(key);return fail(result);
        };
        if (auto result=checkpoint();!result.succeeded()) return abandon(result);
        QVariant actual;
        if (auto result=readValue(runner,pending->target,key,actual);!result.succeeded()) return abandon(result);
        if (actual!=pending->before[key]) return abandon({Status::Failed,"Proxy setting changed before application"});
        pending->dirty=true;
        auto result=writeValue(runner,pending->target,key,pending->installed[key]);
        if(!result.succeeded())return fail(result);
        pending->written.insert(key);
        if (auto result=checkpoint();!result.succeeded()) return fail(result);
    }
    if(auto result=notify(runner,pending->target);!result.succeeded())return fail(result);
    return {Status::Success,{},true};
}

PlatformOperationResult PlatformSystemProxyBackend::clear() {
    if(!snapshot)return {};
    auto &saved=*snapshot;QVariantMap current;
    if (!saved.dirty) {
        const auto result=checkpoint(true);
        if (!result.succeeded()) return {result.status,result.detail,true};
        snapshot.reset();return {};
    }
    if (saved.resumed) {
        auto unconfirmed=saved.intent-saved.written-saved.released;
        unconfirmed.unite(saved.pendingRestore);
        // A crash can lose write confirmation or hide restoration followed by external same-value recreation.
        for (const auto &key:unconfirmed) {
            QVariant value;
            if (auto result=readValue(runner,saved.target,key,value);!result.succeeded()) return {result.status,result.detail,true};
            if (value==saved.installed[key]) saved.uncertain.insert(key);
            else {saved.uncertain.remove(key);saved.released.insert(key);}
            saved.pendingRestore.remove(key);
        }
        saved.pendingRestore.clear();
    }
    saved.resumed=false;
    for (const auto &key:saved.target.keys())
        if (key!=saved.target.pacKey() && !saved.intent.contains(key)) saved.released.insert(key);
    const auto known=[&](const QString &key){return current[key]==saved.before[key]
        || (!saved.released.contains(key) && current[key]==saved.installed[key]);};
    const auto refresh=[&](const QStringList &keys,bool restoring=false) {
        if (restoring) {
            // Keep the whole group's observation marker through the native write and its confirmation.
            for (const auto &key:keys)
                if (saved.intent.contains(key) && !saved.released.contains(key) && !saved.uncertain.contains(key)) saved.pendingRestore.insert(key);
            if (auto result=checkpoint();!result.succeeded()) return Result{result.status,result.detail,true};
        }
        for(const auto &key:keys) {
            const bool owned=saved.intent.contains(key) && !saved.released.contains(key) && !saved.uncertain.contains(key);
            if (!restoring && owned) {
                saved.pendingRestore.insert(key);
                if (auto result=checkpoint();!result.succeeded()) return Result{result.status,result.detail,true};
            }
            QVariant value;auto result=readValue(runner,saved.target,key,value);
            if(!result.succeeded()){result.mayHaveChanged=true;return result;}
            current[key]=value;
            const bool release=saved.intent.contains(key) && !saved.released.contains(key)
                && (value==saved.before[key] || value!=saved.installed[key]);
            if (release) {saved.released.insert(key);saved.uncertain.remove(key);}
            if (release) saved.pendingRestore.remove(key);
            if (!restoring) {
                saved.pendingRestore.remove(key);
                if (owned || release)
                    if (auto result=checkpoint();!result.succeeded()) return Result{result.status,result.detail,true};
            }
        }
        return Result{};
    };
    if (auto result=refresh(saved.target.keys());!result.succeeded()) return result;
    bool changed=false;
    const auto restoreGroup=[&](const QStringList &keys) -> Result {
        const auto release=[&] {
            bool modified=false;
            for (const auto &part:keys) {
                modified|=!saved.released.contains(part) || saved.uncertain.contains(part);
                saved.released.insert(part);saved.uncertain.remove(part);
            }
            for (const auto &key:keys) modified|=saved.pendingRestore.remove(key);
            return modified?checkpoint():Result{};
        };
        bool blocked=false;
        for (const auto &part:keys) if (saved.uncertain.contains(part)) blocked=true;
        if (blocked) {
            auto result=refresh(keys);if (!result.succeeded()) return result;
            for (const auto &part:keys) if (!known(part)) return release();
            blocked=false;
            for (const auto &part:keys) if (saved.uncertain.contains(part)) {
                if (current[part]==saved.installed[part]) blocked=true;
                else {saved.uncertain.remove(part);saved.released.insert(part);}
            }
            if (blocked) return checkpoint();
        }
        for(const auto &key:keys) {
            if(saved.released.contains(key))continue;
            auto result=refresh(keys);if(!result.succeeded())return result;
            for(const auto &part:keys)if(!known(part))return release();
            if(current[key]!=saved.before[key]) {
                auto verification=keys;
                if (key==saved.target.modeKey() || key=="use-same-proxy") {
                    for (const auto &protocol:protocols) verification.append(saved.target.endpointKeys(protocol));
                    verification.append(saved.target.pacKey());
                } else if (key=="ReversedException") verification.append(saved.target.bypassKey());
                if (auto result=refresh(verification,true);!result.succeeded()) return result;
                for (const auto &part:verification) if (!known(part)) return release();
                if (saved.released.contains(key)) continue;
                // Never enable old credentials on an endpoint changed during protected storage.
                if (key=="http/use-authentication" && saved.before[key].toBool()
                    && (current["http/host"]!=saved.before["http/host"] || current["http/port"]!=saved.before["http/port"])) {
                    saved.released.insert(key);saved.pendingRestore.clear();return checkpoint();
                }
                result=writeValue(runner,saved.target,key,saved.before[key]);
                if(!result.succeeded()){result.mayHaveChanged=true;return result;}
                current[key]=saved.before[key];changed=true;
            }
            saved.released.insert(key);
            saved.pendingRestore.clear();
            if (auto result=checkpoint();!result.succeeded()) return {result.status,result.detail,true};
        }
        return Result{};
    };
    for(const auto &protocol:protocols) {
        if(auto result=restoreGroup(saved.target.endpointKeys(protocol));!result.succeeded())return result;
    }
    if(auto result=restoreGroup({saved.target.bypassKey()});!result.succeeded())return result;
    if(saved.target.isKde()) {
        if(auto result=refresh({saved.target.bypassKey()});!result.succeeded())return result;
        if(current[saved.target.bypassKey()]==saved.before[saved.target.bypassKey()])
            if(auto result=restoreGroup({"ReversedException"});!result.succeeded())return result;
    }
    // Recheck endpoints after restoring them; external changes must not inherit old mode/auth flags.
    if(auto result=refresh(saved.target.keys());!result.succeeded())return result;
    bool endpointsRestored=true;
    for(const auto &protocol:protocols)for(const auto &key:saved.target.endpointKeys(protocol))endpointsRestored &= current[key]==saved.before[key];
    if(endpointsRestored && current[saved.target.pacKey()]==saved.before[saved.target.pacKey()]) {
        QStringList flags;if(!saved.target.isKde())flags << "use-same-proxy";
        flags << saved.target.modeKey();
        if(auto result=restoreGroup(flags);!result.succeeded())return result;
    }
    if (auto result=checkpoint();!result.succeeded()) return {result.status,result.detail,true};
    if(auto result=notify(runner,saved.target);!result.succeeded()){result.mayHaveChanged=true;return result;}
    if (!saved.uncertain.isEmpty()) return {Status::Failed,"Unconfirmed proxy restoration retained matching settings for review",true};
    saved.dirty=false;
    if (auto result=checkpoint(true);!result.succeeded()) return {result.status,result.detail,true};
    snapshot.reset();return {Status::Success,{},changed};
}
