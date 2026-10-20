#include "application/profilecredentials.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QSettings>
#include <QTemporaryDir>
#include <QUuid>
#include <functional>
#include <iostream>
#include <stdexcept>

namespace {
using Status=CredentialStatus;
void require(bool okay,const char *message) {if (!okay) throw std::runtime_error(message);}
void expect(const CredentialResult &result,Status status,const char *message) {require(result.status==status,message);}
class Store final:public CredentialStore {
public:
    QHash<QString,QByteArray> values;
    Status readStatus=Status::Success,writeStatus=Status::Success,removeStatus=Status::Success;
    bool loseWrite=false,loseRemoval=false;
    std::function<void()> afterWrite;
    CredentialResult read(const QString &key) override {
        if (readStatus!=Status::Success) return {readStatus,{}};
        return values.contains(key) ? CredentialResult{Status::Success,values.value(key)} : CredentialResult{Status::NotFound,{}};
    }
    CredentialResult write(const QString &key,const QByteArray &value) override {
        if (writeStatus!=Status::Success) return {writeStatus,{}};
        if (!loseWrite) values.insert(key,value);
        if (afterWrite) afterWrite();
        return {Status::Success,{}};
    }
    CredentialResult remove(const QString &key) override {
        if (removeStatus!=Status::Success) return {removeStatus,{}};
        if (!loseRemoval) values.remove(key);
        return {Status::Success,{}};
    }
};
QString newScope() {return QUuid::createUuid().toString(QUuid::WithoutBraces);}
ConnectionProfile profile() {
    ConnectionProfile p;
    p.endpoint.server="vpn.example.invalid";p.endpoint.port=443;p.endpoint.authType="psw";
    p.endpoint.loginDomain="school";p.endpoint.authId="opaque-id";p.endpoint.authSubType="password";
    p.credentials={"alice",QString("fixture password")+QChar(0)+QString::fromUtf8("\xe5\xaf\x86\xe7\xa0\x81"),"fixture TOTP"};
    return p;
}
QByteArray bytes(const QString &path) {QFile file(path);require(file.open(QIODevice::ReadOnly),"read fixture");return file.readAll();}
void write(const QString &path,const QByteArray &value) {
    QFile file(path);require(file.open(QIODevice::WriteOnly) && file.write(value)==value.size(),"write fixture");
}
void legacy(QSettings &settings,const ConnectionProfile &p) {
    settings.setValue("Credential/Username",p.credentials.username);
    settings.setValue("Credential/Password",QString::fromLatin1(p.credentials.password.toUtf8().toBase64()));
    settings.setValue("Credential/TOTPSecret",p.credentials.totpSecret);
    settings.setValue("JustConnect/ServerAddress",p.endpoint.server);
    settings.setValue("Unknown/Value","retained configuration");settings.sync();
    require(settings.status()==QSettings::NoError,"persist legacy fixture");
}
void isolatedIdentities() {
    Store store;ProfileCredentials vault(store);const auto scope=newScope();auto p=profile();
    expect(vault.save(scope,p),Status::Success,"save and verify");
    ConnectionCredentials loaded;
    expect(vault.load(scope,p,loaded),Status::Success,"read credentials");
    require(loaded.username==p.credentials.username && loaded.password==p.credentials.password && loaded.totpSecret==p.credentials.totpSecret,"saved credentials round trip");
    QList<ConnectionProfile> others;
    auto other=p;other.endpoint.server="other.example.invalid";others.append(other);
    other=p;other.endpoint.port=8443;others.append(other);
    other=p;other.endpoint.loginDomain="other";others.append(other);
    other=p;other.endpoint.authType="radius";others.append(other);
    other=p;other.endpoint.authId="other-id";others.append(other);
    other=p;other.endpoint.authSubType="other-subtype";others.append(other);
    other=p;other.endpoint.phone="86-123456";others.append(other);
    other=p;other.credentials.username="bob";others.append(other);
    for (const auto &identity:others) {
        loaded=p.credentials;
        expect(vault.load(scope,identity,loaded),Status::NotFound,"another identity cannot reuse credentials");
        require(loaded.password.isEmpty() && loaded.totpSecret.isEmpty(),"failed load clears prior credentials");
        expect(vault.save(scope,identity),Status::Success,"save separate identity");
    }
    expect(vault.load(newScope(),p,loaded),Status::NotFound,"profiles do not share credentials");
    auto network=p;network.endpoint.server=network.endpoint.server.toUpper();network.tls.verify=false;
    network.dns.secondary="10.0.0.2";network.proxy.httpBind="127.0.0.1:12345";
    expect(vault.load(scope,network,loaded),Status::Success,"network and TLS preferences preserve identity");
    const auto originalKey=ProfileCredentials::key(scope,p);
    p.credentials.password="replacement";expect(vault.save(scope,p),Status::Success,"replace current password");
    require(ProfileCredentials::key(scope,p)==originalKey,"password changes do not orphan credentials");
    QTemporaryDir folder;QSettings settings(folder.filePath("clear.ini"),QSettings::IniFormat);
    settings.setValue("Credential/Username",p.credentials.username);
    expect(vault.clear(settings,scope,p),Status::Success,"verified scoped removal");
    expect(vault.load(scope,p,loaded),Status::NotFound,"deleted identity remains absent");
    for (const auto &identity:others) expect(vault.load(scope,identity,loaded),Status::Success,"deletion preserves other identities");
    expect(vault.save({},p),Status::InvalidArgument,"empty namespace rejected");
    p.credentials.username.clear();expect(vault.save(scope,p),Status::InvalidArgument,"unbound password rejected");
}
void verifiedMigration() {
    QTemporaryDir folder;require(folder.isValid(),"migration directory");
    Store store;ProfileCredentials vault(store);const auto p=profile();const auto path=folder.filePath("legacy.ini");
    QString scope;
    {
        QSettings settings(path,QSettings::IniFormat);legacy(settings,p);
        scope=ProfileCredentials::ensureScope(settings);require(!scope.isEmpty(),"persistent namespace");
        settings.setValue("Credential/OtherAccount/Ticket","other ticket");settings.sync();
        const auto before=bytes(path);
        for (const auto status:{Status::Locked,Status::Unavailable,Status::PermissionDenied,Status::Cancelled,Status::Limit,Status::Failed}) {
            store.writeStatus=status;
            expect(vault.migrate(settings,scope,p),status,"migration propagates store failure");
            require(bytes(path)==before && settings.contains("Credential/Password") && settings.contains("Credential/TOTPSecret"),"failed migration retains exact source");
        }
        store.writeStatus=Status::Success;store.loseWrite=true;
        expect(vault.migrate(settings,scope,p),Status::Failed,"successful write without readback is rejected");
        require(bytes(path)==before,"missing readback preserves plaintext for retry");store.loseWrite=false;
        expect(vault.migrate(settings,scope,p),Status::Success,"verified migration removes legacy keys");
        require(!settings.contains("Credential/Password") && !settings.contains("Credential/TOTPSecret")
            && settings.value("Credential/OtherAccount/Ticket")=="other ticket" && settings.value("Unknown/Value")=="retained configuration","migration preserves configuration and another account");
    }
    QSettings restarted(path,QSettings::IniFormat);
    require(ProfileCredentials::ensureScope(restarted)==scope,"restart keeps namespace");
    ConnectionCredentials loaded;
    expect(vault.load(scope,p,loaded),Status::Success,"restart reads secure migrated credentials");
    require(loaded.password==p.credentials.password && loaded.totpSecret==p.credentials.totpSecret,"migrated values survive source cleanup");
    legacy(restarted,p);
    auto newer=p;newer.credentials.password="newer secure password";expect(vault.save(scope,newer),Status::Success,"save newer password");
    const auto stale=bytes(path);
    expect(vault.migrate(restarted,scope,p),Status::Conflict,"stale source must not replace newer secure password");
    require(bytes(path)==stale,"conflicting legacy source retained");
    expect(vault.load(scope,p,loaded),Status::Success,"newer password remains accessible");require(loaded.password==newer.credentials.password,"stale migration did not overwrite secure value");
    restarted.setValue("Credential/Password","%%%bad-base64");restarted.sync();const auto invalid=bytes(path);
    expect(vault.migrate(restarted,scope,p),Status::InvalidArgument,"malformed legacy encoding rejected");require(bytes(path)==invalid,"malformed legacy value preserved");
}
void interruptedMigration()
{
    QTemporaryDir folder;require(folder.isValid(),"interrupted migration directory");
    const auto p=profile();const auto scope=newScope();
    Store store;ProfileCredentials vault(store);
    QSettings settings(folder.filePath("legacy.ini"),QSettings::IniFormat);legacy(settings,p);
    const auto before=bytes(settings.fileName());
    store.afterWrite=[&]{store.readStatus=Status::Locked;};
    expect(vault.migrate(settings,scope,p),Status::Locked,"readback lock prevents plaintext removal");
    require(bytes(settings.fileName())==before,"readback failure retains exact source");
    store.readStatus=Status::Success;store.afterWrite={};
    expect(vault.migrate(settings,scope,p),Status::Success,"unlock permits safe retry");
    legacy(settings,p);store.values.clear();
    store.afterWrite=[&]{settings.setValue("Credential/Password",QString::fromLatin1(QByteArray("changed source password").toBase64()));settings.sync();};
    expect(vault.migrate(settings,scope,p),Status::Cancelled,"late migration cannot remove replaced source credentials");
    require(QByteArray::fromBase64(settings.value("Credential/Password").toByteArray())=="changed source password"
        && settings.contains("Credential/TOTPSecret"),"changed source retained for its own migration");
    settings.setValue(ProfileCredentials::ScopeSetting,"invalid namespace");settings.sync();
    require(ProfileCredentials::ensureScope(settings).isEmpty() && settings.value(ProfileCredentials::ScopeSetting)=="invalid namespace","invalid scope is not silently replaced or shared");
}

void migrationSaveFailure() {
    QTemporaryDir folder;require(folder.isValid(),"failure directory");
    Store store;ProfileCredentials vault(store);const auto p=profile();const auto path=folder.filePath("legacy.ini"),backup=folder.filePath("saved.ini");
    QString scope;QByteArray original;
    {
        QSettings settings(path,QSettings::IniFormat);legacy(settings,p);scope=ProfileCredentials::ensureScope(settings);original=bytes(path);
        store.afterWrite=[&]{require(QFile::rename(path,backup) && QDir().mkdir(path),"make real configuration commit fail");};
        expect(vault.migrate(settings,scope,p),Status::Failed,"failed INI removal reported");
        require(settings.contains("Credential/Password") && settings.contains("Credential/TOTPSecret") && bytes(backup)==original,"failed INI commit retains retry values and original file");
    }
    require(QDir().rmdir(path) && QFile::rename(backup,path),"restore writable configuration");store.afterWrite={};
    QSettings retry(path,QSettings::IniFormat);
    expect(vault.migrate(retry,scope,p),Status::Success,"restart retries completed secure copy");
    require(!retry.contains("Credential/Password") && !retry.contains("Credential/TOTPSecret"),"successful retry removes legacy keys");
}
void corruptAndFailedOperations() {
    Store store;ProfileCredentials vault(store);const auto scope=newScope();auto p=profile();
    expect(vault.save(scope,p),Status::Success,"initial credentials");const auto key=ProfileCredentials::key(scope,p);const auto saved=store.values.value(key);
    auto blank=p;blank.credentials.password.clear();blank.credentials.totpSecret.clear();
    expect(vault.save(scope,blank),Status::InvalidArgument,"empty save cannot implicitly delete an existing credential");
    require(store.values.value(key)==saved,"only the explicit deletion operation can remove a credential");
    store.loseWrite=true;p.credentials.password="new";
    expect(vault.save(scope,p),Status::Failed,"mismatched write readback rejected");store.loseWrite=false;
    QTemporaryDir folder;QSettings settings(folder.filePath("clear.ini"),QSettings::IniFormat);
    settings.setValue("Credential/Username",p.credentials.username);
    store.loseRemoval=true;expect(vault.clear(settings,scope,p),Status::Failed,"unconfirmed deletion rejected");store.loseRemoval=false;
    p.credentials.password=QString(CredentialStore::MaxBytes,'x');
    expect(vault.save(scope,p),Status::Limit,"oversized password cannot replace saved credentials");
    require(store.values.value(key)==saved,"failed save and remove retain original value");
    ConnectionCredentials loaded;
    for (const auto &value:QList<QByteArray>{"invalid JSON","[]",R"({"version":2,"password":"secret","totp_secret":""})",R"({"version":1,"password":"secret"})",QByteArray(CredentialStore::MaxBytes+1,'x')}) {
        store.values[key]=value;loaded=p.credentials;
        const auto result=vault.load(scope,p,loaded);
        require(!result.succeeded() && loaded.password.isEmpty() && loaded.totpSecret.isEmpty(),"corrupt or oversized data yields no credentials");
    }
    store.values[key]=saved;store.readStatus=Status::Locked;loaded=p.credentials;
    expect(vault.load(scope,p,loaded),Status::Locked,"read failure stays distinct");require(loaded.password.isEmpty(),"locked store exposes no stale password");
}
void unboundAndFutureLegacy() {
    QTemporaryDir folder;Store store;ProfileCredentials vault(store);const auto scope=newScope();auto p=profile();
    QSettings settings(folder.filePath("unconfirmed.ini"),QSettings::IniFormat);legacy(settings,p);
    p.endpoint.server.clear();
    expect(vault.migrate(settings,scope,p),Status::Success,"unconfirmed credentials can be sealed without assigning an account");
    require(!settings.contains("Credential/Password") && store.values.size()==1,"verified unbound archive replaces legacy plaintext");
    ConnectionCredentials loaded;
    expect(vault.load(scope,profile(),loaded),Status::NotFound,"confirming an address never automatically reuses unbound credentials");
    store.loseRemoval=true;
    expect(vault.clear(settings,scope,p),Status::Failed,"archive deletion requires verification");
    store.loseRemoval=false;
    expect(vault.clear(settings,scope,p),Status::Success,"explicit clear removes the unbound archive");
    require(store.values.isEmpty(),"unbound archive removed");
    p=profile();legacy(settings,p);settings.setValue("Common/ConfigVersion",999);settings.sync();const auto future=bytes(settings.fileName());
    expect(vault.migrate(settings,scope,p),Status::InvalidArgument,"future credential format is not guessed");
    expect(vault.clear(settings,scope,p),Status::InvalidArgument,"future credential values are preserved for their owning version");
    require(bytes(settings.fileName())==future && store.values.isEmpty(),"future source left unchanged");
    settings.setValue("Common/ConfigVersion",9);settings.setValue("Credential/Password",42);settings.sync();
    expect(vault.migrate(settings,scope,p),Status::InvalidArgument,"unexpected legacy variant type is not decoded or deleted");
    require(settings.value("Credential/Password").toInt()==42 && ProfileCredentials::hasLegacyCredentials(settings),"unsupported value remains pending");
    legacy(settings,p);expect(vault.migrate(settings,scope,p),Status::Success,"known legacy version still migrates");
    auto other=p;other.credentials.username="bob";expect(vault.save(scope,other),Status::Success,"other account saved");
    legacy(settings,p);expect(vault.clear(settings,scope,p),Status::Success,"explicit clear removes both native and pending legacy credentials");
    expect(vault.load(scope,p,loaded),Status::NotFound,"cleared account cannot reload");
    expect(vault.load(scope,other,loaded),Status::Success,"clear leaves other account intact");
    require(!settings.contains("Credential/Password") && !settings.contains("Credential/TOTPSecret") && settings.value("Unknown/Value")=="retained configuration","clear preserves public and unknown fields");
}
void sealedLegacyCache() {
    QTemporaryDir folder;require(folder.isValid(),"cache directory");
    Store store;ProfileCredentials vault(store);const auto scope=newScope();const auto path=folder.filePath("client-data.json");
    const QByteArray original=R"({"cookies":[{"value":"fixture old cookie"}],"device_id":"legacy device"})";
    write(path,original);store.writeStatus=Status::PermissionDenied;
    expect(vault.quarantine(path,scope),Status::PermissionDenied,"sealing failure reported");require(bytes(path)==original,"sealing failure retains cache");
    store.writeStatus=Status::Success;store.loseWrite=true;
    expect(vault.quarantine(path,scope),Status::Failed,"unverified cache copy rejected");require(bytes(path)==original,"unverified copy retains cache");store.loseWrite=false;
    store.afterWrite=[&]{write(path,"changed cookie");};
    expect(vault.quarantine(path,scope),Status::Cancelled,"concurrent cache replacement retained");require(bytes(path)=="changed cookie","new cache not deleted");store.afterWrite={};
    expect(vault.quarantine(path,scope),Status::Conflict,"different legacy backup not overwritten");
    write(path,original);expect(vault.quarantine(path,scope),Status::Success,"verified quarantine removes plaintext cache");
    require(!QFileInfo::exists(path) && store.values.value(ProfileCredentials::legacyCacheKey(scope))==original,"cache sealed without assigning an account");
    ConnectionCredentials loaded;expect(vault.load(scope,profile(),loaded),Status::NotFound,"unbound cache never used as account credentials");
    write(path,QByteArray(CredentialStore::MaxBytes+1,'x'));
    expect(vault.quarantine(path,newScope()),Status::Limit,"oversized legacy cache retained");require(QFileInfo(path).size()==CredentialStore::MaxBytes+1,"oversized source untouched");
#ifdef Q_OS_UNIX
    const auto alias=folder.filePath("cache-link");require(QFile::link(path,alias),"fixture symbolic link");
    expect(vault.quarantine(alias,newScope()),Status::InvalidArgument,"cache symlinks rejected");require(QFileInfo::exists(path) && QFileInfo(alias).isSymLink(),"unowned target not modified");
#endif
}
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    try {
        isolatedIdentities();verifiedMigration();interruptedMigration();migrationSaveFailure();corruptAndFailedOperations();unboundAndFutureLegacy();sealedLegacyCache();
        std::cout<<"PASS: scoped credentials, verified migration, real file failure/retry and unbound cache quarantine\n";
        return 0;
    } catch(const std::exception &error) {std::cerr<<error.what()<<'\n';return 1;}
}
