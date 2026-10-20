#include "infrastructure/settings/credentialaccess.h"
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QSemaphore>
#include <QSettings>
#include <QTemporaryDir>
#include <QThread>
#include <atomic>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool okay,const char *message) {if (!okay) throw std::runtime_error(message);}
class Store final:public CredentialStore {
public:
    QHash<QString,QByteArray> values;
    CredentialStatus failure=CredentialStatus::Success;
    QSemaphore entered,resume;
    bool blockNextRead=false;
    std::atomic_int active{0},peak{0};
    QThread *lastThread=nullptr;
    CredentialResult read(const QString &key) override {
        lastThread=QThread::currentThread();
        const auto count=++active;peak.store(qMax(peak.load(),count));
        if (blockNextRead) {blockNextRead=false;entered.release();require(resume.tryAcquire(1,5000),"release blocked native boundary");}
        --active;
        if (failure!=CredentialStatus::Success) return {failure,{}};
        return values.contains(key) ? CredentialResult{CredentialStatus::Success,values.value(key)} : CredentialResult{CredentialStatus::NotFound,{}};
    }
    CredentialResult write(const QString &key,const QByteArray &value) override {
        lastThread=QThread::currentThread();
        if (failure!=CredentialStatus::Success) return {failure,{}};
        values.insert(key,value);return {CredentialStatus::Success,{}};
    }
    CredentialResult remove(const QString &key) override {values.remove(key);return {CredentialStatus::Success,{}};}
};
template<class T> T finish(QFuture<T> future) {
    QDeadlineTimer deadline(6000);
    while (!future.isFinished() && !deadline.hasExpired()) {QCoreApplication::processEvents();QThread::msleep(1);}
    require(future.isFinished(),"bounded credential operation");return future.result();
}
void setup(QSettings &settings) {
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");settings.setValue("JustConnect/ServerPort",443);
    settings.setValue("JustConnect/AuthType","psw");settings.setValue("Credential/Username","alice");
    settings.setValue("Credential/Password",QString::fromLatin1(QByteArray("legacy password").toBase64()));
    settings.setValue("Credential/TOTPSecret","legacy TOTP");settings.sync();
}
void readsAndSavesOutsideGui() {
    QTemporaryDir folder;require(folder.isValid(),"isolated settings");
    QSettings settings(folder.filePath("profile.ini"),QSettings::IniFormat);setup(settings);
    auto backend=std::make_unique<Store>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    const auto source=CredentialAccess::source(settings,{});
    require(source.profile.credentials.password.isEmpty() && source.profile.credentials.totpSecret.isEmpty(),"source snapshot has no plaintext credentials");
    store->blockNextRead=true;
    auto first=access.load(source);
    require(store->entered.tryAcquire(1,1000),"worker reached native boundary");
    bool guiResponsive=false;QMetaObject::invokeMethod(&access,[&]{guiResponsive=true;},Qt::QueuedConnection);
    QCoreApplication::processEvents();require(guiResponsive && !first.isFinished(),"GUI remains responsive during blocked native I/O");
    auto second=access.load(source);store->resume.release();
    const auto loaded=finish(first),again=finish(second);
    require(loaded.result.succeeded() && again.result.succeeded() && loaded.credentials.password=="legacy password"
        && loaded.credentials.totpSecret=="legacy TOTP" && store->lastThread!=QCoreApplication::instance()->thread()
        && store->peak==1,"native operations are serialized off the GUI thread");
    require(!settings.contains("Credential/Password") && !settings.contains("Credential/TOTPSecret"),"async migration removes verified legacy values");
    require(finish(access.save(source,source.profile,true,{})).status==CredentialStatus::InvalidArgument,
        "blank save cannot implicitly clear the saved account");
    require(finish(access.load(source)).credentials.password=="legacy password","blank save preserves the existing native credential");
    auto replacement=source.profile;replacement.credentials={"bob","manual password",""};
    require(finish(access.save(source,replacement,true,{})).succeeded(),"save explicitly entered different account");
    require(settings.value("Credential/Username")=="alice","credential I/O does not commit another account's public profile");
    ConnectionCredentials saved;ProfileCredentials vault(*store);
    require(vault.load(source.scope,replacement,saved).succeeded() && saved.password=="manual password","entered account uses its own secure entry");
    replacement.credentials.password.clear();
    require(finish(access.save(source,replacement,false,{})).succeeded() && vault.load(source.scope,replacement,saved).succeeded()
        && saved.password=="manual password","unchanged credential fields do not erase a stored password");
    replacement.credentials.password="must not store";
    store->failure=CredentialStatus::PermissionDenied;
    require(finish(access.save(source,replacement,true,{})).status==CredentialStatus::PermissionDenied
        && !settings.contains("Credential/Password"),"save failure does not write plaintext fallback");
}
void sealsCacheBeforeDelivery()
{
    QTemporaryDir folder;require(folder.isValid(),"cache migration directory");
    QSettings settings(folder.filePath("profile.ini"),QSettings::IniFormat);setup(settings);
    settings.remove("Credential/Password");settings.remove("Credential/TOTPSecret");settings.sync();
    const auto path=folder.filePath("client-data.json");
    const QByteArray original="unbound legacy cookie";
    {QFile file(path);require(file.open(QIODevice::WriteOnly) && file.write(original)==original.size(),"legacy cache fixture");}
    auto backend=std::make_unique<Store>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    const auto source=CredentialAccess::source(settings,path);
    auto saved=source.profile;saved.credentials.password="secure password";ProfileCredentials vault(*store);
    require(vault.save(source.scope,saved).succeeded(),"existing secure credentials");
    store->failure=CredentialStatus::PermissionDenied;
    const auto failed=finish(access.load(source));
    QFile file(path);require(file.open(QIODevice::ReadOnly),"failed migration retains source cache");
    require(failed.result.status==CredentialStatus::PermissionDenied && failed.credentials.password.isEmpty()
        && file.readAll()==original,"cache sealing failure is explicit and retains source");file.close();
    store->failure=CredentialStatus::Success;
    const auto loaded=finish(access.load(source));
    require(loaded.result.succeeded() && loaded.credentials.password=="secure password" && !QFileInfo::exists(path)
        && store->values.value(ProfileCredentials::legacyCacheKey(source.scope))==original,"retry seals unbound cache before delivering account credentials");
}

void acceptsUnconfiguredFirstLaunch()
{
    QTemporaryDir folder;require(folder.isValid(),"first launch directory");
    QSettings settings(folder.filePath("new.ini"),QSettings::IniFormat);
    CredentialAccess access(std::make_unique<Store>());
    const auto source=CredentialAccess::source(settings,{});
    require(finish(access.load(source)).result.status==CredentialStatus::NotFound,"unconfigured first launch has no bound credentials");
    auto draft=source.profile;draft.endpoint.server="vpn.example.invalid";draft.endpoint.port=443;draft.endpoint.authType="psw";
    draft.credentials={"alice","first password",""};
    require(finish(access.save(source,draft,true,{})).succeeded(),"first setup can store new bound credentials");
}

void publicSaveFailureAndStaleness() {
    QTemporaryDir folder;QSettings settings(folder.filePath("profile.ini"),QSettings::IniFormat);setup(settings);
    auto backend=std::make_unique<Store>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    auto source=CredentialAccess::source(settings,{});auto draft=source.profile;
    settings.setValue("JustConnect/SecondaryDNS","10.0.0.9");settings.sync();
    require(finish(access.save(source,draft,false,{{"JustConnect/SecondaryDNS","10.0.0.2"}})).status==CredentialStatus::Cancelled
        && settings.value("JustConnect/SecondaryDNS")=="10.0.0.9","stale public draft cannot overwrite newer network settings");
    source=CredentialAccess::source(settings,{});draft=source.profile;store->failure=CredentialStatus::Locked;
    require(finish(access.save(source,draft,false,{{"JustConnect/DNSTTL",123}})).succeeded()
        && settings.value("JustConnect/DNSTTL")==123 && settings.contains("Credential/Password"),"public changes can save with locked store while pending credentials keep their original identity");
    source=CredentialAccess::source(settings,{});draft.credentials.username="bob";
    require(finish(access.save(source,draft,false,{{"Credential/Username","bob"}})).status==CredentialStatus::Locked
        && settings.value("Credential/Username")=="alice","locked legacy credentials cannot be reassigned to another account");
    require(finish(access.save(source,draft,false,{{"Credential/Password","plaintext"}})).status==CredentialStatus::InvalidArgument,"private key injection rejected before mutation");
    store->failure=CredentialStatus::Success;require(finish(access.migrate(source)).succeeded(),"migration can complete before a profile rename");
    source=CredentialAccess::source(settings,{});draft=source.profile;draft.credentials.password="new password";
    store->blockNextRead=true;auto saved=access.save(source,draft,true,{{"JustConnect/DNSTTL",456}});
    require(access.isBusy(source.path) && access.isSaving(source.path) && store->entered.tryAcquire(1,1000),"public save remains tracked while native verification blocks");
    auto *window=new QObject;saved.then(window,[](const CredentialResult &){});delete window;store->resume.release();
    require(finish(saved).succeeded() && !access.isBusy(source.path) && !access.isSaving(source.path)
        && settings.value("JustConnect/DNSTTL")==456,"closing a consumer does not cancel the already authorized atomic public batch");
    store->failure=CredentialStatus::Unavailable;source=CredentialAccess::source(settings,{});draft=source.profile;draft.credentials={};draft.credentials.username="bob";
    require(finish(access.save(source,draft,false,{{"Credential/Username","bob"}})).succeeded(),"public account setup remains possible without a native store once legacy secrets are sealed");
}
void rejectsChangedIdentity() {
    QTemporaryDir folder;require(folder.isValid(),"isolated switch");
    QSettings settings(folder.filePath("profile.ini"),QSettings::IniFormat);setup(settings);
    auto backend=std::make_unique<Store>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    const auto source=CredentialAccess::source(settings,{});
    require(finish(access.load(source)).result.succeeded(),"initial migration");
    store->blockNextRead=true;auto pending=access.load(source);
    require(store->entered.tryAcquire(1,1000),"pending read reached native boundary");
    settings.setValue("Credential/Username","bob");settings.sync();store->resume.release();
    const auto late=finish(pending);
    require(late.result.status==CredentialStatus::Cancelled && late.credentials.password.isEmpty() && late.credentials.totpSecret.isEmpty(),"late read cannot deliver credentials after account switch");
    auto draft=source.profile;draft.credentials.password="must not save";
    require(finish(access.save(source,draft,true,{})).status==CredentialStatus::Cancelled,"stale source cannot initiate a credential write");
    ProfileCredentials vault(*store);ConnectionCredentials original;
    require(vault.load(source.scope,source.profile,original).succeeded() && original.password=="legacy password","stale save did not overwrite existing credentials");
    settings.setValue("Credential/Username","alice");settings.sync();
    store->blockNextRead=true;auto saving=access.save(source,draft,true,{});
    require(store->entered.tryAcquire(1,1000),"save readback reached native boundary");
    settings.setValue("Credential/Username","bob");settings.sync();store->resume.release();
    require(finish(saving).status==CredentialStatus::Cancelled,"late save result rejected after account switch");
    const auto bob=CredentialAccess::source(settings,{});
    require(finish(access.load(bob)).result.status==CredentialStatus::NotFound,"late save never assigns old account credentials to the new account");
    settings.setValue("Credential/Username","alice");settings.sync();
    settings.setValue("JustConnect/ServerAddress","other.example.invalid");settings.sync();
    require(finish(access.load(source)).result.status==CredentialStatus::Cancelled,"server changes reject old source snapshots");
}
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    try {readsAndSavesOutsideGui();sealsCacheBeforeDelivery();acceptsUnconfiguredFirstLaunch();publicSaveFailureAndStaleness();rejectsChangedIdentity();std::cout<<"PASS: asynchronous serialized credentials, migration, save failure and stale identity rejection\n";return 0;}
    catch(const std::exception &error) {std::cerr<<error.what()<<'\n';return 1;}
}
