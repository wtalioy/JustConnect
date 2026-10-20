#include "infrastructure/platform/systemcredentialstore.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QUuid>
#include <iostream>
#include <stdexcept>
#ifdef Q_OS_MACOS
#include "infrastructure/platform/macos/credentialstore.h"
#elif defined(Q_OS_WIN)
#include <windows.h>
#endif

namespace {
void require(bool okay,const char *message) {if (!okay) throw std::runtime_error(message);}
void expect(const CredentialResult &r,CredentialStatus status,const char *operation) {
    if (r.status!=status) throw std::runtime_error(std::string(operation)+": status="+std::to_string(int(r.status))+" native="+std::to_string(r.nativeCode));
}
QString digest(const QByteArray &value) {return QString::fromLatin1(QCryptographicHash::hash(value,QCryptographicHash::Sha256).toHex());}
QByteArray original() {QByteArray value("fixture password");value.append('\0');value.append("fixture Cookie=sid");return value;}
const QByteArray updated="updated fixture password", other="other fixture cookie";
void prepare(CredentialStore &store,const QString &a,const QString &b) {
    expect(store.read(a),CredentialStatus::NotFound,"new scope");
    expect(store.read(b),CredentialStatus::NotFound,"other new scope");
    expect(store.write(a,original()),CredentialStatus::Success,"write opaque secret");
    auto result=store.read(a);expect(result,CredentialStatus::Success,"read opaque secret");
    require(result.value==original(),"binary secret did not round trip");
    expect(store.write(b,other),CredentialStatus::Success,"write other scope");
    expect(store.write(a,updated),CredentialStatus::Success,"replace own secret");
    result=store.read(a);expect(result,CredentialStatus::Success,"read replacement");
    require(result.value==updated,"replacement did not persist");
    expect(store.write(a,QByteArray(CredentialStore::MaxBytes+1,'x')),CredentialStatus::Limit,"oversized write");
#ifdef Q_OS_WIN
    expect(store.write(a,QByteArray(3000,'x')),CredentialStatus::Limit,"Credential Manager blob limit");
#endif
    require(store.read(a).value==updated && store.read(b).value==other,"failed writes damaged stored values or another scope");
}
void locked(CredentialStore &store,const QString &a) {
    expect(store.read(a),CredentialStatus::Locked,"read locked store");
    expect(store.write(a,"must not overwrite"),CredentialStatus::Locked,"write locked store");
    expect(store.remove(a),CredentialStatus::Locked,"remove from locked store");
}
void finish(CredentialStore &store,const QString &a,const QString &b) {
    const auto first=store.read(a),second=store.read(b);
    expect(first,CredentialStatus::Success,"read own scope after unlock");expect(second,CredentialStatus::Success,"read other scope after unlock");
    require(first.value==updated && second.value==other,"unavailable or locked operations changed protected values");
    expect(store.remove(a),CredentialStatus::Success,"delete own scope");
    expect(store.read(a),CredentialStatus::NotFound,"deleted scope");
    require(store.read(b).value==other,"deletion affected another scope");
    expect(store.remove(a),CredentialStatus::NotFound,"repeat deletion");
    expect(store.remove(b),CredentialStatus::Success,"delete second fixture scope");
}
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    try {
        const auto arguments=app.arguments();
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN) || defined(Q_OS_LINUX)
        const auto mode=arguments.value(1,"smoke");
#else
        const auto mode=arguments.value(1,"unavailable");
#endif
        const auto a=arguments.size()>2 ? arguments[2] : digest(QUuid::createUuid().toRfc4122());
        const auto b=digest(a.toUtf8()+"other");
#ifdef Q_OS_MACOS
        QTemporaryDir folder;require(folder.isValid(),"isolated keychain directory");
        const auto path=folder.filePath("fixture.keychain-db").toUtf8();const QByteArray password="fixture keychain password";
        SecKeychainRef keychain=nullptr;
        require(SecKeychainCreate(path.constData(),UInt32(password.size()),password.constData(),false,nullptr,&keychain)==errSecSuccess,"create isolated keychain");
        const auto cleanup=qScopeGuard([&]{SecKeychainDelete(keychain);CFRelease(keychain);});
        require(SecKeychainUnlock(keychain,UInt32(password.size()),password.constData(),true)==errSecSuccess,"unlock new isolated keychain");
        auto store=createMacCredentialStore(keychain);
#else
        auto store=createSystemCredentialStore();
#endif
        expect(store->read("invalid/key"),CredentialStatus::InvalidArgument,"invalid key read");
        expect(store->write("invalid/key",original()),CredentialStatus::InvalidArgument,"invalid key write");
        expect(store->remove("invalid/key"),CredentialStatus::InvalidArgument,"invalid key removal");
        if (mode=="unavailable") {
            expect(store->read(a),CredentialStatus::Unavailable,"unavailable read");
            expect(store->write(a,original()),CredentialStatus::Unavailable,"unavailable write");
            expect(store->remove(a),CredentialStatus::Unavailable,"unavailable removal");
        } else if (mode=="denied") {
            expect(store->write(a,original()),CredentialStatus::PermissionDenied,"real bus policy denies writing");
            expect(store->read(a),CredentialStatus::NotFound,"denied write created no secret");
        } else if (mode=="locked") locked(*store,a);
        else if (mode=="prepare") prepare(*store,a,b);
        else if (mode=="finish") finish(*store,a,b);
        else {
            expect(store->read(a),CredentialStatus::NotFound,"unique fixture key");
            expect(store->read(b),CredentialStatus::NotFound,"unique second fixture key");
            const auto cleanup=qScopeGuard([&]{store->remove(a);store->remove(b);});
            prepare(*store,a,b);
#ifdef Q_OS_MACOS
            require(SecKeychainLock(keychain)==errSecSuccess,"lock isolated keychain");locked(*store,a);
            require(SecKeychainUnlock(keychain,UInt32(password.size()),password.constData(),true)==errSecSuccess,"unlock isolated keychain");
#elif defined(Q_OS_WIN)
            require(ImpersonateAnonymousToken(GetCurrentThread()),"anonymous logon boundary");
            {
                const auto revert=qScopeGuard([]{RevertToSelf();});
                const auto read=store->read(a),write=store->write(a,"must not overwrite"),remove=store->remove(a);
                const auto inaccessible=[](CredentialStatus s){return s==CredentialStatus::Unavailable || s==CredentialStatus::PermissionDenied;};
                require(inaccessible(read.status) && read.value.isEmpty() && inaccessible(write.status) && inaccessible(remove.status),"anonymous logon accessed credentials");
            }
#endif
            finish(*store,a,b);
        }
        std::cout<<"PASS: native credential store "<<mode.toStdString()<<'\n';return 0;
    } catch(const std::exception &error) {std::cerr<<error.what()<<'\n';return 1;}
}
