#include "infrastructure/credentialstore/systemcredentialstore.h"
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QDBusVariant>

namespace {
const QString service="org.freedesktop.secrets", root="/org/freedesktop/secrets";
const QString serviceInterface="org.freedesktop.Secret.Service", collectionInterface="org.freedesktop.Secret.Collection";
const QString itemInterface="org.freedesktop.Secret.Item";
using Attributes=QMap<QString,QString>;
struct Secret { QDBusObjectPath session; QByteArray parameters,value; QString contentType; };
QDBusArgument &operator<<(QDBusArgument &a,const Secret &s) {
    a.beginStructure(); a<<s.session<<s.parameters<<s.value<<s.contentType; a.endStructure(); return a;
}
const QDBusArgument &operator>>(const QDBusArgument &a,Secret &s) {
    a.beginStructure(); a>>s.session>>s.parameters>>s.value>>s.contentType; a.endStructure(); return a;
}
}
Q_DECLARE_METATYPE(Secret)

namespace {
CredentialStatus errorStatus(const QString &name) {
    if (name=="org.freedesktop.Secret.Error.IsLocked") return CredentialStatus::Locked;
    if (name=="org.freedesktop.DBus.Error.AccessDenied" || name=="org.freedesktop.DBus.Error.AuthFailed") return CredentialStatus::PermissionDenied;
    if (name=="org.freedesktop.Secret.Error.NoSuchObject") return CredentialStatus::NotFound;
    if (name=="org.freedesktop.DBus.Error.ServiceUnknown" || name=="org.freedesktop.DBus.Error.NameHasNoOwner"
        || name=="org.freedesktop.DBus.Error.NoReply" || name=="org.freedesktop.DBus.Error.Disconnected"
        || name=="org.freedesktop.DBus.Error.Timeout" || name=="org.freedesktop.Secret.Error.NotSupported") return CredentialStatus::Unavailable;
    return CredentialStatus::Failed;
}
class Operation {
public:
    QDBusConnection bus=QDBusConnection::sessionBus();
    CredentialStatus status=CredentialStatus::Success;
    QDBusObjectPath collection,session;
    Operation() {
        static const bool registered=[] {qDBusRegisterMetaType<Secret>();qDBusRegisterMetaType<Attributes>();return true;}(); (void)registered;
        if (!bus.isConnected()) {status=CredentialStatus::Unavailable; return;}
        auto reply=call(root,serviceInterface,"ReadAlias",{QString("default")});
        if (!okay()) return;
        collection=qdbus_cast<QDBusObjectPath>(reply.arguments().value(0));
        if (collection.path().isEmpty() || collection.path()=="/") {status=CredentialStatus::Unavailable;return;}
        reply=call(collection.path(),"org.freedesktop.DBus.Properties","Get",{collectionInterface,QString("Locked")});
        if (!okay()) return;
        const auto locked=qdbus_cast<QDBusVariant>(reply.arguments().value(0)).variant();
        if (locked.metaType()!=QMetaType::fromType<bool>()) {status=CredentialStatus::Failed;return;}
        if (locked.toBool()) {status=CredentialStatus::Locked;return;}
        reply=call(root,serviceInterface,"OpenSession",{QString("plain"),QVariant::fromValue(QDBusVariant(QString()))});
        if (!okay()) return;
        session=qdbus_cast<QDBusObjectPath>(reply.arguments().value(1));
        if (session.path().isEmpty() || session.path()=="/") status=CredentialStatus::Failed;
    }
    ~Operation() {
        if (!session.path().isEmpty() && session.path()!="/") call(session.path(),"org.freedesktop.Secret.Session","Close");
    }
    bool okay() const {return status==CredentialStatus::Success;}
    QDBusMessage call(const QString &path,const QString &interface,const QString &method,const QVariantList &arguments={}) {
        auto request=QDBusMessage::createMethodCall(service,path,interface,method); request.setArguments(arguments);
        const auto reply=bus.call(request,QDBus::Block,1000);
        if (reply.type()!=QDBusMessage::ReplyMessage) status=errorStatus(reply.errorName());
        return reply;
    }
    static Attributes attributes(const QString &key) {return {{"application","com.github.wtalioy.JustConnect"},{"key",key}};}
    QDBusObjectPath find(const QString &key) {
        const auto reply=call(collection.path(),collectionInterface,"SearchItems",{QVariant::fromValue(attributes(key))});
        if (!okay()) return {};
        const auto items=qdbus_cast<QList<QDBusObjectPath>>(reply.arguments().value(0));
        if (items.size()!=1) {status=items.isEmpty()?CredentialStatus::NotFound:CredentialStatus::Failed;return {};}
        return items.first();
    }
    bool noPrompt(const QDBusMessage &reply,int index) {
        if (!okay()) return false;
        const auto path=qdbus_cast<QDBusObjectPath>(reply.arguments().value(index)).path();
        if (path=="/") return true;
        if (!path.isEmpty()) call(path,"org.freedesktop.Secret.Prompt","Dismiss");
        status=CredentialStatus::PermissionDenied; return false;
    }
};
class Store final : public CredentialStore {
public:
    CredentialResult read(const QString &key) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        Operation op; if (!op.okay()) return {op.status,{}};
        const auto item=op.find(key); if (!op.okay()) return {op.status,{}};
        const auto reply=op.call(item.path(),itemInterface,"GetSecret",{QVariant::fromValue(op.session)});
        if (!op.okay()) return {op.status,{}};
        const auto secret=qdbus_cast<Secret>(reply.arguments().value(0));
        // Providers may normalize MIME; the stored bytes remain opaque.
        if (secret.session!=op.session || !secret.parameters.isEmpty()) return {CredentialStatus::Failed,{}};
        if (secret.value.size()>MaxBytes) return {CredentialStatus::Limit,{}};
        return {CredentialStatus::Success,secret.value};
    }
    CredentialResult write(const QString &key,const QByteArray &value) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        if (value.size()>MaxBytes) return {CredentialStatus::Limit,{}};
        Operation op; if (!op.okay()) return {op.status,{}};
        const QVariantMap properties{{itemInterface+".Label","JustConnect"},{itemInterface+".Attributes",QVariant::fromValue(Operation::attributes(key))}};
        const Secret secret{op.session,{},value,"application/octet-stream"};
        const auto reply=op.call(op.collection.path(),collectionInterface,"CreateItem",{properties,QVariant::fromValue(secret),true});
        if (!op.noPrompt(reply,1)) return {op.status,{}};
        if (qdbus_cast<QDBusObjectPath>(reply.arguments().value(0)).path()=="/") return {CredentialStatus::Failed,{}};
        return {CredentialStatus::Success,{}};
    }
    CredentialResult remove(const QString &key) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        Operation op; if (!op.okay()) return {op.status,{}};
        const auto item=op.find(key); if (!op.okay()) return {op.status,{}};
        const auto reply=op.call(item.path(),itemInterface,"Delete");
        if (!op.noPrompt(reply,0)) return {op.status,{}};
        return {CredentialStatus::Success,{}};
    }
};
}
std::unique_ptr<CredentialStore> createSystemCredentialStore() {return std::make_unique<Store>();}
