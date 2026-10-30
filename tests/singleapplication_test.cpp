#include "singleapplication_p.h"
#include <QDataStream>
#include <QDeadlineTimer>
#include <QThread>
#include <QUuid>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace {
void require(bool ok,const char *message) {if (!ok) throw std::runtime_error(message);}
template<class F> void waitFor(F ready) {
    QDeadlineTimer deadline(2000);
    while (!ready() && !deadline.hasExpired()) {QCoreApplication::processEvents();QThread::msleep(1);}
    require(ready(),"bounded private IPC operation");
}
QByteArray init(const QString &name) {
    QByteArray result;
    QDataStream out(&result,QIODevice::WriteOnly);out.setVersion(QDataStream::Qt_5_6);
    out << name.toLatin1() << quint8(SingleApplicationPrivate::NewInstance) << quint32(7);
    out << qChecksum(result);
    return result;
}
void exchange(SingleApplication &app,const QByteArray &body,bool valid,bool fragmented=false) {
    SingleApplicationPrivate protocol(&app);
    protocol.blockServerName=QStringLiteral("JustConnect-IPC-test-")+QUuid::createUuid().toString(QUuid::Id128);
    QLocalServer server;
    require(server.listen(protocol.blockServerName),"listen on an owned private test socket");
    QLocalSocket client;client.connectToServer(server.fullServerName());
    waitFor([&]{return client.state()==QLocalSocket::ConnectedState && server.hasPendingConnections();});
    std::unique_ptr<QLocalSocket> peer(server.nextPendingConnection());
    protocol.connectionMap.insert(peer.get(),{});
    int activations=0;
    const auto connection=QObject::connect(&app,&SingleApplication::instanceStarted,&protocol,[&]{++activations;});
    QByteArray header;QDataStream out(&header,QIODevice::WriteOnly);out.setVersion(QDataStream::Qt_5_6);
    const auto payload=valid?init(protocol.blockServerName):body;
    out << quint64(payload.size());
    require(client.write(header)==header.size(),"write init length");client.flush();
    waitFor([&]{return peer->bytesAvailable()==header.size();});
    protocol.readMessageHeader(peer.get(),SingleApplicationPrivate::StageInitBody);
    waitFor([&]{return client.bytesAvailable()==1;});client.readAll();
    if (fragmented) {
        require(client.write(payload.first(1))==1,"write partial init");client.flush();
        waitFor([&]{return peer->bytesAvailable()==1;});
        protocol.readInitMessageBody(peer.get());
        require(activations==0 && peer->state()==QLocalSocket::ConnectedState,"partial frame waits without activation");
        require(client.write(payload.sliced(1))==payload.size()-1,"finish partial init");
    } else require(client.write(payload)==payload.size(),"write init payload");
    client.flush();
    waitFor([&]{return peer->bytesAvailable()==payload.size();});
    protocol.readInitMessageBody(peer.get());
    if (valid) {
        require(activations==1 && protocol.connectionMap[peer.get()].instanceId==7
            && protocol.connectionMap[peer.get()].stage==SingleApplicationPrivate::StageConnectedHeader,
            "valid init retains second-instance notification and identity");
        waitFor([&]{return client.bytesAvailable()==1;});
    } else require(activations==0 && peer->state()==QLocalSocket::UnconnectedState,"malformed init is closed without activation");
    QObject::disconnect(connection);
}
}
int main(int argc,char **argv) {
    SingleApplication app(argc,argv,false,SingleApplication::User,1000,QUuid::createUuid().toString());
    try {
        for (const auto &body:QList<QByteArray>{QByteArray{},QByteArray(1,'x'),QByteArray(2,'x'),init(QStringLiteral("wrong-server"))})
            exchange(app,body,false);
        exchange(app,{},true);
        exchange(app,{},true,true);
    } catch(const std::exception &error) {std::cerr << error.what() << '\n';return 1;}
    return 0;
}
