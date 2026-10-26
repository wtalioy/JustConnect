#pragma once
#include "proxycheck.h"
#include <QUdpSocket>
#include <QProcess>
#include <QJsonDocument>
#include <QFileInfo>

inline void exerciseNativeTUNUDP()
{
    using ProxyCheck::check;
    QUdpSocket udp;
    udp.connectToHost(QHostAddress("198.18.0.6"), 53);
    for (const auto &packet : {QByteArray("native-tun-datagram"), QByteArray()}) {
        check(udp.write(packet) == packet.size(), "native UDP datagram sent");
        check(udp.waitForReadyRead(5000), "native UDP datagram returned through campus tunnel");
        QByteArray returned(qMax(packet.size(), qsizetype(1)), Qt::Uninitialized);
        const auto size = udp.readDatagram(returned.data(), returned.size());
        check(size >= 0, "native UDP datagram received");
        returned.resize(size);
        check(returned == packet, "native UDP bytes and empty datagram preserved");
    }
}

inline void exerciseNativeTUNTraffic(const QHostAddress &tcpTarget = QHostAddress("198.18.0.6"))
{
    using ProxyCheck::check;
    QTcpSocket tcp;
    tcp.connectToHost(tcpTarget, 80);
    check(tcp.waitForConnected(5000), "ordinary TCP reached campus through kernel capture and C ABI");
    const QByteArray payload(32768, 't');
    check(tcp.write(payload) == payload.size(), "native TCP payload queued");
    while (tcp.bytesToWrite() > 0) check(tcp.waitForBytesWritten(5000), "native TCP payload sent");
    QByteArray reply;
    while (reply.size() < payload.size()) {
        if (!tcp.bytesAvailable()) check(tcp.waitForReadyRead(5000), "native TUN TCP response available");
        reply += tcp.readAll();
    }
    check(reply == payload, "multi-packet native TCP bytes preserved through campus tunnel");
    tcp.abort();
    exerciseNativeTUNUDP();
}

inline void exerciseOriginalNetworkUDP()
{
    using ProxyCheck::check;
    const QByteArray tag("original:"), payload("same-ip-original-network");
    QUdpSocket udp;
    udp.connectToHost(QHostAddress("198.18.0.6"),53);
    for (const auto &packet : {payload,QByteArray{}}) {
        const auto expected = tag + packet;
        check(udp.write(packet) == packet.size() && udp.waitForReadyRead(5000),"ordinary UDP reaches the original side of an overlapping IP");
        check(udp.pendingDatagramSize() == expected.size(),"original peer UDP datagram has the exact expected length");
        QByteArray returned(expected.size(),Qt::Uninitialized);
        check(udp.readDatagram(returned.data(),returned.size()) == returned.size() && returned == expected,
              "same-IP original UDP bytes and empty datagrams never entered the campus tunnel");
    }
}

inline void exerciseOriginalNetworkTraffic()
{
    using ProxyCheck::check;
    const QByteArray tag("original:"), payload("same-ip-original-network");
    QTcpSocket tcp;
    tcp.connectToHost(QHostAddress("198.18.0.7"),80);
    check(tcp.waitForConnected(5000),"ordinary TCP reaches the original side of an overlapping IP");
    check(ProxyCheck::receive(tcp,tag.size()) == tag,"same-IP TCP connected to the original peer rather than the campus tunnel");
    check(tcp.write(payload) == payload.size() && (tcp.bytesToWrite() == 0 || tcp.waitForBytesWritten(5000)),"original TCP payload sent");
    check(ProxyCheck::receive(tcp,payload.size()) == payload,"original TCP payload preserved");
    tcp.abort();
    exerciseOriginalNetworkUDP();
}

inline void exerciseNativeSSH(const QHostAddress &target)
{
    const auto encoded=qgetenv("JC_NATIVE_SSH_PROBE");
    if(encoded.isEmpty())return;
    const auto probe=QJsonDocument::fromJson(encoded).object();
    const auto config=probe["config"].toString(),command=probe["command"].toString(),expected=probe["expected"].toString();
    ProxyCheck::check(QFileInfo(config).isAbsolute() && QFileInfo(config).isFile() && !command.isEmpty() && !expected.isEmpty(),"private native SSH probe contract");
    const auto hostname=probe["hostname"].toString();
    ProxyCheck::check(!hostname.isEmpty(),"native SSH domain is supplied by the gateway fixture");
    for(const auto &host:QStringList{target.toString(),hostname}){
        QProcess process;
        process.start("ssh",{"-F",config,host,command});
        const bool finished=process.waitForStarted(5000) && process.waitForFinished(10000);
        const auto output=process.readAllStandardOutput(),error=process.readAllStandardError();
        if(!finished || process.exitStatus()!=QProcess::NormalExit || process.exitCode()!=0)
            std::cerr<<"OpenSSH probe "<<host.toStdString()<<": "<<process.errorString().toStdString()<<" "<<error.toStdString()<<'\n';
        ProxyCheck::check(finished && process.exitStatus()==QProcess::NormalExit && process.exitCode()==0
            && output==expected.toUtf8(),"ordinary OpenSSH authenticates the pinned campus IP/domain and executes the exact command without a proxy");
    }
}
