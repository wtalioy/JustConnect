#pragma once
#include "proxycheck.h"
#include <QUdpSocket>

inline void exerciseNativeTUNTraffic()
{
    using ProxyCheck::check;
    QTcpSocket tcp;
    tcp.connectToHost(QHostAddress("198.18.0.6"), 80);
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
