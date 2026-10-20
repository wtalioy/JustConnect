#pragma once
#include <QJsonObject>
#include <QTcpSocket>
#include <QHostAddress>
#include <functional>
#include <cstdlib>
#include <iostream>

namespace ProxyCheck {
inline void check(bool ok, const char *message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
inline QByteArray receive(QTcpSocket &socket, qsizetype size) {
    QByteArray data;
    while (data.size() < size) {
        if (!socket.bytesAvailable()) check(socket.waitForReadyRead(5000), "proxy receive deadline");
        data += socket.read(size - data.size());
    }
    return data;
}

inline void connectProxy(QTcpSocket &socket, const QString &address) {
    const auto port = address.mid(address.lastIndexOf(':') + 1).toUShort();
    socket.connectToHost(QHostAddress::LocalHost, port);
    check(socket.waitForConnected(5000), "connect owned loopback listener");
}
inline QByteArray openSocks(QTcpSocket &socket, const QString &address, bool udp = false) {
    connectProxy(socket, address);
    check(socket.write(QByteArray::fromHex("050100")) == 3 && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(5000)), "SOCKS greeting");
    check(receive(socket, 2) == QByteArray::fromHex("0500"), "SOCKS authentication");
    const auto destination = QByteArray::fromHex(udp ? "05030001000000000000" : "05010001c000020a0050");
    check(socket.write(destination) == destination.size() && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(5000)), "SOCKS destination");
    const auto response = receive(socket, 10);
    check(response.startsWith(QByteArray::fromHex("05000001")), "SOCKS IPv4 tunnel established");
    return response;
}
inline void exercise(const QJsonObject &listeners, const std::function<void()> &stop) {
    const auto verifyPayload = [&](QTcpSocket &socket) {
        const QByteArray payload(65536, 'j');
        check(socket.write(payload) == payload.size() && (socket.bytesToWrite() == 0 || socket.waitForBytesWritten(5000)), "proxy payload write");
        check(receive(socket, payload.size()) == payload, "actual tunnel payload returned");
    };
    QTcpSocket socks;
    openSocks(socks, listeners["socks"].toString());
    verifyPayload(socks);
    QTcpSocket http;
    connectProxy(http, listeners["http"].toString());
    const QByteArray request("CONNECT 192.0.2.10:80 HTTP/1.1\r\nHost: 192.0.2.10:80\r\n\r\n");
    check(http.write(request) == request.size() && (http.bytesToWrite() == 0 || http.waitForBytesWritten(5000)), "HTTP CONNECT write");
    QByteArray header;
    while (!header.endsWith("\r\n\r\n")) header += receive(http, 1);
    check(header.startsWith("HTTP/1.1 200"), "HTTP tunnel established");
    verifyPayload(http);
    stop();
    for (auto *socket : {&socks, &http}) {
        if (socket->state() != QAbstractSocket::UnconnectedState) socket->waitForDisconnected(5000);
        check(socket->state() == QAbstractSocket::UnconnectedState, "active proxy closed on stop");
    }
 }
}
