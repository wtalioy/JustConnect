#include "infrastructure/socketownership/linux/listenerproof.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>

static void check(bool okay, const char *message) { if (!okay) qFatal("%s",message); }
static QString start(pid_t pid) {
    QFile file("/proc/"+QString::number(pid)+"/stat");
    check(file.open(QIODevice::ReadOnly),"read process identity");
    const auto bytes=file.readAll();
    return QString::fromLatin1(bytes.mid(bytes.lastIndexOf(')')+1).simplified().split(' ').value(19));
}
int main(int argc, char **argv) {
    QCoreApplication app(argc,argv);
    if (argc == 3 && QByteArray(argv[1]) == "--prove") {
        const auto request=QJsonDocument::fromJson(argv[2]).object();
        const auto proofs=readLinuxListenerProofs(request);
        if (!proofs) return 1;
        std::cout<<QJsonDocument(*proofs).toJson(QJsonDocument::Compact).constData()<<'\n';
        return 0;
    }
    for (const int kind:{0,1,2}) {
        const int family = kind == 0 ? AF_INET : AF_INET6;
        const int socket=::socket(family,SOCK_STREAM|SOCK_CLOEXEC,0);
        check(socket>=0,"create owned TCP socket");
        sockaddr_storage storage{};socklen_t length;
        if (family==AF_INET) {
            auto *address=reinterpret_cast<sockaddr_in *>(&storage);
            address->sin_family=AF_INET; address->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*address);
        } else {
            auto *address=reinterpret_cast<sockaddr_in6 *>(&storage);
            address->sin6_family=AF_INET6; address->sin6_addr=in6addr_loopback; length=sizeof(*address);
            if (kind == 2) check(::inet_pton(AF_INET6,"::ffff:127.0.0.1",&address->sin6_addr)==1,"IPv4 mapped fixture address");
        }
        check(::bind(socket,reinterpret_cast<sockaddr *>(&storage),length)==0 && ::listen(socket,1)==0
            && ::getsockname(socket,reinterpret_cast<sockaddr *>(&storage),&length)==0,"listen on a kernel assigned loopback endpoint");
        const auto port=family==AF_INET ? ntohs(reinterpret_cast<sockaddr_in *>(&storage)->sin_port)
                                      : ntohs(reinterpret_cast<sockaddr_in6 *>(&storage)->sin6_port);
        const auto endpoint=(kind==1?QStringLiteral("[::1]:"):QStringLiteral("127.0.0.1:"))+QString::number(port);
        const QJsonObject request{{"pid",QString::number(::getpid())},{"started",start(::getpid())},{"endpoints",QJsonArray{endpoint}}};
        auto proof=readLinuxListenerProofs(request);
        check(proof && proof->size()==1 && proof->first().toObject()["endpoint"]==endpoint
            && proof->first().toObject()["pid"]==request["pid"] && proof->first().toObject()["started"]==request["started"]
            && proof->first().toObject()["inode"].toString().toULongLong()!=0,"native proof did not bind the exact process and live socket inode");
        check(validLinuxListenerProofs(request,*proof),"Reject a matching native proof");
        for (const auto &field : {"pid","started","inode","endpoint"}) {
            auto changed=proof->first().toObject();changed[field]="invalid";
            check(!validLinuxListenerProofs(request,QJsonArray{changed}),"Foreign or malformed proof crossed the native channel");
        }
        check(!validLinuxListenerProofs(request,QJsonArray{proof->first(),proof->first()}),"Duplicate proof crossed the native channel");
        auto stale=request; stale["started"]="1";
        check(readLinuxListenerProofs(stale)==std::optional<QJsonArray>(QJsonArray{}),"stale process identity acquired a proof");
        for (const auto &value:{QStringLiteral("192.0.2.1:80"),QStringLiteral("localhost:80"),QStringLiteral("127.0.0.1:0"),QStringLiteral("127.0.0.1:080")}) {
            auto invalid=request;invalid["endpoints"]=QJsonArray{value};
            check(!validLinuxListenerRequest(invalid) && !readLinuxListenerProofs(invalid),"untrusted endpoint reached native observation");
        }
        auto duplicate=request;duplicate["endpoints"]=QJsonArray{endpoint,endpoint};
        check(!validLinuxListenerRequest(duplicate),"duplicate listeners were accepted");
        auto extra=request;extra["path"]="/proc/1/fd";
        check(!validLinuxListenerRequest(extra),"caller supplied a privileged path");
        ::close(socket);
        check(readLinuxListenerProofs(request)==std::optional<QJsonArray>(QJsonArray{}),"closed listener retained a live proof");
    }
    std::cout<<"PASS: native listener identity, IPv4/IPv6, stale process, closed socket and strict request boundary\n";
}
