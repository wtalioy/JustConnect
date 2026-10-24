"""Shared actual system-resolver query and TUN reply fixture."""

import os
import pwd
import select
import socket
import struct
import subprocess
import sys
import time


def dns_reply(fd, packet, expected, peer):
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_UDP:
        return False
    offset = (packet[0] & 15) * 4
    source, target, length, _ = struct.unpack('!4H', packet[offset:offset + 8])
    if target != 53:
        return False
    assert packet[16:20] == socket.inet_aton(peer), 'system query used a DNS server outside the owned peer'
    query = packet[offset + 8:offset + length]
    assert len(query) >= 12 and struct.unpack('!H', query[4:6])[0] == 1
    cursor, labels = 12, []
    while query[cursor]:
        size = query[cursor]
        assert 0 < size <= 63 and cursor + size + 1 < len(query)
        labels.append(query[cursor + 1:cursor + size + 1].decode('ascii'))
        cursor += size + 1
    cursor += 1
    qtype, qclass = struct.unpack('!HH', query[cursor:cursor + 4])
    assert '.'.join(labels) == expected and qtype == qclass == 1
    answer = query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + query[12:cursor + 4]
    answer += struct.pack('!HHHIH4s', 0xc00c, 1, 1, 60, 4, socket.inet_aton('203.0.113.9'))
    udp = struct.pack('!4H', target, source, 8 + len(answer), 0) + answer
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, socket.IPPROTO_UDP, 0, packet[16:20], packet[12:16])
    checksum = sum(struct.unpack('!10H', header))
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    header = header[:10] + struct.pack('!H', (~checksum) & 0xffff) + header[12:]
    assert os.write(fd, header + udp) == len(header) + len(udp)
    return True


def query_via_tun(device, hostname, peer, uid, environment):
    account = pwd.getpwuid(uid)
    code = ('import os,socket; assert os.getuid()==os.geteuid()==' + str(uid)
            + '; assert int(next(s.split()[1] for s in open("/proc/self/status") if s.startswith("CapEff:")),16)==0'
            + '; print(socket.getaddrinfo(' + repr(hostname) + ',None,socket.AF_INET,socket.SOCK_STREAM))')
    assert os.geteuid() in (0, uid)
    identity = dict(user=uid, group=account.pw_gid, extra_groups=()) if os.geteuid() == 0 else {}
    query = subprocess.Popen([sys.executable, '-c', code], env=environment, **identity,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    packets = 0
    try:
        deadline = time.monotonic() + 8
        while query.poll() is None and time.monotonic() < deadline:
            if select.select([device], [], [], 0.05)[0]:
                packets += dns_reply(device, os.read(device, 65536), hostname, peer)
        output, error = query.communicate(timeout=1)
        assert query.returncode == 0 and '203.0.113.9' in output and packets > 0, (output, error)
    finally:
        if query.poll() is None:
            query.kill()
            query.communicate(timeout=5)
