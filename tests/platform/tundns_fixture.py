"""Shared actual system-resolver query and TUN reply fixture."""

import os
from pathlib import Path
import pwd
import select
import socket
import struct
import subprocess
import sys
import time

from dns_fixture import dns_answer


def dns_reply(fd, packet, expected, peer, framing=b''):
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_UDP:
        return False
    offset = (packet[0] & 15) * 4
    source, target, length, _ = struct.unpack('!4H', packet[offset:offset + 8])
    if target != 53:
        return False
    assert packet[16:20] == socket.inet_aton(peer), 'system query used a DNS server outside the owned peer'
    # Darwin's system resolver also sends interface discovery queries to this peer.
    answer = dns_answer(packet[offset + 8:offset + length], expected, ignore_unrelated=bool(framing))
    if answer is None:
        return False
    udp = struct.pack('!4H', target, source, 8 + len(answer), 0) + answer
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, socket.IPPROTO_UDP, 0, packet[16:20], packet[12:16])
    checksum = sum(struct.unpack('!10H', header))
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    header = header[:10] + struct.pack('!H', (~checksum) & 0xffff) + header[12:]
    assert os.write(fd, framing + header + udp) == len(framing) + len(header) + len(udp)
    return True


def query_via_tun(device, hostname, peer, uid, environment):
    account = pwd.getpwuid(uid)
    code = ('import os,socket; assert os.getuid()==os.geteuid()==' + str(uid)
            + ('')
            + ('; assert all(r[4][0].startswith("127.") for r in socket.getaddrinfo("localhost",None,socket.AF_INET))')
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
                packet = os.read(device, 65536)
                framing = struct.pack('!I', socket.AF_INET)
                if framing and not packet.startswith(framing):
                    continue
                packets += dns_reply(device, packet[len(framing):], hostname, peer, framing)
        output, error = query.communicate(timeout=1)
        assert query.returncode == 0 and '203.0.113.9' in output and packets > 0, (output, error)
    finally:
        if query.poll() is None:
            query.kill()
            query.communicate(timeout=5)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Ordinary Darwin system resolver through an inherited owned utun')
    parser.add_argument('--device', type=int, required=True)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--peer', required=True)
    args = parser.parse_args()
    assert sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0
    query_via_tun(args.device, args.hostname, args.peer, os.getuid(), os.environ.copy())
    print('PASS: ordinary getaddrinfo and localhost through the owned supplemental DNS path')
