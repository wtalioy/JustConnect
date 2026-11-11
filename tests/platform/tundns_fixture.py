"""Shared actual system-resolver query and TUN reply fixture."""

import os
import select
import socket
import struct
import subprocess
import sys
import time

from dns_fixture import dns_answer

UTUN_IPV4 = struct.pack('!I', socket.AF_INET)


def dns_reply(fd, packet, expected, peer):
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_UDP:
        return False
    offset = (packet[0] & 15) * 4
    source, target, length, _ = struct.unpack('!4H', packet[offset:offset + 8])
    if target != 53:
        return False
    assert packet[16:20] == socket.inet_aton(peer), 'system query used a DNS server outside the owned peer'
    # Darwin's system resolver also sends interface discovery queries to this peer.
    answer = dns_answer(packet[offset + 8:offset + length], expected, ignore_unrelated=True)
    if answer is None:
        return False
    udp = struct.pack('!4H', target, source, 8 + len(answer), 0) + answer
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, socket.IPPROTO_UDP, 0, packet[16:20], packet[12:16])
    checksum = sum(struct.unpack('!10H', header))
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    header = header[:10] + struct.pack('!H', (~checksum) & 0xffff) + header[12:]
    response = UTUN_IPV4 + header + udp
    assert os.write(fd, response) == len(response)
    return True


def query_via_tun(device, hostname, peer):
    code = ('import os,socket; '
            f'assert os.getuid()==os.geteuid()=={os.getuid()}; '
            'assert all(r[4][0].startswith("127.") for r in socket.getaddrinfo("localhost",None,socket.AF_INET)); '
            f'print(socket.getaddrinfo({hostname!r},None,socket.AF_INET,socket.SOCK_STREAM))')
    query = subprocess.Popen([sys.executable, '-c', code],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    packets = 0
    try:
        deadline = time.monotonic() + 8
        while query.poll() is None and time.monotonic() < deadline:
            if select.select([device], [], [], 0.05)[0]:
                packet = os.read(device, 65536)
                if not packet.startswith(UTUN_IPV4):
                    continue
                packets += dns_reply(device, packet[len(UTUN_IPV4):], hostname, peer)
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
    query_via_tun(args.device, args.hostname, args.peer)
    print('PASS: ordinary getaddrinfo and localhost through the owned supplemental DNS path')
