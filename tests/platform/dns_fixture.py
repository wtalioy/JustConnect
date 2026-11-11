"""Portable DNS wire replies shared by native system-resolver fixtures."""
import socket
import struct


def dns_answer(query, expected, *, ignore_unrelated=False, ipv4="203.0.113.9"):
    assert len(query) >= 12 and struct.unpack('!H', query[4:6])[0] == 1
    cursor, labels = 12, []
    while query[cursor]:
        size = query[cursor]
        assert 0 < size <= 63 and cursor + size + 1 < len(query)
        labels.append(query[cursor + 1:cursor + size + 1].decode('ascii'))
        cursor += size + 1
    cursor += 1
    qtype, qclass = struct.unpack('!HH', query[cursor:cursor + 4])
    matches = '.'.join(labels).lower() == expected and qclass == 1 and qtype in (1, 28)
    if ignore_unrelated and not matches:
        return None
    assert matches, (labels, qclass, qtype, expected)
    answer = query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + query[12:cursor + 4]
    address = socket.inet_aton(ipv4) if qtype == 1 else socket.inet_pton(socket.AF_INET6, '2001:db8::9')
    answer += struct.pack('!HHHIH', 0xc00c, qtype, 1, 60, len(address)) + address
    return answer
