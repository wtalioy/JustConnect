import importlib.util
from pathlib import Path
import socket
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('dns_fixture', Path(__file__).parent / 'platform/dns_fixture.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class DnsFixtureTest(unittest.TestCase):
    def query(self, kind, hostname='owned.invalid'):
        labels = b''.join(bytes([len(label)]) + label.encode('ascii') for label in hostname.split('.')) + b'\0'
        return struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + labels + struct.pack('!2H', kind, 1)

    def test_replies_preserve_question_and_type(self):
        for kind, expected in ((1, socket.inet_aton('203.0.113.9')),
                               (28, socket.inet_pton(socket.AF_INET6, '2001:db8::9'))):
            with self.subTest(kind=kind):
                query = self.query(kind)
                answer = fixture.dns_answer(query, 'owned.invalid')
                self.assertEqual(struct.unpack('!6H', answer[:12]), (123, 0x8180, 1, 1, 0, 0))
                self.assertEqual(answer[12:len(query)], query[12:])
                self.assertEqual(answer[len(query):], struct.pack('!HHHIH', 0xc00c, kind, 1, 60, len(expected)) + expected)

    def test_never_answers_outside_owned_question(self):
        for query in (self.query(1, 'other.invalid'), self.query(15)):
            with self.subTest(query=query):
                self.assertIsNone(fixture.dns_answer(query, 'owned.invalid', ignore_unrelated=True))
                with self.assertRaises(AssertionError):
                    fixture.dns_answer(query, 'owned.invalid')


if __name__ == '__main__':
    unittest.main()
