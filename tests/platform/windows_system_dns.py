"""Exercise native Windows DNS through real original and redirected endpoints."""
from contextlib import ExitStack
import os
import socket
import subprocess
import threading
import uuid

from dns_fixture import dns_answer


def verify(executable):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Windows':
        raise RuntimeError('System DNS writes require a disposable Windows runner')
    addresses = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM)
    address = next(item[4][0] for item in addresses if not item[4][0].startswith(('127.', '169.254.')))
    hostname = uuid.uuid4().hex + '.invalid'
    encrypted_server = '192.0.2.254'
    received, failures, stopped = [[], []], [], threading.Event()
    threads = []
    with ExitStack() as stack:
        endpoints = []
        for listen, answer_ip in ((address, '203.0.113.9'), ('127.0.0.1', '203.0.113.10')):
            server = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            server.bind((listen, 53))
            server.settimeout(0.1)
            endpoints.append((server, answer_ip))
        for index, (server, answer_ip) in enumerate(endpoints):
            def serve(endpoint=server, answer_ip=answer_ip, queries=received[index]):
                while not stopped.is_set():
                    try:
                        query, sender = endpoint.recvfrom(65536)
                    except socket.timeout:
                        continue
                    try:
                        endpoint.sendto(dns_answer(query, hostname, ipv4=answer_ip), sender)
                        queries.append(hostname)
                    except BaseException as error:
                        failures.append(str(error))
                        return

            thread = threading.Thread(target=serve)
            thread.start()
            threads.append(thread)
        try:
            subprocess.run(['netsh', 'dnsclient', 'add', 'encryption', f'server={encrypted_server}',
                            'dothost=dns.fixture.invalid:853', 'autoupgrade=yes', 'udpfallback=no'], check=True, timeout=10)
            # The native parent owns cleanup; this outer deadline only catches a stuck fixture.
            try:
                subprocess.run([str(executable), address, hostname, encrypted_server], check=True, timeout=50)
                if len(received[0]) < 2 or not received[1] or failures:
                    raise RuntimeError(f'Native resolver did not follow both DNS endpoints and restoration: {received}, {failures}')
            finally:
                subprocess.run(['netsh', 'dnsclient', 'delete', 'encryption', f'server={encrypted_server}', 'protocol=dot'], check=True, timeout=10)
        finally:
            stopped.set()
            for thread in threads:
                thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError('DNS fixture thread did not stop')
