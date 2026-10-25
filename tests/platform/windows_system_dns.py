"""Exercise native Windows DNS through a real endpoint without depending on Wintun."""
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
    received, failures, stopped = [], [], threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        server.bind((address, 53))
        server.settimeout(0.1)

        def serve():
            while not stopped.is_set():
                try:
                    query, sender = server.recvfrom(65536)
                except socket.timeout:
                    continue
                try:
                    answer = dns_answer(query, hostname)
                    server.sendto(answer, sender)
                    received.append(hostname)
                except BaseException as error:
                    failures.append(str(error))
                    return

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            # The native parent owns cleanup; this outer deadline only catches a stuck fixture.
            subprocess.run([str(executable), address, hostname], check=True, timeout=30)
            if not received or failures:
                raise RuntimeError(f'Native resolver did not reach the owned DNS endpoint: {received}, {failures}')
        finally:
            stopped.set()
            thread.join(timeout=2)
        if thread.is_alive():
            raise RuntimeError('DNS fixture thread did not stop')
