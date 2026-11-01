"""Verify ordinary data access to an owned root Mihomo in a private Linux network."""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time


def wait_for_listener_proof(runtime, control, proof, request, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if runtime.poll() is not None or remaining <= 0:
            raise TimeoutError('owned controller/data listener was not ready')
        if control.is_socket():
            result = subprocess.run([str(proof), '--prove', json.dumps(request)], check=True,
                                    capture_output=True, text=True, timeout=min(5, remaining))
            records = json.loads(result.stdout)
            if not isinstance(records, list):
                raise ValueError('native ownership proof must be an array')
            if records:
                return result.stdout
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))


def verify(args):
    import pwd

    assert os.geteuid() == 0 and args.uid != 0
    assert os.stat('/proc/self/ns/net') != os.stat('/proc/1/ns/net'), 'refusing the host network'
    binary, probe, proof = (path.resolve(strict=True) for path in (args.mihomo, args.probe, args.proof))
    account = pwd.getpwuid(args.uid)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=3)
    with tempfile.TemporaryDirectory(prefix='jcm-owner-') as directory, socket.socket() as echo:
        root = Path(directory)
        root.chmod(0o711)
        owned = root / 'mihomo'
        shutil.copyfile(binary, owned)
        owned.chmod(0o700)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        config = {'external-controller-unix': str(root / 'control.sock'), 'mixed-port': port,
                  'port': 0, 'socks-port': 0, 'tun': {'enable': False}, 'dns': {'enable': False},
                  'mode': 'direct', 'rules': [], 'log-level': 'silent'}
        path = root / 'config.json'
        path.write_text(json.dumps(config), encoding='utf-8')
        path.chmod(0o600)
        echo.bind(('127.0.0.1', 0))
        echo.listen(1)
        echo.settimeout(0.1)
        errors = []
        stopped = threading.Event()

        def serve():
            try:
                while not stopped.is_set():
                    try:
                        connection, _ = echo.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(5)
                        while packet := connection.recv(65536):
                            connection.sendall(packet)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=serve)
        with (root / 'mihomo.log').open('wb') as log:
            runtime = subprocess.Popen([str(owned), '-d', str(root), '-f', str(path), '-ext-ctl-unix', str(root / 'control.sock')],
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                thread.start()
                deadline = time.monotonic() + 10
                stat = (Path('/proc') / str(runtime.pid) / 'stat').read_text()
                started = stat[stat.rindex(')') + 1:].split()[19]
                request = {'pid': str(runtime.pid), 'started': started,
                           'endpoints': ['127.0.0.1:' + str(port), '[::1]:' + str(port)]}
                proofs = wait_for_listener_proof(runtime, root / 'control.sock', proof, request, deadline)
                environment = {**os.environ, 'JC_OWNED_MIHOMO_PID': str(runtime.pid),
                               'JC_LISTENER_PROOFS': proofs, 'JC_OWNED_ECHO': '127.0.0.1:' + str(echo.getsockname()[1])}
                subprocess.run([str(probe), '-test.v', '-test.run', '^TestPrivilegedListenerOwnership$'],
                               env=environment, user=args.uid, group=account.pw_gid, extra_groups=[], check=True, timeout=20)
                stopped.set()
                thread.join(timeout=5)
                assert not thread.is_alive() and not errors, errors
                assert path.read_text(encoding='utf-8') == json.dumps(config), 'runtime changes altered the owned configuration source'
            finally:
                stopped.set()
                runtime.terminate()
                try:
                    runtime.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    runtime.kill()
                    runtime.wait(timeout=5)
                thread.join(timeout=11)
                if errors:
                    print('owned echo fixture:', errors, flush=True)
                if runtime.returncode not in (0, -15):
                    print((root / 'mihomo.log').read_text(encoding='utf-8'), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--mihomo', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    verify(parser.parse_args())


if __name__ == '__main__':
    main()
