"""Actual application/Mihomo matrix inside the installed-helper private namespaces."""

import http.client
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def run_matrix(binary, gateway, host, uid, environment):
    command = ['unshare', '--mount', '--', sys.executable, '-B', str(Path(__file__).resolve()),
               '--mihomo', str(binary), '--gateway', str(gateway), '--host', str(host), '--uid', str(uid)]
    result = subprocess.run(command, env={**os.environ, **environment}, capture_output=True, text=True, timeout=200)
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', flush=True)
    assert result.returncode == 0, 'isolated desktop coexistence matrix failed'
    reports = [line.removeprefix('COEXISTENCE REPORT: ') for line in result.stdout.splitlines() if line.startswith('COEXISTENCE REPORT: ')]
    assert len(reports) == 1
    return json.loads(reports[0])


def matrix(binary, gateway, host, uid, environment, filter_mode, filter_entries):
    assert os.geteuid() == 0 and uid != 0
    for kind in ('net', 'mnt'):
        assert os.stat('/proc/thread-self/ns/' + kind) != os.stat('/proc/1/ns/' + kind), 'refusing host namespaces'
    # sysfs is scoped to the network namespace in which it was mounted.
    subprocess.run(['mount', '-t', 'sysfs', '-o', 'ro,nosuid,nodev,noexec', 'sysfs', '/sys'], check=True)
    account = pwd.getpwuid(uid)
    ordinary = dict(user=uid, group=account.pw_gid, extra_groups=())
    processes, logs = [], []
    original_interface = 'helperorig0'
    original_dns = None
    with tempfile.TemporaryDirectory(prefix='jcm-coexist-') as directory:
        root = Path(directory)
        root.chmod(0o711)
        desktop, runtime = root / 'desktop', root / 'runtime'
        desktop.mkdir(mode=0o700)
        runtime.mkdir(mode=0o700)
        os.chown(desktop, uid, account.pw_gid)
        env = {**environment, 'XDG_CURRENT_DESKTOP': 'GNOME', 'GSETTINGS_BACKEND': 'keyfile',
               'XDG_CONFIG_HOME': str(desktop / 'config'), 'XDG_DATA_HOME': str(desktop / 'data'),
               'XDG_RUNTIME_DIR': str(desktop / 'run'), 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(desktop / 'bus.sock')}
        for name in ('config', 'data', 'run', 'control'):
            path = desktop / name
            path.mkdir(mode=0o700)
            os.chown(path, uid, account.pw_gid)
        bus = desktop / 'bus.conf'
        bus.write_text('<busconfig><type>session</type><listen>' + env['DBUS_SESSION_BUS_ADDRESS'] + '</listen>'
                       '<auth>EXTERNAL</auth><policy context="default"><allow own="*"/>'
                       '<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
        os.chown(bus, uid, account.pw_gid)
        bus.chmod(0o600)

        def launch(arguments, values, identity=None, data=None):
            log = (root / ('process-' + str(len(processes)) + '.log')).open('wb')
            logs.append(log)
            process = subprocess.Popen(arguments, env=values, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL, **(identity or {}))
            processes.append(process)
            if data is not None:
                process.stdin.write(data)
                process.stdin.close()
            return process

        def run(arguments):
            return subprocess.check_output(arguments, env=env, text=True, timeout=10, **ordinary).strip()

        try:
            dbus = launch(['/usr/bin/dbus-daemon', '--nofork', '--config-file=' + str(bus)], env, ordinary)
            deadline = time.monotonic() + 5
            while not (desktop / 'bus.sock').is_socket():
                assert dbus.poll() is None and time.monotonic() < deadline, 'private desktop bus failed to start'
                time.sleep(0.02)
            provider = os.environ.get('JC_TEST_SECRET_PROVIDER') or shutil.which('gnome-keyring-daemon')
            assert provider, 'real Secret Service provider is required'
            secret_env = dict(env)
            libraries = os.environ.get('JC_TEST_SECRET_PROVIDER_LIBS')
            if libraries:
                secret_env['LD_LIBRARY_PATH'] = libraries + ':' + env.get('LD_LIBRARY_PATH', '')
            secrets = launch([provider, '--foreground', '--unlock', '--components=secrets', '--control-directory', str(desktop / 'control')],
                             secret_env, ordinary, b'owned coexistence keyring password')
            deadline = time.monotonic() + 5
            while run(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.DBus', '--object-path', '/org/freedesktop/DBus',
                       '--method', 'org.freedesktop.DBus.NameHasOwner', 'org.freedesktop.secrets']) != '(true,)':
                assert secrets.poll() is None and time.monotonic() < deadline, 'private Secret Service failed to start'
                time.sleep(0.02)
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0))
                port = reserve.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
                reserve.bind(('127.0.0.1', 0))
                dns_port = reserve.getsockname()[1]
            owned = runtime / 'mihomo'
            shutil.copyfile(binary, owned)
            owned.chmod(0o700)
            controller = root / 'controller.sock'
            config = {'external-controller-unix': str(controller), 'mixed-port': port,
                      'port': 0, 'socks-port': 0, 'allow-lan': False, 'log-level': 'debug', 'mode': 'rule',
                      'tun': {'enable': False, 'stack': 'gvisor', 'auto-route': True, 'auto-detect-interface': True,
                              'inet4-address': ['198.18.255.1/30'], 'route-exclude-address': ['192.0.2.0/24'], 'dns-hijack': []},
                      'dns': {'enable': True, 'listen': '127.0.0.1:' + str(dns_port), 'ipv6': False,
                              'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.19.0.1/16',
                              'use-hosts': False, 'use-system-hosts': False, 'nameserver': ['192.0.2.53']},
                      'proxy-groups': [{'name': 'GLOBAL', 'type': 'select', 'proxies': ['REJECT', 'DIRECT']}],
                      'rules': ['MATCH,DIRECT']}
            config['dns']['fake-ip-filter-mode'] = filter_mode
            config['dns']['fake-ip-filter'] = filter_entries
            path = runtime / 'config.json'
            source = json.dumps(config)
            path.write_text(source)
            path.chmod(0o600)
            mihomo = launch([str(owned), '-d', str(runtime), '-f', str(path), '-ext-ctl-unix', str(controller)], environment)
            deadline = time.monotonic() + 10
            while True:
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                try:
                    connection.request('GET', 'http://198.18.0.5:8080/')
                    response = connection.getresponse()
                    if response.status == 200 and response.read() == b'original-http' and controller.is_socket():
                        break
                except (OSError, http.client.HTTPException):
                    pass
                finally:
                    connection.close()
                assert mihomo.poll() is None and time.monotonic() < deadline, 'owned runtime traffic readiness failed'
                time.sleep(0.02)
            for protocol in ('http', 'https', 'socks'):
                for key, value in [('host', "'127.0.0.1'"), ('port', str(port))]:
                    run(['gsettings', 'set', 'org.gnome.system.proxy.' + protocol, key, value])
            run(['gsettings', 'set', 'org.gnome.system.proxy', 'use-same-proxy', 'false'])
            run(['gsettings', 'set', 'org.gnome.system.proxy', 'mode', "'manual'"])
            assert run(['gsettings', 'get', 'org.gnome.system.proxy', 'mode']) == "'manual'", 'private desktop settings did not persist'
            current_dns = subprocess.check_output(['/usr/bin/resolvectl', 'dns', original_interface], env=environment, text=True, timeout=5)
            original_dns = current_dns.strip().split(': ', 1)[1].split()
            assert original_dns, 'the private original DNS source is required'
            subprocess.run(['/usr/bin/resolvectl', 'dns', original_interface, config['dns']['listen']], env=environment, check=True, timeout=5)
            # Each filter starts independently; the application cache is populated only after this reset.
            subprocess.run(['/usr/bin/resolvectl', 'flush-caches'], env=environment, check=True, timeout=5)
            matrix_env = {**env, 'JC_NATIVE_COEXISTENCE': '1', 'JC_NATIVE_TUN_HOST': str(host),
                          'JC_NATIVE_COEXISTENCE_RUNTIME': json.dumps({'pid': mihomo.pid, 'controller': str(controller), 'port': port,
                                                                     'original_interface': original_interface,
                                                                     'fake_range': config['dns']['fake-ip-range']})}
            result = subprocess.run([str(gateway), '-test.v', '-test.timeout', '165s', '-test.run', '^TestNativeCoexistenceHost$'],
                                    env=matrix_env, capture_output=True, text=True, timeout=175, **ordinary)
            print(result.stdout, end='', flush=True)
            print(result.stderr, end='', flush=True)
            if result.returncode:
                connection = http.client.HTTPConnection('localhost', timeout=2)
                connection.sock = socket.socket(socket.AF_UNIX)
                connection.sock.settimeout(2)
                try:
                    connection.sock.connect(str(controller))
                    connection.request('GET', '/configs')
                    state = json.loads(connection.getresponse().read(1 << 20))
                    print('CHECK: owned runtime TUN ' + json.dumps(state.get('tun')), flush=True)
                finally:
                    connection.close()
            assert result.returncode == 0, 'native coexistence matrix failed'
            assert path.read_text() == source, 'coexistence changed the owned Mihomo source configuration'
            return {'cases': 12, 'filter_mode': filter_mode,
                    'entry': 'actual composed application/native helpers/private desktop/Secret Service',
                    'campus': 'actual DNS, HTTP, TCP, UDP/empty datagram, OpenSSH IP/domain',
                    'ordinary': 'actual original HTTP and SOCKS UDP/empty datagram; GLOBAL REJECT and both-off direct',
                    'initial_tun': 'second real session starts and restores with original TUN already active',
                    'live_exclusions': 'campus remains captured; ordinary native HTTP bypasses GLOBAL REJECT only while excluded; withdrawal restores Clash selection',
                    'preexisting_cache': 'actual Qt application DNS cache prewarmed from the real original Fake-IP resolver before connection',
                    'protected': 'actual original network HTTP survives GLOBAL REJECT', 'source_configuration': 'unchanged'}
        finally:
            if original_dns is not None:
                subprocess.run(['/usr/bin/resolvectl', 'dns', original_interface, *original_dns], env=environment, check=True, timeout=5)
            # Keep the private keyring/settings alive until detached EOF restoration finishes.
            deadline = time.monotonic() + 5
            while True:
                workers = []
                for entry in Path('/proc').iterdir():
                    if not entry.name.isdecimal():
                        continue
                    try:
                        if (entry / 'exe').resolve() != host.parent / 'JustConnectProxyRecovery' or entry.stat().st_uid != uid:
                            continue
                        if ('XDG_CONFIG_HOME=' + env['XDG_CONFIG_HOME']).encode() not in (entry / 'environ').read_bytes().split(b'\0'):
                            continue
                        workers.append(int(entry.name))
                    except (OSError, RuntimeError):
                        continue
                if not workers:
                    break
                if time.monotonic() >= deadline:
                    for pid in workers:
                        try:
                            descriptor = os.pidfd_open(pid)
                        except ProcessLookupError:
                            continue
                        try:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        finally:
                            os.close(descriptor)
                    print('Stopped only owned private-desktop recovery workers after their cleanup budget.', flush=True)
                    break
                time.sleep(0.02)
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for log in logs:
                log.close()
            for path in sorted(root.glob('process-*.log')):
                print(path.name + ':\n' + path.read_text(errors='replace')[-8000:], flush=True)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mihomo', type=Path, required=True)
    parser.add_argument('--gateway', type=Path, required=True)
    parser.add_argument('--host', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.uid != 0
    for kind in ('net', 'mnt'):
        assert os.stat('/proc/thread-self/ns/' + kind) != os.stat('/proc/1/ns/' + kind), 'refusing host namespaces'
    subprocess.run(['mount', '--make-rprivate', '/'], check=True, timeout=5)
    # Isolate the production per-UID proxy lock as well as its desktop settings.
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', '/tmp'], check=True, timeout=5)
    reports = {}
    for mode, entries in [('blacklist', []), ('whitelist', ['+.campus.test']),
                          ('rule', ['DOMAIN-SUFFIX,campus.test,fake-ip', 'MATCH,real-ip'])]:
        print('CHECK: actual preexisting Fake-IP cache with filter ' + mode, flush=True)
        reports[mode] = matrix(args.mihomo.resolve(strict=True), args.gateway.resolve(strict=True),
                               args.host.resolve(strict=True), args.uid, os.environ, mode, entries)
    report = {'cases': sum(item['cases'] for item in reports.values()), 'filters': reports}
    print('COEXISTENCE REPORT: ' + json.dumps(report, sort_keys=True), flush=True)
