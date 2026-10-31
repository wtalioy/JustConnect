"""Own a native proxy runtime for the disposable macOS application matrix."""

import ipaddress
import ctypes
import json
import os
import plistlib
from pathlib import Path
import re
import socket
import subprocess
import time

from mihomo_tun_native import finish_runtime, request


class MacProxyScope:
    """Keep a root-owned in-memory backup of only this runner's proxy fields."""
    def __init__(self):
        assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
        self.cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sc = ctypes.CDLL('/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration')

        def bind(library, name, result, *arguments):
            function = getattr(library, name)
            function.restype, function.argtypes = result, list(arguments)
            return function

        pointer, integer = ctypes.c_void_p, ctypes.c_long
        self.release = bind(self.cf, 'CFRelease', None, pointer)
        self.string = bind(self.cf, 'CFStringCreateWithCString', pointer, pointer, ctypes.c_char_p, ctypes.c_uint32)
        self.data = bind(self.cf, 'CFDataCreate', pointer, pointer, ctypes.c_char_p, integer)
        self.decode = bind(self.cf, 'CFPropertyListCreateWithData', pointer, pointer, pointer, ctypes.c_ulong, pointer, pointer)
        self.encode = bind(self.cf, 'CFPropertyListCreateData', pointer, pointer, pointer, integer, ctypes.c_ulong, pointer)
        self.length = bind(self.cf, 'CFDataGetLength', integer, pointer)
        self.bytes = bind(self.cf, 'CFDataGetBytePtr', pointer, pointer)
        self.create = bind(self.sc, 'SCPreferencesCreate', pointer, pointer, pointer, pointer)
        self.get = bind(self.sc, 'SCPreferencesGetValue', pointer, pointer, pointer)
        self.set = bind(self.sc, 'SCPreferencesPathSetValue', ctypes.c_bool, pointer, pointer, pointer)
        self.remove = bind(self.sc, 'SCPreferencesPathRemoveValue', ctypes.c_bool, pointer, pointer)
        self.commit = bind(self.sc, 'SCPreferencesCommitChanges', ctypes.c_bool, pointer)
        self.apply = bind(self.sc, 'SCPreferencesApplyChanges', ctypes.c_bool, pointer)
        self.synchronize = bind(self.sc, 'SCPreferencesSynchronize', None, pointer)
        name = self.text('JustConnect disposable proxy scope')
        self.preferences = self.create(None, name, None)
        self.release(name)
        assert self.preferences, 'open actual runner proxy preferences'
        self.before = self.snapshot()

    def text(self, value):
        return self.string(None, value.encode(), 0x08000100)  # kCFStringEncodingUTF8.

    def snapshot(self):
        self.synchronize(self.preferences)
        key = self.text('NetworkServices')
        value = self.get(self.preferences, key)
        self.release(key)
        assert value, 'actual network services are present'
        data = self.encode(None, value, 200, 0, None)  # kCFPropertyListBinaryFormat_v1_0.
        assert data
        try:
            services = plistlib.loads(ctypes.string_at(self.bytes(data), self.length(data)))
            return {key: value.get('Proxies') for key, value in services.items()}
        finally:
            self.release(data)

    def close(self):
        try:
            self.synchronize(self.preferences)
            current = self.snapshot()
            for identifier, proxies in self.before.items():
                path = self.text('/NetworkServices/' + identifier + '/Proxies')
                try:
                    if proxies is None:
                        # Removal is necessary only when the fixture added a dictionary.
                        assert current.get(identifier) is None or self.remove(self.preferences, path)
                    else:
                        encoded = plistlib.dumps(proxies)
                        data = self.data(None, encoded, len(encoded))
                        value = self.decode(None, data, 0, None, None)
                        try:
                            assert value and self.set(self.preferences, path, value)
                        finally:
                            if value:
                                self.release(value)
                            self.release(data)
                finally:
                    self.release(path)
            assert self.commit(self.preferences) and self.apply(self.preferences), 'restore actual original proxy preferences'
            assert self.snapshot() == self.before, 'root cleanup left actual runner proxy fields changed'
        finally:
            self.release(self.preferences)


class MacCoexistenceRuntime:
    def __init__(self, binary, directory):
        assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
        directory.mkdir(mode=0o755)
        self.path = directory / 'config.json'
        self.log = (directory / 'runtime.log').open('w+', encoding='utf-8')
        self.process = None
        output = subprocess.check_output(['/usr/sbin/scutil', '--dns'], text=True, timeout=5)
        servers = list(dict.fromkeys(re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', output)))
        servers = [value for value in servers if ipaddress.ip_address(value).version == 4
                   and not ipaddress.ip_address(value).is_loopback]
        assert servers, 'matrix requires the actual original IPv4 DNS sources'
        address = next(row[4][0] for row in socket.getaddrinfo('github.com', 80, socket.AF_INET, socket.SOCK_STREAM)
                       if ipaddress.ip_address(row[4][0]).is_global)
        route = subprocess.check_output(['/sbin/route', '-n', 'get', '-inet', address], text=True, timeout=5)
        interface = re.search(r'^\s*interface:\s*(\S+)\s*$', route, re.MULTILINE).group(1)
        interfaces = subprocess.check_output(['/sbin/ifconfig', '-l'], text=True, timeout=5).split()
        # Leave the next allocator slot for JustConnect's real helper.
        device = 'utun' + str(max([int(name[4:]) for name in interfaces if re.fullmatch(r'utun\d+', name)] + [-1]) + 2)

        def port():
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0))
                return reserve.getsockname()[1]

        mixed, controller = port(), port()
        self.config = {'external-controller': '127.0.0.1:' + str(controller), 'secret': os.urandom(32).hex(),
                       'external-controller-unix': str(directory / 'controller.sock'),
                       'mixed-port': mixed, 'port': 0, 'socks-port': 0, 'allow-lan': False, 'mode': 'rule',
                       'tun': {'enable': False, 'device': device, 'stack': 'gvisor', 'auto-route': True,
                               'auto-detect-interface': True, 'dns-hijack': []},
                       'dns': {'enable': True, 'ipv6': False, 'enhanced-mode': 'fake-ip',
                               'fake-ip-range': '198.19.0.1/16', 'nameserver': servers},
                       'proxy-groups': [{'name': 'GLOBAL', 'type': 'select', 'proxies': ['REJECT', 'DIRECT']}],
                       'rules': ['MATCH,DIRECT']}
        self.source = json.dumps(self.config)
        self.path.write_text(self.source)
        self.path.chmod(0o600)
        self.facts = {'controller': self.config['external-controller-unix'], 'port': mixed,
                      'original_interface': interface, 'ordinary_address': address,
                      'tun_device': device,
                      'ordinary_url': 'http://github.com/robots.txt'}
        try:
            self.process = subprocess.Popen([str(binary), '-d', str(directory), '-f', str(self.path)],
                                            stdout=self.log, stderr=subprocess.STDOUT)
            self.facts['pid'] = self.process.pid
            deadline = time.monotonic() + 10
            while True:
                assert self.process.poll() is None, 'owned runtime exited during startup'
                try:
                    state = request(self.config)
                except OSError:
                    state = None
                if state and Path(self.facts['controller']).is_socket():
                    break
                assert time.monotonic() < deadline, 'owned native controller startup deadline'
                time.sleep(.02)
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if self.process is not None:
                finish_runtime(self.process, self.config)
            assert self.path.read_text() == self.source, 'application changed original proxy source configuration'
        finally:
            self.log.flush()
            print(self.path.with_name('runtime.log').read_text(errors='replace')[-12000:], flush=True)
            self.log.close()
