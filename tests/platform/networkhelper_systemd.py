"""Real system-manager recovery, restricted to the install probe's private mounts/netns."""

import os
from pathlib import Path
import shlex
import subprocess
import time
import uuid


class RecoveryTimer:
    def __init__(self, layout, service, timer, root, state, development_libraries=()):
        assert os.geteuid() == 0
        for kind in ('net', 'mnt'):
            assert os.stat(f'/proc/thread-self/ns/{kind}') != os.stat(f'/proc/1/ns/{kind}'), 'refusing host namespaces'
        self.layout, self.service, self.timer = layout, service, timer
        self.root, self.state = root, state
        self.development_libraries = development_libraries
        self.name = layout['recovery_unit']
        self.owner = 'JustConnect isolated recovery ' + str(uuid.uuid4())
        self.environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'}
        self.created = False
        for kind in ('timer', 'service'):
            assert self.property(kind, 'LoadState') == 'not-found', 'refusing to replace an existing recovery unit'

    def command(self, *arguments, check=True):
        return subprocess.run(list(arguments), env=self.environment, text=True, capture_output=True, timeout=30, check=check)

    def property(self, kind, name):
        result = self.command(self.layout['systemctl_program'], 'show', '--value', '--property=' + name,
                              self.name + '.' + kind, check=False)
        return result.stdout.strip()

    def start(self, deferred=False, namespace_process=None):
        command = ['systemd-run', '--collect', '--unit=' + self.name, '--description=' + self.owner]
        # The probe's private bind supplies writable state; PID 1 must never create production directories on the host.
        scoped = {'ExecStart', 'StateDirectory', 'StateDirectoryMode'}
        command += ['--property=' + key + '=' + value for key, value in self.service['Service'].items() if key not in scoped]
        process = os.getpid()
        # PID 1 starts the real installed helper with exactly this probe's files, storage and network.
        command += [f'--property=NetworkNamespacePath=/proc/{namespace_process or process}/ns/net',
                    f'--property=RootDirectory={self.root}', f'--property=BindPaths={self.state}:/var/lib',
                    '--property=MemoryPressureWatch=no']
        libraries = [path for path in ('/usr/bin', '/usr/sbin', '/usr/lib', '/usr/lib64', '/proc')
                     if Path(path).is_dir() and not Path(path).is_symlink()]
        command += ['--property=BindReadOnlyPaths=' + ' '.join(path + ':' + path for path in libraries)]
        if self.development_libraries:
            command += ['--property=Environment=LD_LIBRARY_PATH=/usr/local/lib']
        schedule = self.timer['Timer']
        # Manual fault cases retain their original assertions; production timing is exercised separately.
        command += ['--on-active=' + ('1h' if deferred else schedule['OnActiveSec']),
                    '--on-unit-inactive=' + ('1h' if deferred else schedule['OnUnitInactiveSec']),
                    '--timer-property=AccuracySec=' + schedule['AccuracySec']]
        command += shlex.split(self.service['Service']['ExecStart'])
        try:
            self.command(*command)
            self.created = True
            assert self.property('timer', 'ActiveState') == 'active'
            assert self.property('service', 'Slice') == 'system.slice'
        except BaseException:
            self.stop()
            raise

    def invocation_summary(self):
        invocation = self.property('service', 'InvocationID')
        if not invocation or self.property('service', 'ActiveState') == 'activating':
            return None
        if self.property('service', 'Result') not in ('success', ''):
            diagnostics = self.command('journalctl', '--no-pager', '--output=cat', '-u', self.name + '.service', '-n', '8')
            raise AssertionError(diagnostics.stdout)
        result = self.command('journalctl', '--no-pager', '--output=cat', '_SYSTEMD_INVOCATION_ID=' + invocation)
        import json
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"')]
        rows = [row for row in rows if row.get('worker') == 'network-recovery']
        return rows[-1] if rows else None

    def stop(self):
        if self.property('service', 'Description') != self.owner:
            assert not self.created, 'owned recovery unit was replaced during the test'
            return
        self.command(self.layout['systemctl_program'], 'stop', self.name + '.timer', self.name + '.service')
        self.command(self.layout['systemctl_program'], 'reset-failed', self.name + '.timer', self.name + '.service', check=False)
        deadline = time.monotonic() + 10
        while any(self.property(kind, 'LoadState') != 'not-found' for kind in ('timer', 'service')) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert all(self.property(kind, 'LoadState') == 'not-found' for kind in ('timer', 'service')), 'temporary recovery units did not unload'
        self.created = False
