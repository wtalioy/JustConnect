"""Check that collecting ABI evidence never hides an earlier Go failure."""
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
lines = (ROOT / '.github/workflows/coreabi.yml').read_text(encoding='utf-8').splitlines()
def workflow_body(marker):
    for index, line in enumerate(lines):
        if line.strip() != 'shell: python':
            continue
        end = index + 2
        while end < len(lines) and (not lines[end].strip() or lines[end].startswith('          ')):
            end += 1
        body = textwrap.dedent('\n'.join(lines[index + 2:end]))
        if marker in body:
            return body
    raise AssertionError('Workflow Python body not found: ' + marker)


body = workflow_body('race_status = shutdown_status')

def scenario(failures, arch='ARM64', runner='macOS'):
    calls = []

    class Process:
        def __init__(self, args, **options):
            if args[0] == 'go' and 'test' in args:
                name = 'shutdown' if '-count' in args else 'race' if '-race' in args else 'normal'
            elif args[0] == 'ctest':
                name = 'host'
            elif args[:2] == ['cmake', '--build']:
                name = 'build'
            elif args[:2] == ['cmake', '-S']:
                name = 'configure'
            else:
                name = args[0]
            calls.append(name)
            self.code = failures.get(name, 0)
            self.stdout = io.BytesIO(b'bounded command output\n')

        def __enter__(self):
            return self

        def __exit__(self, *ignored):
            self.stdout.close()

        def wait(self):
            return self.code

    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as directory, io.TextIOWrapper(io.BytesIO(), encoding='utf-8') as output:
        try:
            os.chdir(directory)
            with patch.dict(os.environ, CC='fixture-cc', RUNNER_OS=runner, RUNNER_ARCH=arch), \
                    patch.object(subprocess, 'Popen', Process), patch.object(sys, 'stdout', output):
                try:
                    exec(compile(body, str(ROOT / '.github/workflows/coreabi.yml'), 'exec'), {})
                except SystemExit as result:
                    status = result.code
                else:
                    raise AssertionError('Workflow did not propagate its final result')
        finally:
            os.chdir(previous)
    return status, calls


for failure in ({}, {'race': 7}, {'shutdown': 8}, {'race': 7, 'shutdown': 8}):
    status, calls = scenario(failure)
    assert status == (failure.get('race') or failure.get('shutdown') or 0), (failure, status)
    assert calls[-1] == 'host' and calls.index('race') < calls.index('shutdown') < calls.index('configure'), calls
for failed in ('normal', 'configure', 'build'):
    status, calls = scenario({failed: 9})
    assert status == 9 and 'host' not in calls, (failed, status, calls)
status, calls = scenario({}, runner='Windows')
assert status == 0 and calls[-1] == 'host' and 'race' not in calls and 'shutdown' not in calls, calls
print('PASS: 8 workflow outcomes; race failures collect ABI evidence and remain failures')

# GitHub's continue-on-error changes the displayed conclusion; retain the actual device failure.
probe = lines.index('      - &windows_device_probe')
end = next(i for i in range(probe+1,len(lines)) if lines[i].startswith('      - '))
assert not any(line.strip() == 'continue-on-error: true' for line in lines[probe:end]), 'Device failure would be displayed as success'
condition = next(line.split('${{',1)[1].rsplit('}}',1)[0] for line in lines if 'if: &collect_native_evidence ' in line)
condition = condition.replace('&&',' and ').replace('||',' or ').replace('!cancelled()','not cancelled()').strip()
for runner, previous_success, outcome, cancelled, expected in (
        ('Windows',False,'failure',False,True),
        ('Windows',True,'success',False,True),
        ('Windows',False,'skipped',False,False),
        ('Windows',False,'cancelled',True,False),
        ('Windows',False,'failure',True,False),
        ('macOS',True,'skipped',False,True),
        ('macOS',False,'skipped',False,False),
        ('Linux',False,'skipped',False,False)):
    actual=eval(condition,{'__builtins__':{}},{
        'runner':SimpleNamespace(os=runner),
        'steps':SimpleNamespace(windows_device_probe=SimpleNamespace(outcome=outcome)),
        'success':lambda:previous_success,'cancelled':lambda:cancelled})
    assert actual == expected,(runner,previous_success,outcome,cancelled,actual)
assert '        if: *collect_native_evidence' in lines,'Packet-only checks lost independent evidence collection'
print('PASS: device failures stay visible; 8 native evidence/cancellation conditions')


controller_body = workflow_body('build/controller-checks')

def controller_scenario(runner, arch, failure):
    calls = []
    def run(command, **options):
        kind = 'race' if '-race' in command else 'normal'
        assert './underlay' in command and './internal/mihomo/...' in command, command
        calls.append(kind)
        options['stdout'].write(b'native controller evidence\n')
        return SimpleNamespace(returncode=17 if kind == failure else 0)
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as directory, io.TextIOWrapper(io.BytesIO(), encoding='utf-8') as output:
        try:
            os.chdir(directory)
            with patch.dict(os.environ, RUNNER_OS=runner, RUNNER_ARCH=arch), \
                    patch.object(subprocess, 'run', run), patch.object(sys, 'stdout', output):
                try:
                    exec(compile(controller_body, str(ROOT / '.github/workflows/coreabi.yml'), 'exec'), {})
                    status = 0
                except SystemExit as result:
                    status = result.code
            assert (Path('build/controller-checks') / (calls[-1] + '.log')).read_bytes() == b'native controller evidence\n'
        finally:
            os.chdir(previous)
    return status, calls

for runner, arch in [('Windows', 'ARM64'), ('Windows', 'X64'), ('macOS', 'ARM64'), ('Linux', 'ARM64')]:
    status, calls = controller_scenario(runner, arch, None)
    expected = ['normal'] if (runner, arch) == ('Windows', 'ARM64') else ['normal', 'race']
    assert status == 0 and calls == expected, (runner, arch, status, calls)
for failure in ['normal', 'race']:
    status, calls = controller_scenario('Windows', 'X64', failure)
    assert status == 17 and calls[-1] == failure, (failure, status, calls)
print('PASS: 6 native controller race-support/failure-propagation cases with actual evidence files')

live_body = workflow_body('https://github.com/robots.txt')
for failure in (None, 0, 1, 2):
    calls = []

    def run_live(command, **options):
        assert options['check'] and options['timeout'] == 115
        options['stdout'].write(b'owned live TUN evidence\n')
        calls.append(command)
        if failure == len(calls) - 1:
            raise subprocess.CalledProcessError(17, command)
        return SimpleNamespace(returncode=0)

    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as directory, io.TextIOWrapper(io.BytesIO(), encoding='utf-8') as output:
        try:
            os.chdir(directory)
            with patch.dict(os.environ, JC_TEST_MIHOMO_BINARY='owned-test-runtime'), \
                    patch.object(subprocess, 'run', run_live), patch.object(sys, 'stdout', output):
                try:
                    exec(compile(live_body, str(ROOT / '.github/workflows/coreabi.yml'), 'exec'), {})
                except subprocess.CalledProcessError as result:
                    assert failure is not None and result.returncode == 17
                else:
                    assert failure is None
            assert len(calls) == (3 if failure is None else failure + 1)
            assert (Path('build/controller-checks') / 'live-tun.log').read_bytes() == b'owned live TUN evidence\n' * len(calls)
        finally:
            os.chdir(previous)
print('PASS: 4 live TUN workflow outcomes preserve build/test/runtime failures and their evidence')
