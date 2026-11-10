"""Exercise the ABI workflow’s failure and evidence handling."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
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


spec = importlib.util.spec_from_file_location('run_coreabi', ROOT / 'tests/platform/run_coreabi.py')
runner_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner_script)


def scenario(failures, arch='ARM64', runner='macOS'):
    calls = []

    class Process:
        def __init__(self, args, **options):
            if len(args) > 1 and args[1] == 'tests/platform/mihomo_api_probe.py':
                name = 'mihomo-api'
            elif args[0] == 'go' and 'test' in args:
                name = 'regressions' if '-count' in args else 'race' if '-race' in args else 'normal'
            elif len(args) > 1 and args[1] == 'tests/platform/run_ctest.py':
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
            with patch.dict(os.environ, CC='fixture-cc', RUNNER_OS=runner, RUNNER_ARCH=arch,
                            JC_TEST_MIHOMO_BINARY='fixture-mihomo'), \
                    patch.object(subprocess, 'Popen', Process), patch.object(sys, 'stdout', output):
                try:
                    runner_script.main()
                except SystemExit as result:
                    status = result.code
                else:
                    raise AssertionError('Workflow did not propagate its final result')
        finally:
            os.chdir(previous)
    return status, calls


class CoreAbiWorkflowTest(unittest.TestCase):
    def test_race_failure_still_collects_host_evidence(self):
        for failure in ({}, {'race': 7}, {'regressions': 8}, {'race': 7, 'regressions': 8}):
            with self.subTest(failure=failure):
                status, calls = scenario(failure)
                self.assertEqual(status, failure.get('race') or failure.get('regressions') or 0)
                self.assertEqual(calls[-1], 'host')
                self.assertLess(calls.index('race'), calls.index('regressions'))
                self.assertLess(calls.index('regressions'), calls.index('configure'))

    def test_required_failure_stops_before_unusable_host(self):
        for failed in ('mihomo-api', 'normal', 'configure', 'build', 'host'):
            with self.subTest(failed=failed):
                status, calls = scenario({failed: 9})
                self.assertEqual(status, 9)
                self.assertEqual(calls[-1], failed)

    def test_windows_arm64_still_runs_host_without_race_support(self):
        status, calls = scenario({}, runner='Windows')
        self.assertEqual(status, 0)
        self.assertEqual(calls[-1], 'host')
        self.assertNotIn('race', calls)
        self.assertNotIn('regressions', calls)

    def test_device_failure_stays_required_without_hiding_independent_evidence(self):
        probe = lines.index('      - name: Probe Windows device broker in the disposable runner')
        end = next(i for i in range(probe + 1, len(lines)) if lines[i].startswith('      - '))
        self.assertNotIn('continue-on-error: true', [line.strip() for line in lines[probe:end]])
        formal = lines.index('      - name: Verify formal C ABI, protocol session and authentication')
        live = lines.index('      - name: Verify control beneath a live rejecting Mihomo TUN')
        enforce = lines.index('      - name: Enforce required Windows device result')
        self.assertTrue(probe < formal < live < enforce, 'The live TUN must run after the native checks')
        condition = next(line.split('${{', 1)[1].rsplit('}}', 1)[0] for line in lines if 'if: &collect_native_evidence ' in line)
        condition = condition.replace('&&', ' and ').replace('||', ' or ').replace('!cancelled()', 'not cancelled()').strip()
        for runner, success, outcome, cancelled, expected in (
                ('Windows', False, 'failure', False, True),
                ('Windows', True, 'success', False, True),
                ('Windows', False, 'skipped', False, False),
                ('Windows', False, 'cancelled', True, False),
                ('Windows', False, 'failure', True, False),
                ('macOS', True, 'skipped', False, True),
                ('macOS', False, 'skipped', False, False),
                ('macOS', False, 'cancelled', True, False)):
            with self.subTest(runner=runner, success=success, outcome=outcome, cancelled=cancelled):
                actual = eval(condition, {'__builtins__': {}}, {
                    'runner': SimpleNamespace(os=runner),
                    'steps': SimpleNamespace(windows_device_probe=SimpleNamespace(outcome=outcome)),
                    'success': lambda: success, 'cancelled': lambda: cancelled,
                })
                self.assertEqual(actual, expected)

    def test_live_tun_step_stops_at_failure_and_retains_evidence(self):
        body = workflow_body('https://github.com/robots.txt')
        script = compile(body, str(ROOT / '.github/workflows/coreabi.yml'), 'exec')
        previous = Path.cwd()
        for failure in (None, 0, 1, 2):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, \
                    io.TextIOWrapper(io.BytesIO(), encoding='utf-8') as output:
                calls = []

                def run_live(command, **options):
                    self.assertTrue(options['check'])
                    self.assertEqual(options['timeout'], 115)
                    options['stdout'].write(b'owned live TUN evidence\n')
                    calls.append(command)
                    if failure == len(calls) - 1:
                        raise subprocess.CalledProcessError(17, command)

                try:
                    os.chdir(directory)
                    with patch.dict(os.environ, JC_TEST_MIHOMO_BINARY='owned-test-runtime'), \
                            patch.object(subprocess, 'run', run_live), patch.object(sys, 'stdout', output):
                        if failure is None:
                            exec(script, {})
                        else:
                            with self.assertRaises(subprocess.CalledProcessError) as error:
                                exec(script, {})
                            self.assertEqual(error.exception.returncode, 17)
                    self.assertEqual(len(calls), 3 if failure is None else failure + 1)
                    self.assertEqual((Path('build/controller-checks') / 'live-tun.log').read_bytes(),
                                     b'owned live TUN evidence\n' * len(calls))
                finally:
                    os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
