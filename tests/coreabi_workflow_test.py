"""Check that collecting ABI evidence never hides an earlier Go failure."""
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
lines = (ROOT / '.github/workflows/coreabi.yml').read_text(encoding='utf-8').splitlines()
for index, line in enumerate(lines):
    if line.strip() != 'shell: python':
        continue
    end = index + 2
    while end < len(lines) and (not lines[end].strip() or lines[end].startswith('          ')):
        end += 1
    body = textwrap.dedent('\n'.join(lines[index + 2:end]))
    if 'race_status = shutdown_status' in body:
        break
else:
    raise AssertionError('Formal ABI workflow body not found')


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
