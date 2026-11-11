"""Verify the integrated Go module and its complete offline test suite."""

import json
import os
from pathlib import Path
import subprocess
import sys


CORE = Path(__file__).resolve().parents[1] / 'corelib'
ENV = dict(os.environ, CGO_ENABLED='1', GOEXPERIMENT='cgocheck2', GOTOOLCHAIN='local', GOWORK='off',
           GOENV='off', GOFLAGS='-mod=readonly')


def go(*args, capture=False):
    return subprocess.run(['go', *args], cwd=CORE, env=ENV, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def main():
    metadata = json.loads(go('mod', 'edit', '-json', capture=True))
    module = metadata['Module']['Path']
    if module != 'github.com/wtalioy/JustConnect/corelib':
        raise RuntimeError('Expected the single JustConnect Go module')
    version = go('version', capture=True).split()[2]
    if version != 'go' + metadata['Go']:
        raise RuntimeError(f"Required Go {metadata['Go']}; found {version}")
    if list(CORE.rglob('go.mod')) != [CORE / 'go.mod'] or any(
            not entry['New'].get('Version') for entry in metadata.get('Replace') or []):
        raise RuntimeError('The core must not contain nested modules or local replacements')
    subprocess.run([sys.executable, str(CORE.parent / "scripts/generate-core-abi.py"), "--check"], check=True)
    locks = {name: (CORE / name).read_bytes() for name in ('go.mod', 'go.sum')}
    unformatted = subprocess.check_output(['gofmt', '-l', *map(str, CORE.rglob('*.go'))], text=True)
    if unformatted.strip():
        raise RuntimeError('Run gofmt on:\n' + unformatted)
    go('mod', 'download')
    go('mod', 'verify')
    modules = go('list', '-m', '-f', '{{.Path}}', 'all', capture=True).splitlines()
    if 'github.com/mythologyli/zju-connect' in modules:
        raise RuntimeError('Integrated sources must not depend on the remote upstream module')
    go('vet', './...')
    go('build', './...')

    packages = go('list', './...', capture=True).splitlines()
    go('test', '-timeout', '90s', *packages)
    for name, before in locks.items():
        if (CORE / name).read_bytes() != before:
            raise RuntimeError(f'Go verification modified the lock file: {name}')
    print(f'PASS: {version}, integrated module build, {len(packages)} package test suites', flush=True)


if __name__ == '__main__':
    main()
