"""Stage the reviewed versioned native Linux packaging tools, checking all cached/downloaded bytes."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
import urllib.request

CONTRACT = Path(__file__).with_name('linuxdeploy.json')


def stage(contract, destination, arch):
    if any(arch not in tool['sha256'] for tool in contract.values()):
        raise ValueError('Unsupported AppImage architecture')
    for name, tool in contract.items():
        path = Path(destination) / name
        version = tool['version']
        url = f'https://github.com/linuxdeploy/{name}/releases/download/{version}/{name}-{arch}.AppImage'
        cached = path.exists()
        if cached:
            contents = path.read_bytes()
        else:
            with urllib.request.urlopen(url, timeout=60) as response:
                contents = response.read()
        if hashlib.sha256(contents).hexdigest() != tool['sha256'][arch]:
            raise ValueError(f'{name}: SHA-256 mismatch; review the pinned source before changing linuxdeploy.json')
        if not cached:
            path.write_bytes(contents)
        print(f'Verified {name} {version} ({arch})')


def strip_elfs(root):
    for path in Path(root).rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as stream:
            elf = stream.read(4) == b'\x7fELF'
        if elf:
            subprocess.run(['strip', '--strip-unneeded', str(path)], check=True)


if __name__ == '__main__':
    contract = json.loads(CONTRACT.read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', choices=sorted(set.intersection(*(set(tool['sha256']) for tool in contract.values()))))
    args = parser.parse_args()
    stage(contract, Path.cwd(), args.arch)
