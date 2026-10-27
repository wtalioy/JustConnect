"""Stage a pinned, test-only Mihomo runtime; never install or start a service."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024


def unpack(data, asset):
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != asset['sha256']:
        raise ValueError('Mihomo test archive does not match its pinned source')
    if asset['file'].endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = [e for e in archive.infolist() if not e.is_dir() and e.filename.endswith('.exe')]
            if len(entries) != 1 or entries[0].file_size > MAX_BINARY:
                raise ValueError('Unexpected Mihomo executable archive')
            binary = archive.read(entries[0])
    else:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as archive:
            binary = archive.read(MAX_BINARY + 1)
    if not binary or len(binary) > MAX_BINARY:
        raise ValueError('Unexpected Mihomo executable size')
    return binary


def main():
    lock = json.loads((Path(__file__).with_name('mihomo-runtime.json')).read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, choices=lock['assets'])
    args = parser.parse_args()
    asset = lock['assets'][args.target]
    url = f"https://github.com/MetaCubeX/mihomo/releases/download/{lock['version']}/{asset['file']}"
    with urllib.request.urlopen(url, timeout=45) as response:
        binary = unpack(response.read(MAX_ARCHIVE + 1), asset)
    destination = ROOT / 'build/tools/test-mihomo' / args.target
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / ('mihomo.exe' if args.target.startswith('windows-') else 'mihomo')
    path.write_bytes(binary)
    path.chmod(0o700)
    (destination / 'source.json').write_text(json.dumps(dict(asset, version=lock['version'], url=url), indent=2) + '\n')
    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as environment:
        environment.write(f'JC_TEST_MIHOMO_BINARY={path}\n')
    print(f"Staged pinned Mihomo {lock['version']} for {args.target}")


if __name__ == '__main__':
    main()
