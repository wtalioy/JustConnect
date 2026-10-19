"""Build the pinned third-party core with its recorded patch set."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'core/manifest.json'


def sha256(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def check_hash(path, expected):
    if sha256(path) != expected:
        raise RuntimeError(f'SHA-256 mismatch: {path.name}')


def prepare_source(archive, manifest, destination, manifest_dir):
    check_hash(archive, manifest['source_sha256'])
    with tarfile.open(archive) as source:
        source.extractall(destination, filter='data')
    root = destination / f"zju-connect-{manifest['commit']}"
    check_hash(root / 'LICENSE', manifest['license_sha256'])
    for patch in manifest['patches']:
        path = (manifest_dir / patch['file']).resolve()
        if not path.is_relative_to(manifest_dir.resolve()):
            raise RuntimeError('Patch path must stay within core/')
        check_hash(path, patch['sha256'])
        subprocess.run(['git', 'apply', '--check', str(path)], cwd=root, check=True)
        subprocess.run(['git', 'apply', str(path)], cwd=root, check=True)
    check_hash(root / 'go.sum', manifest['go_sum_sha256'])
    return root


def build(output):
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('ZJU_CONNECT_')}
    env.update(CGO_ENABLED='0', GOTOOLCHAIN='local', GOWORK='off', GOENV='off',
               GOFLAGS='-mod=readonly', GOAMD64='v1', GOARM64='v8.0', GOEXPERIMENT='')
    version = subprocess.check_output(['go', 'version'], env=env, text=True).split()[2]
    if version != f"go{manifest['go_version']}":
        raise RuntimeError(f"Required Go {manifest['go_version']}; found {version}")
    host = subprocess.check_output(['go', 'env', 'GOHOSTOS', 'GOHOSTARCH'],
                                   env=env, text=True).split()
    env.update(GOOS=host[0], GOARCH=host[1])
    binary = 'zju-connect.exe' if host[0] == 'windows' else 'zju-connect'
    flags = ['-trimpath', '-buildvcs=false', '-ldflags',
             '-s -w -buildid= -X main.zjuConnectVersion=v0.0.0-justconnect '
             f"-X main.CommitID={manifest['commit']}"]
    with tempfile.TemporaryDirectory(prefix='justconnect-core-') as directory:
        temporary = Path(directory)
        archive = temporary / 'source.tar.gz'
        with urlopen(manifest['source_url'], timeout=60) as response, archive.open('wb') as target:
            shutil.copyfileobj(response, target)
        source = prepare_source(archive, manifest, temporary, MANIFEST.parent)
        for command in (['go', 'mod', 'download'], ['go', 'mod', 'verify'],
                        ['go', 'build', *flags, '-o', str(temporary / binary), '.']):
            subprocess.run(command, cwd=source, env=env, check=True)
        check_hash(source / 'go.sum', manifest['go_sum_sha256'])
        core_version = subprocess.check_output([str(temporary / binary), '-version'],
                                              cwd=temporary, env=env, text=True).strip()
        expected = f"ZJU Connect v0.0.0-justconnect-{manifest['commit']}"
        if core_version != expected:
            raise RuntimeError(f'Unexpected core version: {core_version}')
        output.mkdir(parents=True, exist_ok=True)
        shutil.copy2(temporary / binary, output / binary)
        provenance = output / 'core-provenance'
        if provenance.exists():
            shutil.rmtree(provenance)
        provenance.mkdir()
        shutil.copy2(archive, provenance / 'source.tar.gz')
        shutil.copy2(source / 'LICENSE', provenance / 'LICENSE.zju-connect')
        shutil.copy2(MANIFEST, provenance / 'manifest.json')
        for patch in manifest['patches']:
            path = MANIFEST.parent / patch['file']
            target = provenance / patch['file']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        record = dict(version=core_version, go_version=version, goos=host[0], goarch=host[1],
                      build_flags=flags, manifest_sha256=sha256(MANIFEST),
                      unsigned_binary_sha256=sha256(output / binary))
        (provenance / 'build.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
        print(f'{core_version}\nBuilt {host[0]}/{host[1]}: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/core')
    build(parser.parse_args().output.resolve())
