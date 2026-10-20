"""Export the clean repository commit, including the maintained core and build scripts."""

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()


def archive(output):
    if git('status', '--porcelain'):
        raise RuntimeError('Source export requires a clean tree matching the compiled commit')
    revision = git('rev-parse', 'HEAD')
    prefix = f'JustConnect-{revision}/'
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'source.tar'
        git('archive', '--format=tar', f'--prefix={prefix}', '-o', str(path), 'HEAD')
        with tarfile.open(path, 'a') as bundle:
            contents = (revision + '\n').encode()
            entry = tarfile.TarInfo(prefix + 'source-revision.txt')
            entry.size, entry.mode = len(contents), 0o644
            entry.mtime = int(git('show', '-s', '--format=%ct', 'HEAD'))
            bundle.addfile(entry, io.BytesIO(contents))
        with path.open('rb') as source, output.open('wb') as destination:
            with gzip.GzipFile(filename='', mode='wb', fileobj=destination, mtime=0) as compressed:
                shutil.copyfileobj(source, compressed)
    with output.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    output.with_name(output.name + '.sha256').write_text(f'{digest}  {output.name}\n', encoding='utf-8')
    print(f'PASS: source for {revision}: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    archive(parser.parse_args().output)
