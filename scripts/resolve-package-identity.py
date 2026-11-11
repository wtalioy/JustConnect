"""Resolve a package version and validate a release tag before any native build."""

from datetime import date
import os
from pathlib import Path
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def main():
    env = os.environ
    ref, revision = env['GITHUB_REF'], env['GITHUB_SHA']
    tagged = env['GITHUB_REF_TYPE'] == 'tag'
    version = ref.removeprefix('refs/tags/') if tagged else env.get('RELEASE_VERSION', '')
    release_date = env.get('RELEASE_DATE', '')
    if (tagged or version) and not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        sys.exit('Use a version such as v0.0.1.')
    if tagged:
        if (git('rev-parse', '--verify', f'{ref}^{{commit}}') != revision or
                subprocess.run(['git', 'merge-base', '--is-ancestor', revision, 'refs/remotes/origin/main']).returncode):
            sys.exit('The release tag must point to a commit on main.')
        notes = Path('docs/releases') / f'{version}.md'
        if not notes.is_file() or notes.stat().st_size == 0:
            sys.exit(f'Missing release notes: {notes.as_posix()}')
        release_date = git('for-each-ref', '--format=%(creatordate:short)', ref)
    if release_date:
        if not version:
            sys.exit('A release date requires a version.')
        try:
            if date.fromisoformat(release_date).isoformat() != release_date:
                raise ValueError
        except ValueError:
            sys.exit('Use a valid release date in YYYY-MM-DD format.')
    prefix = 'JustConnect-' + (version or f'preview-{revision}')
    with Path(env['GITHUB_OUTPUT']).open('a', encoding='utf-8') as outputs:
        outputs.write(f'prefix={prefix}\nversion={version}\ndate={release_date}\n')
    with Path(env['GITHUB_ENV']).open('a', encoding='utf-8') as outputs:
        outputs.write(f'ARCHIVE_NAME={prefix}-source\n')


if __name__ == '__main__':
    main()
