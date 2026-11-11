import importlib.util
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('archive_source', Path(__file__).resolve().parents[1] / 'scripts/archive-source.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


class ArchiveSourceTest(unittest.TestCase):
    def test_native_go_probe_checkout_keeps_lf_on_windows(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def git(*args):
                subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                                *args], cwd=root, check=True)
            git('init', '-q')
            git('config', 'core.autocrlf', 'true')
            (root / '.gitattributes').write_bytes((source.ROOT / '.gitattributes').read_bytes())
            probe = root / 'tests/platform/probe.go'
            probe.parent.mkdir(parents=True)
            expected = b'package main\n\nfunc main() {}\n'
            probe.write_bytes(expected)
            git('add', '.')
            git('commit', '-qm', 'Add native Go probe')
            probe.unlink()
            git('checkout', '--', 'tests/platform/probe.go')
            self.assertEqual(probe.read_bytes(), expected)

    def test_exports_actual_modifications_and_rejects_uncommitted_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'repo'
            root.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                                                *args], cwd=root).decode().strip()
            git('init', '-q')
            git('config', 'core.autocrlf', 'true')
            code = root / 'core.go'
            code.write_bytes(b'maintained implementation\n')
            git('add', '.')
            git('commit', '-qm', 'Maintain core')
            output = Path(folder) / 'source.tar.gz'
            with patch.object(source, 'ROOT', root):
                source.archive(output)
                revision = git('rev-parse', 'HEAD')
                with tarfile.open(output) as bundle:
                    prefix = 'JustConnect-' + revision + '/'
                    self.assertEqual(bundle.extractfile(prefix + 'core.go').read(), code.read_bytes())
                    self.assertEqual(bundle.extractfile(prefix + 'source-revision.txt').read().decode().strip(), revision)
                code.write_text('not the compiled commit\n')
                with self.assertRaises(RuntimeError):
                    source.archive(output)


class PackageIdentityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = (source.ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        step = workflow.split('      - name: Resolve package identity\n', 1)[1].split('\n      - ', 1)[0]
        cls.script = textwrap.dedent(step.split('        run: |\n', 1)[1])

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)

    def git(self, *args):
        return subprocess.check_output(
            ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', *args],
            cwd=self.root, text=True, env={**os.environ, 'GIT_COMMITTER_DATE': '2026-11-11T12:00:00Z'},
        ).strip()

    def resolve(self, ref, revision, version='', date=''):
        outputs = self.root / 'outputs'
        outputs.unlink(missing_ok=True)
        result = subprocess.run(
            ['bash', '-c', self.script], cwd=self.root, text=True, capture_output=True,
            env={**os.environ, 'GITHUB_REF': ref, 'GITHUB_SHA': revision,
                 'GITHUB_REF_TYPE': 'tag' if ref.startswith('refs/tags/') else 'branch',
                 'GITHUB_ENV': 'github-env', 'GITHUB_OUTPUT': 'outputs',
                 'RELEASE_VERSION': version, 'RELEASE_DATE': date},
        )
        if result.returncode:
            self.assertFalse(outputs.exists(), result.stderr)
            return result.stderr
        return dict(line.split('=', 1) for line in outputs.read_text().splitlines())

    def test_branch_preview_and_candidate(self):
        ref, revision = 'refs/heads/main', 'a' * 40
        self.assertEqual(self.resolve(ref, revision),
                         {'prefix': f'JustConnect-preview-{revision}', 'version': '', 'date': ''})
        self.assertEqual(self.resolve(ref, revision, 'v0.0.2', '2026-11-11'),
                         {'prefix': 'JustConnect-v0.0.2', 'version': 'v0.0.2', 'date': '2026-11-11'})
        self.assertIn('requires a version', self.resolve(ref, revision, date='2026-11-11'))
        self.assertIn('valid release date', self.resolve(ref, revision, 'v0.0.2', '2026-02-30'))

    def test_tag_needs_the_same_main_commit_and_its_release_notes(self):
        self.git('init', '-qb', 'main')
        notes = self.root / 'docs/releases'
        notes.mkdir(parents=True)
        (notes / 'v0.0.2.md').write_text('Release notes\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'Add release notes')
        main = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/main', main)
        self.git('tag', '-am', 'Release v0.0.2', 'v0.0.2')
        self.assertEqual(self.resolve('refs/tags/v0.0.2', main, 'v0.0.2'),
                         {'prefix': 'JustConnect-v0.0.2', 'version': 'v0.0.2', 'date': '2026-11-11'})

        self.git('tag', 'v0.0.3')
        self.assertIn('Missing release notes', self.resolve('refs/tags/v0.0.3', main, 'v0.0.3'))
        self.assertIn('Use a version', self.resolve('refs/tags/v0.00.2', main, 'v0.00.2'))
        self.git('switch', '-qc', 'feature')
        self.git('commit', '--allow-empty', '-qm', 'Not yet merged')
        feature = self.git('rev-parse', 'HEAD')
        self.git('tag', '-f', 'v0.0.2', feature)
        self.assertIn('commit on main', self.resolve('refs/tags/v0.0.2', feature, 'v0.0.2'))
        self.assertIn('commit on main', self.resolve('refs/tags/v0.0.2', main, 'v0.0.2'))


if __name__ == '__main__':
    unittest.main()
