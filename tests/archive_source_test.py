import importlib.util
from pathlib import Path
import subprocess
import tarfile
import tempfile
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


if __name__ == '__main__':
    unittest.main()
