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
