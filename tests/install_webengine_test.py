import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'install_webengine', Path(__file__).resolve().parents[1] / 'scripts/install-webengine.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallWebEngineTest(unittest.TestCase):
    def test_rejects_empty_sdk_before_downloading(self):
        with patch.object(installer, 'WebEngineArchives') as archives:
            with self.assertRaises(RuntimeError):
                installer.install(Path(''), 'linux', 'linux_gcc_64')
            archives.assert_not_called()

    def test_rejects_unreviewed_build(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory) / 'Qt/6.12.0/gcc_64'
            (sdk / 'bin').mkdir(parents=True)
            with patch.object(installer, 'WebEngineArchives') as archives, \
                    patch.object(installer, 'run_installer') as extract:
                archives.return_value.get_packages.return_value = [
                    SimpleNamespace(name='qtwebengine', archive_path='unexpected-build')]
                with self.assertRaises(RuntimeError):
                    installer.install(sdk, 'linux', 'linux_gcc_64')
                extract.assert_not_called()

    @unittest.skipIf(os.name == 'nt', 'Framework symlinks are used by Unix SDKs')
    def test_merges_frameworks_repeatedly_and_preserves_sdk(self):
        temporary_directories = []

        def extract(packages, directory, *args):
            root = Path(directory)
            temporary_directories.append(root)
            framework = root / '6.12.0/gcc_64/lib/Foo.framework'
            (framework / 'Versions/A').mkdir(parents=True)
            (framework / 'Versions/A/Foo').write_text('WebEngine')
            (framework / 'Versions/Current').symlink_to('A', target_is_directory=True)
            (framework / 'Foo').symlink_to('Versions/Current/Foo')

        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory) / 'Qt/6.12.0/gcc_64'
            (sdk / 'bin').mkdir(parents=True)
            (sdk / 'keep.txt').write_text('Qt core')
            package = SimpleNamespace(name='qtwebengine', archive_path=installer.WEBENGINE_BUILD)
            with patch.object(installer, 'WebEngineArchives') as archives, \
                    patch.object(installer, 'run_installer', side_effect=extract), \
                    patch.object(installer.Updater, 'update'):
                archives.return_value.get_packages.return_value = [package]
                installer.install(sdk, 'linux', 'linux_gcc_64')
                installer.install(sdk, 'linux', 'linux_gcc_64')
                self.assertEqual((sdk / 'keep.txt').read_text(), 'Qt core')
                self.assertTrue((sdk / 'lib/Foo.framework/Foo').is_symlink())
                self.assertEqual((sdk / 'lib/Foo.framework/Foo').read_text(), 'WebEngine')
                package.archive_path = 'unexpected-build'
                with self.assertRaises(RuntimeError):
                    installer.install(sdk, 'linux', 'linux_gcc_64')
            self.assertTrue(all(not path.exists() for path in temporary_directories))


if __name__ == '__main__':
    unittest.main()
