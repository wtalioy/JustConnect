import hashlib
import importlib.util
import io
import json
import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('linuxdeploy_tools', ROOT / 'scripts/linuxdeploy_tools.py')
tools = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tools)


class LinuxDeployToolsTest(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(tools.CONTRACT.read_text())
        self.payloads = {}
        for name, tool in self.contract.items():
            tool['version'] = 'reviewed-version'
            for arch in tool['sha256']:
                payload = f'{name}-{arch}-native-tool'.encode()
                self.payloads[name, arch] = payload
                tool['sha256'][arch] = hashlib.sha256(payload).hexdigest()

    def test_downloads_exact_version_and_architecture(self):
        for arch in ('x86_64', 'aarch64'):
            urls = []
            def download(url, timeout):
                self.assertEqual(timeout, 60)
                urls.append(url)
                name = next(name for name in self.contract if f'https://github.com/linuxdeploy/{name}/releases/' in url)
                return io.BytesIO(self.payloads[name, arch])
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory, \
                    patch.object(tools.urllib.request, 'urlopen', side_effect=download):
                tools.stage(self.contract, directory, arch)
                for name in self.contract:
                    self.assertEqual((Path(directory) / name).read_bytes(), self.payloads[name, arch])
                    self.assertIn(f'https://github.com/linuxdeploy/{name}/releases/download/reviewed-version/{name}-{arch}.AppImage', urls)

    def test_verified_cache_needs_no_download_and_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(tools.urllib.request, 'urlopen') as download:
            for name in self.contract:
                (Path(directory) / name).write_bytes(self.payloads[name, 'x86_64'])
            tools.stage(self.contract, directory, 'x86_64')
            first = Path(directory) / next(iter(self.contract))
            first.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                tools.stage(self.contract, directory, 'x86_64')
            self.assertEqual(first.read_bytes(), b'tampered')
            download.assert_not_called()

    def test_changed_download_is_not_staged(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(tools.urllib.request, 'urlopen', return_value=io.BytesIO(b'unreviewed')):
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                tools.stage(self.contract, directory, 'aarch64')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unsupported_architecture_does_not_download_or_write(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(tools.urllib.request, 'urlopen') as download:
            with self.assertRaisesRegex(ValueError, 'Unsupported AppImage architecture'):
                tools.stage(self.contract, directory, 'armv7')
            download.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])


@unittest.skipUnless(sys.platform.startswith('linux'), 'ELF packaging uses the native Linux toolchain')
class LinuxDeployStripTest(unittest.TestCase):
    def test_deployment_entry_maps_native_architecture_before_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = root / 'arguments.json'
            python = root / 'python'
            python.write_text(f'#!{sys.executable}\nimport json, sys\n'
                              f'open({str(arguments)!r}, "w").write(json.dumps(sys.argv[1:]))\n'
                              'sys.exit(42)\n')
            python.chmod(0o755)
            for native, expected in (('x86_64', 'x86_64'), ('arm64', 'aarch64'),
                                     ('aarch64', 'aarch64'), ('armv7', None)):
                with self.subTest(native=native):
                    arguments.unlink(missing_ok=True)
                    result = subprocess.run(['bash', str(ROOT / 'scripts/deploy-linux.sh'),
                                             'JustConnect', 'JustConnect', 'build', native],
                                            env={**os.environ, 'PATH': f'{root}:{os.environ["PATH"]}'},
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 42 if expected else 1, result.stderr)
                    if expected:
                        self.assertEqual(json.loads(arguments.read_text()),
                                         ['scripts/linuxdeploy_tools.py', expected])
                    else:
                        self.assertFalse(arguments.exists())

    def test_strips_owned_elfs_preserving_exports_and_external_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'fixture.c'
            source.write_text('int fixture(void) { return 42; }\n')
            library = root / 'original.so'
            subprocess.run(['cc', '-shared', '-fPIC', '-g', str(source), '-o', str(library)], check=True)
            appdir = root / 'AppDir'
            appdir.mkdir()
            deployed = appdir / 'deployed.so'
            shutil.copyfile(library, deployed)
            (appdir / 'external.so').symlink_to(library)
            plain = appdir / 'plain.txt'
            plain.write_text('unchanged metadata')
            original = library.read_bytes()
            tools.strip_elfs(appdir)
            self.assertLess(deployed.stat().st_size, len(original))
            self.assertEqual(ctypes.CDLL(str(deployed)).fixture(), 42)
            self.assertEqual(library.read_bytes(), original)
            self.assertEqual(plain.read_text(), 'unchanged metadata')

    def test_native_stripping_failure_is_propagated(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'broken.so').write_bytes(b'\x7fELFtruncated')
            with self.assertRaises(subprocess.CalledProcessError):
                tools.strip_elfs(directory)


if __name__ == '__main__':
    unittest.main()
