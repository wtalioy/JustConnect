import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_helper_sdk', ROOT / 'scripts/windows_helper_sdk.py')
sdk_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sdk_module)


class WindowsHelperSDKTest(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(sdk_module.CONTRACT.read_text())
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr(self.contract['sdk']['driver_entry'].format(arch='amd64'), b'x64-native-payload')
            output.writestr(self.contract['sdk']['driver_entry'].format(arch='arm64'), b'arm64-native-payload')
            output.writestr(self.contract['sdk']['license_entry'], b'fixture-license')
            output.writestr(self.contract['sdk']['header_entry'], b'fixture-native-header')
            output.writestr('../unrelated', b'must-never-be-extracted')
        self.data = archive.getvalue()
        self.contract['sdk']['archive_sha256'] = hashlib.sha256(self.data).hexdigest()

    def test_stages_only_verified_native_payloads(self):
        for arch in self.contract['sdk']['architectures']:
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory, \
                    patch.object(sdk_module.urllib.request, 'urlopen', return_value=io.BytesIO(self.data)):
                directory = Path(directory).resolve()
                result = sdk_module.stage(self.contract, directory, arch)
                expected = b'x64-native-payload' if arch == 'amd64' else b'arm64-native-payload'
                self.assertEqual(Path(result['driver']).read_bytes(), expected)
                self.assertEqual(result['driver_sha256'], hashlib.sha256(expected).hexdigest())
                self.assertEqual(Path(result['license']).read_bytes(), b'fixture-license')
                self.assertEqual(Path(result['header']).read_bytes(), b'fixture-native-header')
                self.assertEqual(set(Path(directory).iterdir()), {Path(result['driver']), Path(result['license']), Path(result['header']), Path(directory) / 'source.json'})

    def test_refuses_changed_archive_before_writing(self):
        bad = copy.deepcopy(self.contract)
        bad['sdk']['archive_sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(sdk_module.urllib.request, 'urlopen', return_value=io.BytesIO(self.data)):
            with self.assertRaisesRegex(ValueError, 'pinned source'):
                sdk_module.stage(bad, directory, 'amd64')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unsupported_architecture_never_downloads(self):
        with patch.object(sdk_module.urllib.request, 'urlopen') as download:
            with self.assertRaisesRegex(ValueError, 'Unsupported'):
                sdk_module.stage(self.contract, 'unused', 'unsupported')
            download.assert_not_called()


if __name__ == '__main__':
    unittest.main()
