import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
with patch.object(sys, 'path', [str(ROOT / 'tests/platform'), *sys.path]):
    spec = importlib.util.spec_from_file_location('windows_packet_runner', ROOT / 'tests/platform/run_windows_packet.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
spec = importlib.util.spec_from_file_location('windows_helper_runner', ROOT / 'tests/platform/run_windows_helper.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class WindowsPacketRunnerTest(unittest.TestCase):
    def test_helper_payloads_are_private_and_cleaned_after_success_or_failure(self):
        contract = json.loads((ROOT / 'resource/network-helper-windows.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'build/coreabi'
            output.mkdir(parents=True)
            (root / 'resource').mkdir()
            (root / 'resource/network-helper-windows.json').write_text(json.dumps(contract))
            sdk = root / 'sdk'
            sdk.mkdir()
            driver, license = sdk / contract['driver_library'], sdk / contract['driver_license']
            driver.write_bytes(b'immutable SDK driver')
            license.write_bytes(b'immutable SDK license')
            metadata = dict(driver=str(driver), license=str(license), powershell_host='pwsh',
                driver_sha256='driver hash', license_sha256='license hash', native_build=str(root / 'native'), arch='amd64')
            (output / 'windows-device.json').write_text(json.dumps(metadata))
            for code in (0, 1):
                payloads = []
                def execute(*args, env, **kwargs):
                    payload = Path(env['JC_HELPER_TAMPER_DIRECTORY'])
                    payloads.append(payload)
                    self.assertNotEqual(payload, sdk)
                    self.assertEqual(Path(env['JC_HELPER_SDK_DIRECTORY']), sdk)
                    self.assertEqual(Path(env['JC_HELPER_SERVICE_IMAGE']).parent, sdk)
                    self.assertEqual((payload / driver.name).read_bytes(), driver.read_bytes())
                    self.assertEqual((payload / license.name).read_bytes(), license.read_bytes())
                    (payload / driver.name).write_bytes(b'owned tamper fixture')
                    self.assertEqual(driver.read_bytes(), b'immutable SDK driver')
                    return subprocess.CompletedProcess([], code)
                with self.subTest(code=code), patch.object(helper, 'ROOT', root), \
                        patch.object(sys, 'argv', ['runner', '--qt-control']), patch.object(helper.os, 'chdir'), \
                        patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Windows'}), \
                        patch.object(helper.subprocess, 'run', side_effect=execute):
                    if code:
                        with self.assertRaisesRegex(RuntimeError, 'Protected Windows helper check failed'):
                            helper.main()
                    else:
                        helper.main()
                    self.assertEqual(len(payloads), 1)
                    self.assertFalse(payloads[0].exists())
                    self.assertEqual(driver.read_bytes(), b'immutable SDK driver')
                    self.assertEqual(license.read_bytes(), b'immutable SDK license')

    def test_early_dns_check_publishes_only_complete_successful_native_reads(self):
        facts = {'interfaces': [], 'clients': [], 'global': {}, 'nrpt': [], 'doh_supported': False, 'doh': [],
                 'nrpt_sources': [], 'configured_encryption': [], 'adapters': [], 'native_global': {'Status': 87, 'Value': None}}
        for result in (subprocess.CompletedProcess([], 1, b'', b'provider denied'),
                       subprocess.CompletedProcess([], 0, b'{}', b''),
                       subprocess.CompletedProcess([], 0, json.dumps(facts).encode(), b'')):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                (folder / 'JustConnectDnsReader.exe').touch()
                report = folder / 'windows-native-dns.json'
                valid = result.returncode == 0 and result.stdout != b'{}'
                with patch.dict(os.environ, {'GITHUB_SHA': 'checked-source'}), \
                        patch.object(runner.subprocess, 'run', side_effect=[subprocess.CompletedProcess([], 0), result]):
                    if valid:
                        runner.verify_native_dns(folder, folder, 'arm64')
                        data = json.loads(report.read_text())
                        self.assertEqual((data['source'], data['arch']), ('checked-source', 'arm64'))
                    else:
                        with self.assertRaises(RuntimeError):
                            runner.verify_native_dns(folder, folder, 'arm64')
                        self.assertFalse(report.exists())

    def test_core_only_refuses_non_disposable_host(self):
        with patch.object(sys, 'argv', ['runner', '--core-only']), \
                patch.dict(os.environ, {}, clear=True), patch.object(runner.os, 'chdir'), \
                patch.object(runner.subprocess, 'run') as execute:
            with self.assertRaisesRegex(RuntimeError, 'disposable runner'):
                runner.main()
            execute.assert_not_called()

    def test_core_only_requires_device_inputs_before_execution(self):
        with patch.object(sys, 'argv', ['runner', '--core-only']), \
                patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Windows'}, clear=True), \
                patch.object(runner.os, 'chdir'), patch.object(runner.subprocess, 'run') as execute:
            with self.assertRaisesRegex(RuntimeError, 'native input'):
                runner.main()
            execute.assert_not_called()

    def test_core_only_collects_application_evidence_without_repeating_device_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            driver, broker = Path(directory) / 'wintun.dll', Path(directory) / 'broker.exe'
            driver.touch()
            broker.touch()
            env = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Windows', 'RUNNER_ARCH': 'ARM64',
                   'JC_TEST_WINTUN_DLL': str(driver.resolve()), 'JC_TEST_CPP_WINTUN_BROKER': str(broker.resolve())}
            with patch.object(sys, 'argv', ['runner', '--core-only']), \
                    patch.dict(os.environ, env, clear=True), patch.object(runner.os, 'chdir'), \
                    patch.object(runner, 'device', side_effect=AssertionError('device probe repeated')), \
                    patch.object(runner.subprocess, 'run') as execute:
                runner.main()
            commands = [call.args[0] for call in execute.call_args_list]
            self.assertTrue(any('coreabi_windows_session_test' in args for args in commands))
            self.assertTrue(any(args[0] == 'ctest' and '^coreabi_windows_(packet|session)_test$' in args for args in commands))
            for call in execute.call_args_list:
                if 'env' in call.kwargs:
                    self.assertEqual(call.kwargs['env']['JC_TEST_WINTUN_DLL'], env['JC_TEST_WINTUN_DLL'])


if __name__ == '__main__':
    unittest.main()
