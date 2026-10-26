import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
with patch.object(sys, 'path', [str(ROOT / 'tests/platform'), *sys.path]):
    spec = importlib.util.spec_from_file_location('windows_packet_runner', ROOT / 'tests/platform/run_windows_packet.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)


class WindowsPacketRunnerTest(unittest.TestCase):
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
