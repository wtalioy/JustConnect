import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('ctest_runner', pathlib.Path(__file__).parent / 'platform/run_ctest.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CTestRunnerTest(unittest.TestCase):
    def test_samples_only_native_descendants_and_preserves_failure(self):
        process = MagicMock(pid=10)
        process.__enter__.return_value = process
        process.wait.side_effect = [subprocess.TimeoutExpired('ctest', 10), 8]
        with tempfile.TemporaryDirectory() as directory, patch.object(runner.sys, 'platform', 'darwin'), \
                patch.object(runner.subprocess, 'Popen', return_value=process), \
                patch.object(runner.subprocess, 'check_output', return_value=
                             '10 1 ctest\n11 10 go\n12 11 /build/coreabi_ui_test\n13 1 /other/native_test\n'), \
                patch.object(runner.subprocess, 'run', side_effect=subprocess.TimeoutExpired('sample', 5)) as sample:
            self.assertEqual(runner.run(['--test-dir', directory]), 8)
            self.assertEqual(sample.call_count, 1)
            self.assertEqual(sample.call_args.args[0][:3], ['/usr/bin/sample', '12', '1'])

    def test_other_hosts_run_ctest_directly(self):
        process = MagicMock()
        process.__enter__.return_value = process
        process.wait.return_value = 3
        with patch.object(runner.sys, 'platform', 'win32'), \
                patch.object(runner.subprocess, 'Popen', return_value=process) as start:
            self.assertEqual(runner.run(['--test-dir', 'build']), 3)
            start.assert_called_once_with(['ctest', '--test-dir', 'build'])


if __name__ == '__main__':
    unittest.main()
