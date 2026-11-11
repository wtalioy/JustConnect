import subprocess
import unittest
from unittest.mock import Mock, patch

import mihomo_tun_native as native


class CleanupTests(unittest.TestCase):
    def test_failed_tun_shutdown_still_reaps_its_owned_process(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('owned-runtime', 3), 0]
        with patch.object(native, 'disable_tun', side_effect=RuntimeError('shutdown refused')):
            with self.assertRaisesRegex(RuntimeError, 'shutdown refused'):
                native.finish_runtime(process, {})
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_exited_runtime_does_not_write_to_an_unowned_replacement(self):
        process = Mock()
        process.poll.return_value = 1
        with patch.object(native, 'disable_tun') as disable:
            native.finish_runtime(process, {})
        disable.assert_not_called()
        process.terminate.assert_not_called()


if __name__ == '__main__':
    unittest.main()
