import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('mihomo_owner', Path(__file__).parent / 'platform/mihomo_owner_linux.py')
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


class ListenerOwnershipReadinessTest(unittest.TestCase):
    def test_empty_proof_waits_for_the_actual_owner(self):
        results = [SimpleNamespace(stdout='[]'), SimpleNamespace(stdout='[{"pid":"42"}]')]
        with patch.object(owner.subprocess, 'run', side_effect=results) as run, \
                patch.object(owner.time, 'monotonic', return_value=0), patch.object(owner.time, 'sleep'):
            proof = owner.wait_for_listener_proof(Mock(poll=lambda: None), Mock(is_socket=lambda: True),
                                                 'helper', {'pid': '42'}, 10)
        self.assertEqual(proof, results[-1].stdout)
        self.assertEqual(run.call_count, 2)
        self.assertTrue(all(call.kwargs['check'] and call.kwargs['timeout'] == 5 for call in run.call_args_list))

    def test_empty_proof_cannot_extend_the_original_budget(self):
        now = [0.0]
        def sleep(delay):
            now[0] += delay
        with patch.object(owner.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(owner.time, 'sleep', side_effect=sleep), \
                patch.object(owner.subprocess, 'run', return_value=SimpleNamespace(stdout='[]')) as run:
            with self.assertRaises(TimeoutError):
                owner.wait_for_listener_proof(Mock(poll=lambda: None), Mock(is_socket=lambda: True),
                                             'helper', {}, 0.03)
        self.assertEqual(run.call_count, 2)
        self.assertAlmostEqual(now[0], 0.03)
        self.assertEqual([round(c.kwargs['timeout'], 2) for c in run.call_args_list], [0.03, 0.01])

    def test_process_exit_and_helper_failure_are_not_retried(self):
        with patch.object(owner.subprocess, 'run') as run:
            with self.assertRaises(TimeoutError):
                owner.wait_for_listener_proof(Mock(poll=lambda: 1), Mock(), 'helper', {}, owner.time.monotonic() + 10)
            run.assert_not_called()
        with patch.object(owner.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'helper')) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                owner.wait_for_listener_proof(Mock(poll=lambda: None), Mock(is_socket=lambda: True),
                                             'helper', {}, owner.time.monotonic() + 10)
            self.assertEqual(run.call_count, 1)

    def test_malformed_proof_is_not_pending_readiness(self):
        with patch.object(owner.subprocess, 'run', return_value=SimpleNamespace(stdout='{"pid":"42"}')) as run:
            with self.assertRaises(ValueError):
                owner.wait_for_listener_proof(Mock(poll=lambda: None), Mock(is_socket=lambda: True),
                                             'helper', {}, owner.time.monotonic() + 10)
            self.assertEqual(run.call_count, 1)
