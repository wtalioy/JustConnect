"""Stop only a verified fixture helper at its durable capture deletion boundary."""

import ctypes
import json
import os
import signal
import socket
import subprocess
import time


def kill_during_capture_delete(worker, journal, owner, prefix, begin, route_present):
    assert os.geteuid() == 0
    for name in ('net', 'mnt'):
        scope = os.stat(f'/proc/thread-self/ns/{name}')
        assert scope != os.stat(f'/proc/1/ns/{name}'), 'refusing a host namespace'
        assert scope == os.stat(f'/proc/{worker}/ns/{name}'), 'helper is outside the isolated fixture'
    # Linux UAPI: fork events stop both parent and child before the new command executes.
    # https://man7.org/linux/man-pages/man2/ptrace.2.html
    seize, resume, event_message = 0x4206, 7, 0x4201
    fork_events, trace_exec, exit_kill = 0x02 | 0x04, 0x10, 0x100000
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long

    def trace(request, pid, data=0):
        if libc.ptrace(request, pid, None, data) == -1:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    tracked = {worker: os.pidfd_open(worker)}
    attached = False
    try:
        trace(seize, worker, fork_events | trace_exec | exit_kill)
        attached = True
        begin()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            for pid in tuple(tracked):
                observed, status = os.waitpid(pid, os.WNOHANG)
                if not observed:
                    continue
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    os.close(tracked.pop(pid))
                    assert pid != worker, 'helper exited before the capture deletion checkpoint'
                    continue
                assert os.WIFSTOPPED(status), status
                event = status >> 16
                if event in (1, 2):  # PTRACE_EVENT_FORK / PTRACE_EVENT_VFORK
                    child = ctypes.c_ulong()
                    trace(event_message, pid, ctypes.byref(child))
                    tracked[child.value] = os.pidfd_open(child.value)
                    record = json.loads(journal.read_text())
                    assert record['owner'] == owner
                    deleting = [row for row in record['routes'] if row['prefix'] == prefix and row['delete_started'] is True]
                    if pid == worker and deleting:
                        assert len(deleting) == 1 and deleting[0]['applied']
                        routes = json.loads(subprocess.check_output(['ip', '-N', '-j', '-4', 'route', 'show', 'table', 'main'], text=True, timeout=3))
                        assert socket.if_nametoindex(record['interface']) == record['index'], 'owned device disappeared at the checkpoint'
                        present = deleting[0]['applied'] in routes
                        if present == route_present:
                            return {'owner': owner, 'prefix': prefix, 'delete_started': True,
                                    'kernel_route_present': present, 'owned_device_present': True}
                delivered = os.WSTOPSIG(status)
                trace(resume, pid, 0 if event or delivered in (signal.SIGTRAP, signal.SIGSTOP) else delivered)
            time.sleep(0.001)
        raise AssertionError('capture deletion checkpoint was not reached')
    finally:
        if attached:
            for descriptor in tracked.values():
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 5
            while tracked and time.monotonic() < deadline:
                for pid in tuple(tracked):
                    observed, status = os.waitpid(pid, os.WNOHANG)
                    if observed and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                        os.close(tracked.pop(pid))
                time.sleep(0.001)
        for descriptor in tracked.values():
            os.close(descriptor)
        assert not attached or not tracked, 'traced fixture processes did not exit'
