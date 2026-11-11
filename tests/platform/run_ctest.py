"""Keep CTest's deadlines and exit status; sample stalled native macOS children."""
import pathlib
import subprocess
import sys


def run(arguments):
    with subprocess.Popen(['ctest', *arguments]) as process:
        if sys.platform != 'darwin':
            return process.wait()
        directory = pathlib.Path(arguments[arguments.index('--test-dir') + 1]) / 'Testing/Temporary'
        directory.mkdir(parents=True, exist_ok=True)
        seen = set()
        while True:
            try:
                return process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                rows = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,comm='], text=True)
                children = {int(pid): (int(parent), command) for pid, parent, command in
                            (row.strip().split(None, 2) for row in rows.splitlines() if row.strip())}
                descendants = {process.pid}
                while True:
                    expanded = descendants | {pid for pid, (parent, _) in children.items() if parent in descendants}
                    if expanded == descendants:
                        break
                    descendants = expanded
                for pid in descendants - seen:
                    if pid != process.pid and pathlib.Path(children[pid][1]).name.endswith('_test'):
                        seen.add(pid)
                        try:
                            subprocess.run(['/usr/bin/sample', str(pid), '1', '-file', str(directory / f'{pid}.sample.txt')],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
                        except (OSError, subprocess.TimeoutExpired):
                            pass  # Diagnostic collection must not replace the test result.


if __name__ == '__main__':
    sys.exit(run(sys.argv[1:]))
