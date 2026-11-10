"""Run the formal ABI matrix checks and stream their evidence."""
import os
import pathlib
import subprocess
import sys


def run(output, name, args, required=True):
    sys.stdout.buffer.write(('RUN: ' + name + '\n').encode())
    sys.stdout.buffer.flush()
    with (output / (name + '.log')).open('wb') as log:
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
            for chunk in iter(lambda: process.stdout.read1(4096), b''):
                log.write(chunk)
                log.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            status = process.wait()
    if status and required:
        sys.exit(status)
    return status


def main():
    output = pathlib.Path('build/coreabi')
    output.mkdir(parents=True, exist_ok=True)
    run(output, 'mihomo-runtime-unit', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/platform', '-p', 'setup_mihomo_test.py'])
    run(output, 'mihomo-api-capabilities', [sys.executable, 'tests/platform/mihomo_api_probe.py', os.environ['JC_TEST_MIHOMO_BINARY']])
    run(output, 'go', ['go', 'version'])
    run(output, 'cgo-env', ['go', 'env', 'GOHOSTOS', 'GOHOSTARCH', 'CC', 'CGO_ENABLED'])
    run(output, 'cc', [os.environ['CC'], '--version'])
    run(output, 'constants', [sys.executable, 'scripts/generate-core-abi.py', '--check'])
    run(output, 'go-test', ['go', '-C', 'corelib', 'test', '-json', '-timeout', '90s', './...'])
    race_status = regression_status = 0
    if not (os.environ['RUNNER_OS'] == 'Windows' and os.environ['RUNNER_ARCH'] == 'ARM64'):
        # Collect independent ABI results even when a race regression fails; the step still fails below.
        # Serialize packages; retain the platform's CPU and parallel-test budgets.
        race_status = run(output, 'go-race', ['go', '-C', 'corelib', 'test', '-json', '-race', '-p', '1', '-timeout', '90s', './...'], required=False)
        # Repeat observed shutdown/DNS regressions without relaxing their original deadlines.
        regression_status = run(output, 'go-race-tun-regressions', ['go', '-C', 'corelib', 'test', '-json', '-race', '-count', '5',
            '-timeout', '90s', '-run', '^(TestTUNBoundsFlowsAndJoinsFullCapacityOnShutdown|TestTUNDNSUsesOwnedPeerAndCampusACL)$', './service'], required=False)
    else:
        print('UNSUPPORTED: Go race detector on Windows ARM64; normal Go and C ABI tests still run', flush=True)
    args = ['cmake', '-S', 'tests/coreabi', '-B', str(output), '-DCMAKE_BUILD_TYPE=Release']
    if sys.platform == 'win32':
        args += ['-A', 'ARM64' if os.environ['RUNNER_ARCH'] == 'ARM64' else 'x64']
    run(output, 'configure', args)
    run(output, 'build', ['cmake', '--build', str(output), '--config', 'Release', '--parallel', '3', '--verbose'])
    run(output, 'host', [sys.executable, 'tests/platform/run_ctest.py', '--test-dir', str(output), '-C', 'Release', '-V', '--output-on-failure'])
    sys.exit(race_status or regression_status)


if __name__ == '__main__':
    main()
