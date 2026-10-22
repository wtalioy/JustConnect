"""Exercise the real Secret Service in a private bus and encrypted test keyring."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid


def run(*args, env=None, data=None):
    result=subprocess.run(args, env=env, input=data, check=True, timeout=20,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode()


def session(root, native, denied):
    runtime = root / 'run'
    runtime.mkdir(mode=0o700)
    provider = os.environ.get('JC_TEST_SECRET_PROVIDER') or shutil.which('gnome-keyring-daemon')
    if not provider:
        raise RuntimeError('Unverified: install gnome-keyring or set JC_TEST_SECRET_PROVIDER')
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_CONFIG_HOME=str(root / 'config'),
               XDG_DATA_HOME=str(root / 'data'), GNOME_KEYRING_CONTROL=str(runtime / 'control'))
    libraries = env.get('JC_TEST_SECRET_PROVIDER_LIBS')
    if libraries:
        env['LD_LIBRARY_PATH'] = libraries + ':' + env.get('LD_LIBRARY_PATH', '')
    scope = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    # The private bus has no activation directories, even if the desktop has a provider.
    print(run(native, 'unavailable', scope, env=env), end='')
    run(provider, '--unlock', '--components=secrets', '--control-directory', str(runtime / 'control'),
        env=env, data=b'fixture keyring password')
    run(provider, '--start', '--components=secrets', '--control-directory', str(runtime / 'control'), env=env)
    if denied:
        print(run(native, 'denied', scope, env=env), end='')
        return
    print(run(native, 'prepare', scope, env=env), end='')
    call = ['gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets',
            '--object-path', '/org/freedesktop/secrets', '--method']
    alias = run(*call, 'org.freedesktop.Secret.Service.ReadAlias', 'default', env=env)
    collection = re.fullmatch(r"\(objectpath '([^']+)',\)\s*", alias).group(1)
    run(*call, 'org.freedesktop.Secret.Service.Lock', f"[objectpath '{collection}']", env=env)
    print(run(native, 'locked', scope, env=env), end='')
    # Restart only this private provider to verify durable data as well as unlocking.
    run(provider, '--replace', '--unlock', '--components=secrets', '--control-directory', str(runtime / 'control'),
        env=env, data=b'fixture keyring password')
    run(provider, '--start', '--components=secrets', '--control-directory', str(runtime / 'control'), env=env)
    keyrings = list((root / 'data/keyrings').glob('*.keyring'))
    if not keyrings:
        raise RuntimeError('Provider did not persist an encrypted keyring')
    for keyring in keyrings:
        contents = keyring.read_bytes()
        if keyring.stat().st_mode & 0o077 or any(value in contents for value in
                [b'fixture password', b'updated fixture password', b'other fixture cookie',
                 b'proxy recovery snapshot', b'PAC token=fixture']):
            raise RuntimeError('Provider exposed fixture credential data')
    print(run(native, 'finish', scope, env=env), end='')


def main():
    os.umask(0o077)
    if len(sys.argv) == 5 and sys.argv[1] == '--session':
        session(Path(sys.argv[2]), sys.argv[3], sys.argv[4] == 'denied')
        return
    native = str(Path(sys.argv[1]).resolve())
    for denied in [False, True]:
        with tempfile.TemporaryDirectory(prefix='JustConnect-secret-test-') as folder:
            root = Path(folder)
            config = root / 'bus.conf'
            deny = '<deny send_interface="org.freedesktop.Secret.Collection" send_member="CreateItem"/>' if denied else ''
            config.write_text('<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen>'
                              '<auth>EXTERNAL</auth><policy context="default">'
                              '<allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/>' + deny +
                              '</policy></busconfig>', encoding='utf-8')
            subprocess.run(['dbus-run-session', '--config-file', str(config), '--', sys.executable,
                            str(Path(__file__).resolve()), '--session', str(root), native,
                            'denied' if denied else 'normal'], check=True, timeout=60)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr.decode(errors='replace'), file=sys.stderr)
        raise
